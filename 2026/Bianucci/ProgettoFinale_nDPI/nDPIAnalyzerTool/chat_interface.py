
""" Scheda per l'interrogazione di un modello LLM locale """

import threading
import tkinter as tk
from tkinter import ttk
from datetime import datetime

from NetSession import NetSession
from analyzer import query_local_ai
from gui_utils import COLORS


def json_ready(value):
    """ Converte ricorsivamente i set prodotti dal parser in liste JSON """

    if isinstance(value, set):
        return sorted(json_ready(item) for item in value)
    if isinstance(value, dict):
        return {key: json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_ready(item) for item in value]
    return value


class ChatApp(ttk.Frame):
    def __init__(self, parent, session: NetSession, **kwargs):
        super().__init__(parent, **kwargs)
        self.kb = None
        self.is_waiting = False
        self.session: NetSession = session

        self.configure(style="TFrame")
        self._build_ui()

        # Saluto iniziale differito
        self.after(150, lambda: self.add_message(
            "assistant",
            "Ciao! Sono il tuo analista di rete. Puoi caricare un file .txt di nDPI o convertire un .pcapng tramite il pannello laterale."
            )
        )

    def _build_ui(self):
        # self funge già da contenitore (essendo un ttk.Frame)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew", padx=28, pady=(20, 10))
        ttk.Label(header, text="Network Intelligence", font=("Arial", 19, "bold")).pack(side="left")
        ttk.Label(header, text="Pronto a leggere il tuo traffico", font=("Arial", 12), foreground=COLORS["muted"]).pack(side="left", padx=12, pady=(4, 0))
        ttk.Button(header, text="Nuova chat", style="Ghost.TButton", command=self.reset_chat).pack(side="right")

        chat_outer = tk.Frame(self, bg=COLORS["bg"])
        chat_outer.grid(row=1, column=0, sticky="nsew", padx=28, pady=6)
        self.chat = tk.Text(chat_outer, bg=COLORS["bg"], fg=COLORS["text"], relief="flat", borderwidth=0, wrap="word", padx=2, pady=8, state="disabled", font=("Arial", 12), cursor="arrow")
        scroll = ttk.Scrollbar(chat_outer, orient="vertical", command=self.chat.yview)
        self.chat.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.chat.pack(side="left", fill="both", expand=True)

        # Definizione delle etichette che identificano chi ha scritto cosa
        self.chat.tag_configure("assistant", background=COLORS["bot"], foreground=COLORS["text"], lmargin1=18, lmargin2=18, rmargin=100, spacing1=12, spacing3=12)
        self.chat.tag_configure("user", background=COLORS["user"], foreground="white", lmargin1=100, lmargin2=100, rmargin=18, spacing1=12, spacing3=12, justify="right")
        self.chat.tag_configure("meta", foreground=COLORS["muted"], font=("Arial", 9), spacing1=6)

        # Box per scrivere le domande in basso
        composer = tk.Frame(self, bg=COLORS["panel_alt"], highlightbackground=COLORS["border"], highlightthickness=1)
        composer.grid(row=2, column=0, sticky="ew", padx=28, pady=(10, 22))
        composer.columnconfigure(0, weight=1)
        self.prompt = tk.Text(composer, height=2, bg=COLORS["panel_alt"], fg=COLORS["text"], insertbackground="white", relief="flat", wrap="word", padx=12, pady=10, font=("Arial", 12))
        self.prompt.grid(row=0, column=0, sticky="ew")
        self.prompt.bind("<Return>", self._on_return) # gestione ENTER o ENTER+SHIFT

        self.send_button = ttk.Button(composer, text="Invia  ↑", style="Primary.TButton", command=self.send_message)
        self.send_button.grid(row=0, column=1, padx=(0, 8), pady=8, sticky="ns")

    def _on_return(self, event):
        if event.state & 0x1:  # se premuto shift+Enter ==> a capo e NON invia
            return None
        self.send_message()  # altrimenti se premuto solo Enter ==> sottometti la domanda
        return "break"

    def add_message(self, role, content):
        now = datetime.now().strftime("%H:%M")
        label = "NETSCOPE AI" if role == "assistant" else "TU"
        self.chat.configure(state="normal") # abilito modifica del Widget Text
        self.chat.insert("end", f"{label}  ·  {now}\n", "meta")
        self.chat.insert("end", f"{content}\n", role)
        self.chat.configure(state="disabled") # disabilito la modifica -> sola lettura
        self.chat.see("end")

    def reset_chat(self):
        self.chat.configure(state="normal")  # rendo remporaneamenre il widget chat modificabile
        self.chat.delete("1.0", "end")  # dalla prima riga fino alla fine del testo
        self.chat.configure(state="disabled")  # lo rendo nuovamente in sola lettura per l'utente
        self.add_message("assistant", "Nuova conversazione avviata. Il file attualmente caricato resta disponibile.")

    def send_message(self):
        question = self.prompt.get("1.0", "end").strip()
        if not question or self.is_waiting:
            return
        self.prompt.delete("1.0", "end")
        self.add_message("user", question)

        # Controllo che la KB sia stata creata
        if self.session.workspace is None:
            self.add_message("assistant", "Prima carica un file di output nDPI o converti una cattura PCAP dal pannello laterale.")
            return

        self.is_waiting = True
        self.send_button.configure(state="disabled", text="Analizzo…")
        threading.Thread(target=self._ask_model, args=(question,), daemon=True).start()

    def _ask_model(self, question):
        try:
            target_ip = self.session.active_ip
            answer = query_local_ai(question, json_ready(self.session.workspace), target_ip=target_ip)
        except Exception as error:
            answer = f"Non sono riuscito a contattare il modello locale: {error}"
        self.after(0, lambda: self._complete_answer(answer)) # dice: "Appena possibile, esegui _complete_answer(answer) nel thread della GUI."

    def _complete_answer(self, answer):
        self.add_message("assistant", answer)
        self.is_waiting = False
        self.send_button.configure(state="normal", text="Invia  ↑")
        self.prompt.focus_set()  # rimette il cursore nella casella di testo per scrivere una nuova domanda