#!/usr/bin/env python3
"""Interfaccia desktop multipiattaforma per il Network AI Assistant."""

from __future__ import annotations

import os
import threading
import urllib.request
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from analyzer import parse_ndpi_output, query_local_ai
from converter_window import PcapConverterWindow

COLORS = {
    "bg": "#0b1020", "panel": "#121a2f", "panel_alt": "#18233e",
    "border": "#263454", "text": "#edf2ff", "muted": "#9ba8c8",
    "accent": "#7c5cff", "accent_hover": "#9178ff", "success": "#41d7a7",
    "user": "#6246d8", "bot": "#1b2948", "danger": "#ff7d8f",
}


def json_ready(value):
    """Converte ricorsivamente i set prodotti dal parser in liste JSON."""
    if isinstance(value, set):
        return sorted(json_ready(item) for item in value)
    if isinstance(value, dict):
        return {key: json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_ready(item) for item in value]
    return value


class ChatApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network AI Assistant")
        self.minsize(940, 640)
        self.geometry("1180x760")
        self.configure(bg=COLORS["bg"])
        self.knowledge_base = None
        self.current_file = None
        self.last_generated_file = None
        self.is_waiting = False
        self._configure_style()
        self._build_ui()
        self.after(150, lambda: self.add_message(
            "assistant",
            "Ciao! Sono il tuo analista di rete. Puoi caricare un file .txt di nDPI o convertire un .pcapng tramite il pannello laterale."
            )
        )

    def _configure_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background=COLORS["bg"])
        style.configure("Side.TFrame", background=COLORS["panel"])
        style.configure("TLabel", background=COLORS["bg"], foreground=COLORS["text"], font=("Arial", 14))
        style.configure("Side.TLabel", background=COLORS["panel"], foreground=COLORS["text"])
        style.configure("Muted.TLabel", background=COLORS["panel"], foreground=COLORS["muted"], font=("Arial", 12))
        style.configure("Primary.TButton", background=COLORS["accent"], foreground="white", borderwidth=0,
                        padding=(15, 10), font=("Arial", 12, "bold"))
        style.map("Primary.TButton", background=[("active", COLORS["accent_hover"]), ("disabled", "#4a4775")])
        style.configure("Ghost.TButton", background=COLORS["panel_alt"], foreground=COLORS["text"], borderwidth=0,
                        padding=(11, 8), font=("Arial", 12))
        style.map("Ghost.TButton", background=[("active", COLORS["border"])])

    def _build_ui(self):
        root = ttk.Frame(self)
        root.pack(fill="both", expand=True)

        root.columnconfigure(1, weight=1)
        root.rowconfigure(0, weight=1)

        self._build_sidebar(root)
        self._build_chat(root)

    def _build_sidebar(self, root):
        side = ttk.Frame(root, style="Side.TFrame", width=285)
        side.grid(row=0, column=0, sticky="nsew")
        side.grid_propagate(False)

        brand = ttk.Frame(side, style="Side.TFrame")
        brand.pack(fill="x", padx=20, pady=(24, 18))
        tk.Label(brand, text="✦", bg=COLORS["accent"], fg="white", font=("Arial", 18, "bold"), width=2).pack(side="left", padx=(0, 10))
        title = ttk.Frame(brand, style="Side.TFrame")
        title.pack(side="left")
        ttk.Label(title, text="nDPI ANALYZER TOOL", style="Side.TLabel", font=("Arial", 15, "bold")).pack(anchor="w")
        ttk.Label(title, text="AI network analyst", style="Muted.TLabel").pack(anchor="w")

        ttk.Label(side, text="ANALISI ATTIVA", style="Muted.TLabel", font=("Arial", 10, "bold")).pack(anchor="w",
                                                                                                     padx=20)
        self.file_status = ttk.Label(side, text="Nessun file caricato", style="Side.TLabel", wraplength=240, font=("Arial", 11, "bold"))
        self.file_status.pack(anchor="w", padx=20, pady=(6, 2))
        self.stats_label = ttk.Label(side, text="Carica un output .txt o converti un pcap", style="Muted.TLabel", wraplength=240, font=("Arial", 10))
        self.stats_label.pack(anchor="w", padx=20)

        # Pulsante 1 --> Carica file TXT
        ttk.Button(side, text="＋  Carica file .txt", style="Primary.TButton", command=self.load_file).pack(fill="x", padx=20, pady=(12, 6))

        # Pulsante 2 --> Apre la finestra di conversione
        ttk.Button(side, text="⚡  Converti PCAP con nDPI", style="Ghost.TButton", command=self.open_pcap_converter).pack(fill="x", padx=20, pady=(0, 6))

        # Pulsante 3 --> Scorciatoia ultimo file generato
        self.btn_load_recent = tk.Button(
            side,
            text="➔  Usa ultimo file generato",
            bg=COLORS["panel_alt"],
            fg=COLORS["success"],
            font=("Arial", 10, "bold"),
            relief="flat",
            state="disabled",
            command=self._load_last_generated
        )
        self.btn_load_recent.pack(fill="x", padx=20, pady=(0, 18))

        ttk.Separator(side).pack(fill="x", padx=20, pady=(0, 16))
        ttk.Label(side, text="SUGGERIMENTI", style="Muted.TLabel", font=("Arial", 10, "bold")).pack(anchor="w", padx=20)
        suggestions = [
            "Quali fingerprint JA4 usa l'host 192.168.2.2?",
            "Mostrami la frequenza delle app e i volumi in byte",
            "Mostrami i domini più frequenti",
            "Ci sono fingerprint JA4 sospetti?"
        ]
        for prompt in suggestions:
            button = tk.Button(side, text=prompt, command=lambda p=prompt: self.use_suggestion(p),
                               anchor="w", justify="left", wraplength=235, bg=COLORS["panel"], fg=COLORS["muted"],
                               activebackground=COLORS["panel_alt"], activeforeground=COLORS["text"], relief="flat",
                               cursor="hand2", padx=20, pady=6, font=("Arial", 10))
            button.pack(fill="x")

        self.model_status = tk.Label(
            side,
            text="●  Modello locale: verifica...",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=("Arial", 10),
        )
        self.model_status.pack(side="bottom", anchor="w", padx=20, pady=18)
        self.after(0, self._check_model_status)

    def _check_model_status(self):
        try:
            req = urllib.request.Request("http://localhost:1234/v1/models")
            with urllib.request.urlopen(req, timeout=1) as response:
                active = 200 <= response.status < 300
        except Exception:
            active = False

        if active:
            self.model_status.configure(text="●  Modello locale: attivo (1234)", fg=COLORS["success"])
        else:
            self.model_status.configure(text="●  Modello locale: non attivo", fg=COLORS["muted"])

        self.after(4000, self._check_model_status)

    def _build_chat(self, root):
        main = ttk.Frame(root)
        main.grid(row=0, column=1, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(1, weight=1)

        header = ttk.Frame(main)
        header.grid(row=0, column=0, sticky="ew", padx=28, pady=(20, 10))
        ttk.Label(header, text="Network Intelligence", font=("Arial", 19, "bold")).pack(side="left")
        ttk.Label(header, text="Pronto a leggere il tuo traffico", font=("Arial", 12), foreground=COLORS["muted"]).pack(
            side="left", padx=12, pady=(4, 0))
        ttk.Button(header, text="Nuova chat", style="Ghost.TButton", command=self.reset_chat).pack(side="right")

        chat_outer = tk.Frame(main, bg=COLORS["bg"])
        chat_outer.grid(row=1, column=0, sticky="nsew", padx=28, pady=6)
        self.chat = tk.Text(chat_outer, bg=COLORS["bg"], fg=COLORS["text"], relief="flat", borderwidth=0,
                            wrap="word", padx=2, pady=8, state="disabled", font=("Arial", 12), cursor="arrow")
        scroll = ttk.Scrollbar(chat_outer, orient="vertical", command=self.chat.yview)
        self.chat.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.chat.pack(side="left", fill="both", expand=True)
        self.chat.tag_configure("assistant", background=COLORS["bot"], foreground=COLORS["text"], lmargin1=18,
                                lmargin2=18, rmargin=100, spacing1=12, spacing3=12)
        self.chat.tag_configure("user", background=COLORS["user"], foreground="white", lmargin1=100, lmargin2=100,
                                rmargin=18, spacing1=12, spacing3=12, justify="right")
        self.chat.tag_configure("meta", foreground=COLORS["muted"], font=("Arial", 9), spacing1=6)

        composer = tk.Frame(main, bg=COLORS["panel_alt"], highlightbackground=COLORS["border"], highlightthickness=1)
        composer.grid(row=2, column=0, sticky="ew", padx=28, pady=(10, 22))
        composer.columnconfigure(0, weight=1)
        self.prompt = tk.Text(composer, height=2, bg=COLORS["panel_alt"], fg=COLORS["text"], insertbackground="white", relief="flat", wrap="word", padx=12, pady=10, font=("Arial", 12))
        self.prompt.grid(row=0, column=0, sticky="ew")
        self.prompt.bind("<Return>", self._on_return)
        self.send_button = ttk.Button(composer, text="Invia  ↑", style="Primary.TButton", command=self.send_message)
        self.send_button.grid(row=0, column=1, padx=(0, 8), pady=8, sticky="ns")

    def _on_return(self, event):
        if event.state & 0x1: # se premuto shift+Enter ==> a capo e NON invia
            return None
        self.send_message() # altrimenti se premuto solo Enter ==> sottometti la domanda
        return "break"

    def add_message(self, role, content):
        now = datetime.now().strftime("%H:%M")
        label = "NETSCOPE AI" if role == "assistant" else "TU"
        self.chat.configure(state="normal")
        self.chat.insert("end", f"{label}  ·  {now}\n", "meta")
        self.chat.insert("end", f"{content}\n", role)
        self.chat.configure(state="disabled")
        self.chat.see("end")

    def open_pcap_converter(self):
        """Istanzia la finestra separata definita nel modulo converter_window."""
        PcapConverterWindow(self, COLORS)

    def register_generated_file(self, path: str):
        self.last_generated_file = path
        self.btn_load_recent.configure(
            state="normal",
            cursor="hand2",
            text=f"➔  Usa {Path(path).name}"
        )

    def _load_last_generated(self):
        if self.last_generated_file and os.path.exists(self.last_generated_file):
            self.load_file_from_path(self.last_generated_file)

    def load_file(self):
        path = filedialog.askopenfilename(
            title="Scegli l'output nDPI",
            filetypes=[("File di testo", "*.txt *.log"), ("Tutti i file", "*.*")]
        )
        if path:
            self.load_file_from_path(path)

    def load_file_from_path(self, path: str):
        try:
            kb = parse_ndpi_output(path)
        except Exception as error:
            messagebox.showerror("Impossibile leggere il file", str(error))
            return

        self.knowledge_base = kb
        self.current_file = path
        name = Path(path).name
        self.file_status.configure(text=name)
        self.stats_label.configure(
            text=f"{len(kb['hosts'])} host  ·  {len(kb['ja4_to_info'])} JA4\n{len(kb['all_domains'])} domini rilevati"
        )
        self.add_message("assistant", f"Analisi pronta: ho caricato “{name}”. Puoi iniziare a interrogare la baseline.")

    def use_suggestion(self, prompt):
        self.prompt.delete("1.0", "end")
        self.prompt.insert("1.0", prompt)
        self.prompt.focus_set()

    def reset_chat(self):
        self.chat.configure(state="normal") # rendo remporaneamenre il widget chat modificabile
        self.chat.delete("1.0", "end") # dalla prima riga fino alla fine del testo
        self.chat.configure(state="disabled") # lo rendo nuovamente in sola lettura per l'utente
        self.add_message("assistant", "Nuova conversazione avviata. Il file attualmente caricato resta disponibile.")

    def send_message(self):
        question = self.prompt.get("1.0", "end").strip()
        if not question or self.is_waiting:
            return
        self.prompt.delete("1.0", "end")
        self.add_message("user", question)
        if self.knowledge_base is None:
            self.add_message("assistant",
                             "Prima carica un file di output nDPI o converti una cattura PCAP dal pannello laterale.")
            return
        self.is_waiting = True
        self.send_button.configure(state="disabled", text="Analizzo…")
        threading.Thread(target=self._ask_model, args=(question,), daemon=True).start()

    def _ask_model(self, question):
        try:
            answer = query_local_ai(question, json_ready(self.knowledge_base))
        except Exception as error:
            answer = f"Non sono riuscito a contattare il modello locale: {error}"
        self.after(0, lambda: self._complete_answer(answer)) # dice: "Appena possibile, esegui _complete_answer(answer) nel thread della GUI."

    def _complete_answer(self, answer):
        self.add_message("assistant", answer)
        self.is_waiting = False
        self.send_button.configure(state="normal", text="Invia  ↑")
        self.prompt.focus_set() # rimette il cursore nella casella di testo per scrivere una nuova domanda


if __name__ == "__main__":
    app = ChatApp()
    app.mainloop()