#!/usr/bin/env python3
""" Interfaccia desktop multipiattaforma per il Network AI Assistant """

from __future__ import annotations

import os
import urllib.request
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from analytics import Analytics
from chat_interface import ChatApp
from analyzer import parse_ndpi_output
from converter_window import PcapConverterWindow
from gui_utils import COLORS

from NetSession import NetSession

SIDEBAR_W = 220
SIDEBAR_BG = COLORS["panel"]
HOVER_BG = COLORS["bg"]
ITEM_H = 52 # altezza voci sidebar
ITEM_FONT = ("Arial", 12, "bold")

NAV_ITEMS = [
    ("chat", "LLM Chat", "", COLORS["accent"]),
    ("analytics", "Traffic Analytics", "", COLORS["accent"])
]


class SidebarItem(tk.Frame):
    """ Gestisce le varie finestre """

    def __init__(self, parent, key: str, icon: str, label: str, accent: str, on_click, **kwargs):
        super().__init__(parent, bg=SIDEBAR_BG, cursor="hand2", height=ITEM_H, **kwargs)
        self.pack_propagate(False) # non voglio che i widget modifichino la dimensione del contenitore

        self.key = key
        self.style = accent
        self._active = False
        self._on_click = on_click

        self._active_bar = tk.Frame(self, width=4, bg=SIDEBAR_BG)
        self._active_bar.pack(side="left", fill="y")

        self._icon_lbl = tk.Label(self, text=icon, bg=SIDEBAR_BG, fg=COLORS["text"], font=("Arial", 14), padx=6)
        self._icon_lbl.pack(side="left")

        self._text_lbl = tk.Label(self, text=label, bg=SIDEBAR_BG, fg=COLORS["text"], font=ITEM_FONT, anchor="w")
        self._text_lbl.pack(side="left", fill="x", expand=True)

        # Gestione passaggio del mause e click
        self.bind("<Button-1>", self._click)
        self._icon_lbl.bind("<Button-1>", self._click)
        self._text_lbl.bind("<Button-1>", self._click)

        self.bind("<Enter>", self._hover_on)
        self._icon_lbl.bind("<Enter>", self._hover_on)
        self._text_lbl.bind("<Enter>", self._hover_on)

        self.bind("<Leave>", self._hover_off)
        self._icon_lbl.bind("<Leave>", self._hover_off)
        self._text_lbl.bind("<Leave>", self._hover_off)

    def set_active(self, active):
        self._active = active
        self._refresh()

    def _refresh(self):
        if self._active:
            self._active_bar.config(bg=self.style)
            self._icon_lbl.config(bg=HOVER_BG, fg=self.style)
            self._text_lbl.config(bg=HOVER_BG, fg=COLORS["text"], font=ITEM_FONT)
            self.config(bg=HOVER_BG)
        else:
            self._active_bar.config(bg=SIDEBAR_BG)
            self._icon_lbl.config(bg=SIDEBAR_BG, fg=COLORS["muted"])
            self._text_lbl.config(bg=SIDEBAR_BG, fg=COLORS["text"], font=ITEM_FONT)
            self.config(bg=SIDEBAR_BG)

    def _click(self, _event=None):
        self._on_click(self.key)

    def _hover_on(self, _event=None):
        if not self._active:
            self.config(bg=HOVER_BG)
            self._active_bar.config(bg=SIDEBAR_BG)
            self._icon_lbl.config(bg=HOVER_BG, fg=self.style)
            self._text_lbl.config(bg=HOVER_BG)

    def _hover_off(self, _event=None):
        if not self._active:
            self._refresh()


class AnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network AI Assistant")
        self.minsize(940, 640)
        self.geometry("1180x760")
        self.configure(bg=COLORS["bg"])

        self.current_file = None
        self.last_generated_file = None
        self._current_key = None  # pagina attualmente visualizzata
        self.session: NetSession = NetSession()

        self._configure_style()
        self._build_ui()
        self._navigate("chat")  # apre inizialmente la pagina della chat

    def _configure_style(self):
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam") # "clam" -> consente di avere un interfaccia che rimanga consistente multi-piattaforma

        style.configure("TFrame", background=COLORS["bg"])
        style.configure("Side.TFrame", background=COLORS["panel"])
        style.configure("TLabel", background=COLORS["bg"], foreground=COLORS["text"], font=("Arial", 14))
        style.configure("Side.TLabel", background=COLORS["panel"], foreground=COLORS["text"])
        style.configure("Muted.TLabel", background=COLORS["panel"], foreground=COLORS["muted"], font=("Arial", 12))
        style.configure("Primary.TButton", background=COLORS["accent"], foreground="white", borderwidth=0, padding=(15, 10), font=("Arial", 12, "bold"))
        style.map("Primary.TButton", background=[("active", COLORS["accent_hover"]), ("disabled", "#4a4775")])
        style.configure("Ghost.TButton", background=COLORS["panel_alt"], foreground=COLORS["text"], borderwidth=0, padding=(11, 8), font=("Arial", 12))
        style.map("Ghost.TButton", background=[("active", COLORS["border"])])

    def _build_ui(self):
        root = ttk.Frame(self)
        root.pack(fill="both", expand=True)
        root.columnconfigure(1, weight=1)
        root.rowconfigure(0, weight=1)

        self._build_sidebar(root)
        self.build_content_area(root)

    def _build_sidebar(self, root):
        sidebar = ttk.Frame(root, style="Side.TFrame", width=285)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)

        brand = ttk.Frame(sidebar, style="Side.TFrame")
        brand.pack(fill="x", padx=20, pady=(24, 18))
        tk.Label(brand, text="✦", bg=COLORS["accent"], fg="white", font=("Arial", 18, "bold"), width=2).pack(side="left", padx=(0, 10))
        title = ttk.Frame(brand, style="Side.TFrame")
        title.pack(side="left")
        ttk.Label(title, text="nDPI ANALYZER", style="Side.TLabel", font=("Arial", 15, "bold")).pack(anchor="w")
        ttk.Label(title, text="AI network analyst", style="Muted.TLabel").pack(anchor="w")

        ttk.Separator(sidebar).pack(fill="x", padx=20, pady=10)

        # Pulsanti --> Gestine voci della sidebar
        self._nav_items: dict[str, SidebarItem] = {}
        for key, label, icon, style in NAV_ITEMS:  # creazione automatica delle voci del menu laterale
            item = SidebarItem(sidebar, key=key, icon=icon, label=label, accent=style, on_click=self._navigate)
            item.pack(fill="x", pady=2)
            self._nav_items[key] = item

        ttk.Separator(sidebar).pack(fill="x", padx=20, pady=(15, 10))

        ttk.Label(sidebar, text="FILE DI ANALISI", style="Muted.TLabel", font=("Arial", 10, "bold")).pack(anchor="w", padx=20)

        self.file_status = ttk.Label(sidebar, text="Nessun file caricato", style="Side.TLabel", wraplength=240, font=("Arial", 12, "bold"))
        self.file_status.pack(anchor="w", padx=20, pady=(6, 2))
        self.stats_label = ttk.Label(sidebar, text="Carica un output .txt o converti un pcap", style="Muted.TLabel", wraplength=240, font=("Arial", 11))
        self.stats_label.pack(anchor="w", padx=20)


        ttk.Button(sidebar, text="Carica file .txt", style="Primary.TButton", command=self.load_file).pack(fill="x", padx=20, pady=(12, 6))
        ttk.Button(sidebar, text="Converti PCAP con nDPI", style="Ghost.TButton", command=self.open_pcap_converter).pack(fill="x", padx=20, pady=(0, 6))
        self.btn_load_recent = tk.Button(
            sidebar,
            text="➔  Usa ultimo generato",
            bg=COLORS["panel_alt"],
            fg=COLORS["success"],
            font=("Arial", 12, "bold"),
            relief="flat",
            state="disabled",
            command=self._load_last_generated
        )
        self.btn_load_recent.pack(fill="x", padx=20, pady=(5, 18))

        self._build_statusbar(sidebar)

    def _build_statusbar(self, parent):
        bar = tk.Frame(parent, bg=COLORS["panel"], pady=20, padx=10)
        bar.pack(fill="x", side="bottom")

        self.model_status = tk.Label(bar, text="●  Modello locale: verifica...", bg=COLORS["panel"], fg=COLORS["muted"], font=("Arial", 10))
        self.model_status.pack(side="left", anchor="n")
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

    def build_content_area(self, parent):
        content_window = tk.Frame(parent, bg=COLORS["bg"])
        content_window.grid(row=0, column=1, sticky="nsew")

        self._page_header = tk.Frame(content_window, bg=COLORS["panel"], pady=14)
        self._page_header.pack(fill="x")

        self._page_title_lbl = tk.Label(self._page_header, text="", bg=COLORS["panel"], fg=COLORS["text"], font=("Arial", 14, "bold"), padx=24)
        self._page_title_lbl.pack(side="left")

        self._page_subtitle_lbl = tk.Label(self._page_header, text="", bg=COLORS["panel"], fg=COLORS["muted"], font=("Arial", 10), padx=4)
        self._page_subtitle_lbl.pack(side="left")

        self._content_stack = tk.Frame(content_window, bg=COLORS["bg"]) # contenitore che ospita tutte le tab
        self._content_stack.pack(fill="both", expand=True)

        # qui vengono create tutte le pagine dell'applicazione una sola volta
        # Passiamo SOLO self._content_stack come parent e la session per condividere i dati
        self._frames: dict[str, tk.Frame] = {
            "chat": ChatApp(self._content_stack, session=self.session),
            "analytics": Analytics(self._content_stack, session=self.session)
        }

    # associa ad ogni pagina il titolo visualizzato e il titolo descrittivo
    _PAGE_META = {
        "chat": ("LLM Chat", "Comunica con il modello locale per analizzare il traffico"),
        "analytics": ("Traffic Analytics", "Mostra le metriche visive sul traffico analizzato")
    }

    def _navigate(self, key):
        # se la pagina è gia aperta evito di ricaricarla inutilmente
        if key == self._current_key:
            return

        # nascondo la pagina che era aperta, prima di mostrarne un’altra
        if self._current_key:
            if self._current_key in self._nav_items:
                self._nav_items[self._current_key].set_active(False) # recupero la voce della sidebar corrispondente alla pagina corrente e la disattivo
            if self._current_key in self._frames:
                self._frames[self._current_key].pack_forget() # rimossione visiva della pagina vecchia

        self._current_key = key  # memorizzo la nuova pagina
        self._nav_items[key].set_active(True)  # evidenzio la voce nella sidebar

        title, subtitle = self._PAGE_META.get(key, (key, ""))
        self._page_title_lbl.config(text=title)
        self._page_subtitle_lbl.config(text=subtitle)

        # Se stiamo aprendo Analytics eseguo il refresh dei grafici
        if key == "analytics" and hasattr(self._frames[key], "refresh"):
            self._frames[key].refresh()

        self._frames[key].pack(fill="both", expand=True)  # mostra la nuova pagina nell'area centrale

    def open_pcap_converter(self):
        PcapConverterWindow(self)

    def register_generated_file(self, path):
        self.last_generated_file = path
        self.btn_load_recent.configure(state="normal", cursor="hand2", text=f"➔  Usa {Path(path).name}")

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

    def load_file_from_path(self, path):
        try:
            kb = parse_ndpi_output(path)
            self.session.workspace = kb  # memorizzo la KB a livello di sessione condivisa
        except Exception as error:
            messagebox.showerror("Impossibile leggere il file", str(error))
            return

        self.current_file = path
        name = Path(path).name
        self.file_status.configure(text=name)
        self.stats_label.configure(text=f"{len(kb['hosts'])} host  ·  {len(kb['ja4_to_info'])} JA4\n{len(kb['all_domains'])} domini rilevati")

        # Notifica nella chat che l'analisi è pronta (recuperando l'istanza della chat)
        chat_frame = self._frames.get("chat")
        if isinstance(chat_frame, ChatApp):
            chat_frame.add_message("assistant", f"Analisi pronta: ho caricato “{name}”. Puoi iniziare a interrogare la baseline o guardare i grafici nella tab Analytics.")

        # Se il file è stato caricato mentre siamo nella scheda Analytics,
        # forzo un refresh immediato dei grafici e delle summary senza dover cambiare tab
        if self._current_key == "analytics":
            analytics_frame = self._frames.get("analytics")
            if hasattr(analytics_frame, "refresh"):
                analytics_frame.refresh()

if __name__ == "__main__":
    app = AnalyzerApp()
    app.mainloop()