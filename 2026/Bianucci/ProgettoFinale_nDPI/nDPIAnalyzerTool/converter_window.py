#!/usr/bin/env python3
"""Modulo per la conversione da file PCAP/PCAPNG a TXT tramite nDPI."""

import os
import threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from analyzer import run_ndpi_reader

class PcapConverterWindow(tk.Toplevel):
    """Finestra di dialogo modale per eseguire ndpiReader."""

    def __init__(self, parent, colors: dict):
        super().__init__(parent)
        self.parent = parent # salvo il riferimento alla schermata principale
        self.colors = colors
        self.created_txt = None

        self.title("nDPI Extractor (PCAP ➔ TXT)")
        self.geometry("620x460")
        self.minsize(580, 420)
        self.configure(bg=self.colors["panel"])
        self.transient(parent) # dice a Tkinter che questa deve essere considerata come finestra secondaria alla finestra parent
        self.grab_set() # fa sì che tutti gli eventi del mouse e della tastiera vengano indirizzati a questa finestra finché rimane aperta.

        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 20, "pady": 8}

        header = tk.Frame(self, bg=self.colors["panel"])
        header.pack(fill="x", padx=20, pady=(18, 10))
        tk.Label(
            header,
            text="Estrai Metadati con nDPI",
            font=("Arial", 14, "bold"),
            bg=self.colors["panel"],
            fg=self.colors["text"],
        ).pack(anchor="w")
        tk.Label(
            header,
            text="Esegue ndpiReader -v 2 sul file di cattura e produce il dump per l'assistente.",
            font=("Arial", 10),
            bg=self.colors["panel"],
            fg=self.colors["muted"],
        ).pack(anchor="w")

        # Selezione PCAP
        f_pcap = tk.Frame(self, bg=self.colors["panel"])
        f_pcap.pack(fill="x", **pad)
        tk.Label(f_pcap, text="File di cattura (.pcap / .pcapng):", bg=self.colors["panel"], fg=self.colors["text"], font=("Arial", 10, "bold")).pack(anchor="w")
        self.ent_pcap = self._mostra_pulsante("pcap", f_pcap)

        # Destinazione TXT
        f_txt = tk.Frame(self, bg=self.colors["panel"])
        f_txt.pack(fill="x", **pad)
        tk.Label(f_txt, text="Salva file di output (.txt):", bg=self.colors["panel"], fg=self.colors["text"], font=("Arial", 10, "bold")).pack(anchor="w")
        self.ent_txt = self._mostra_pulsante("txt", f_txt)


        # Status
        self.lbl_status = tk.Label(self, text="", bg=self.colors["panel"], fg=self.colors["success"], font=("Arial", 10))
        self.lbl_status.pack(fill="x", padx=20, pady=(6, 0))

        # Pulsanti inferiori
        f_btn = tk.Frame(self, bg=self.colors["panel"])
        f_btn.pack(fill="x", padx=20, pady=(12, 18), side="bottom")

        self.btn_run = ttk.Button(f_btn, text="⚡  Avvia Estrazione", style="Primary.TButton", command=self._start_conversion)
        self.btn_run.pack(side="left", fill="x", expand=True, padx=(0, 6))

        self.btn_use = tk.Button(
            f_btn,
            text="Usa nel Chatbot ➔",
            bg=self.colors["success"],
            fg=self.colors["bg"],
            font=("Arial", 11, "bold"),
            relief="flat",
            state="disabled",
            command=self._use_in_chat
        )
        self.btn_use.pack(side="right", fill="x", expand=True, padx=(6, 0), ipady=6)

    def _mostra_pulsante(self, tipo: str, f_file: tk.Frame) -> tk.Entry:
        row_file = tk.Frame(f_file, bg=self.colors["panel"])
        row_file.pack(fill="x", pady=4)
        ent_file = tk.Entry(row_file, bg=self.colors["panel_alt"], fg=self.colors["text"], insertbackground="white", relief="flat", font=("Arial", 10)) # casella di testo che contiene il path del file
        ent_file.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        if tipo == "pcap":
            ttk.Button(row_file, text="Sfoglia…", style="Ghost.TButton", command=self._browse_pcap).pack(side="right")
        elif tipo == "txt":
            ttk.Button(row_file, text="Sfoglia…", style="Ghost.TButton", command=self._browse_txt).pack(side="right")
        return ent_file

    def _browse_pcap(self):
        path = filedialog.askopenfilename(
            title="Seleziona file di cattura",
            filetypes=[("Catture Wireshark/tcpdump", "*.pcapng *.pcap *.cap"), ("Tutti i file", "*.*")]
        )
        if path:
            self.ent_pcap.delete(0, "end")
            self.ent_pcap.insert(0, path)
            p = Path(path)
            suggested_txt = str(p.parent / f"{p.stem}_ndpi.txt")
            self.ent_txt.delete(0, "end")
            self.ent_txt.insert(0, suggested_txt) # scrivo il percorso di output suggerito

    def _browse_txt(self):
        path = filedialog.asksaveasfilename(
            title="Salva output nDPI",
            defaultextension=".txt",
            filetypes=[("File di testo", "*.txt"), ("Tutti i file", "*.*")]
        )
        if path:
            self.ent_txt.delete(0, "end")
            self.ent_txt.insert(0, path)

    def _start_conversion(self):
        pcap = self.ent_pcap.get().strip()
        txt = self.ent_txt.get().strip()
        ndpi_bin = "ndpiReader"

        if not pcap or not txt:
            messagebox.showwarning("Dati mancanti", "Seleziona sia il file PCAP sia il percorso del file TXT.")
            return

        self.btn_run.configure(state="disabled", text="Elaborazione in corso…")
        self.lbl_status.configure(text="Esecuzione di ndpiReader -v 2 in corso...", fg=self.colors["accent"])

        threading.Thread(target=self._run_process, args=(pcap, txt, ndpi_bin), daemon=True).start()

    def _run_process(self, pcap, txt, ndpi_bin):
        try:
            run_ndpi_reader(pcap, txt, ndpi_bin)
            self.after(0, lambda: self._on_success(txt))
        except Exception as e:
            self.after(0, lambda: self._on_error(str(e)))

    def _on_success(self, txt_path):
        self.btn_run.configure(state="normal", text="⚡  Avvia Estrazione")
        self.lbl_status.configure(text="✓ Estrazione completata con successo!", fg=self.colors["success"])
        self.created_txt = txt_path
        self.btn_use.configure(state="normal", cursor="hand2")
        self.parent.register_generated_file(txt_path) # btn utlilizza file...

    def _on_error(self, err_msg):
        self.btn_run.configure(state="normal", text="⚡  Avvia Estrazione")
        self.lbl_status.configure(text="Errore durante l'estrazione", fg=self.colors["danger"])
        messagebox.showerror("Errore ndpiReader", err_msg)

    def _use_in_chat(self):
        if self.created_txt and os.path.exists(self.created_txt):
            self.parent.load_file_from_path(self.created_txt)
            self.destroy() # chiude la finestra corrente