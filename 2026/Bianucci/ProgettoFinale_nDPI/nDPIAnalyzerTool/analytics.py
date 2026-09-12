
""" Scheda per l'analisi delle analytic del traffico di rete """

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from tkinter.ttk import Combobox

from NetSession import NetSession
from charts import ChartFactory, MultiPieChart
from gui_utils import COLORS


def formatta_traffico(tot_bytes):
    unita = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    valore = float(tot_bytes)
    indice = 0
    while valore >= 1000 and indice < len(unita) - 1:
        valore /= 1000.0
        indice += 1

    return f"{valore:.2f} {unita[indice]}"

def converti_secondi_minuti(tempo):
    minuti, secondi = divmod(tempo, 60)
    return minuti, secondi

def _render_combobox_ip(kb, container):
    top_bar = tk.Frame(container, bg=COLORS["panel"])
    top_bar.pack(fill="x", padx=12, pady=(10, 4))
    tk.Label(top_bar, text="Host target:", bg=COLORS["panel"], fg=COLORS["text"], font=("Arial", 10, "bold")).pack(side="left", padx=(0, 8))

    ip_list = [ip for ip in kb.get("hosts", {})]
    combo = Combobox(top_bar, values=ip_list, state="readonly", width=25)
    combo.set("Seleziona un indirizzo IP" if ip_list else "Nessun host selezionabile")
    combo.pack(side="left")
    return combo


class Analytics(ttk.Frame):

    def __init__(self, parent, session: NetSession):
        super().__init__(parent)
        self.session = session

        self._configure_styles()
        self._build_ui()
        self._render_graphs_manager("overview") # default

    def _configure_styles(self):
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")  # "clam" -> consente di avere un interfaccia che rimanga consistente multi-piattaforma

        style.configure("Analytics.TFrame", background=COLORS["bg"])
        style.configure("Side.Analytics.TFrame", background=COLORS["panel"])
        style.configure("Card.TFrame", background=COLORS["panel_alt"])
        style.configure("Muted.TLabel", background=COLORS["panel"], foreground=COLORS["muted"], font=("Arial", 12))
        style.configure("Header.TLabel", background=COLORS["bg"], foreground=COLORS["text"], font=("Arial", 18, "bold"))
        style.configure("SubHeader.TLabel", background=COLORS["bg"], foreground=COLORS["muted"], font=("Arial", 11))
        style.configure("KPIValue.TLabel", background=COLORS["panel_alt"], foreground=COLORS["accent_hover"], font=("Arial", 20, "bold"))
        style.configure("KPITitle.TLabel", background=COLORS["panel_alt"], foreground=COLORS["muted"], font=("Arial", 10))

    def _build_ui(self):
        root = ttk.Frame(self, style="Analytics.TFrame")
        root.pack(fill="both", expand=True)

        root.columnconfigure(1, weight=1)
        root.rowconfigure(0, weight=1)

        self._build_sidebar(root)
        self._build_dashboard(root)

    def _build_sidebar(self, root):
        side = ttk.Frame(root, style="Side.Analytics.TFrame", width=285)
        side.grid(row=0, column=0, sticky="nsew")
        side.grid_propagate(False)

        brand = ttk.Frame(side, style="Side.Analytics.TFrame")
        brand.pack(fill="x", padx=20, pady=(24, 18))
        tk.Label(brand, text="√", bg=COLORS["accent"], fg="white", font=("Arial", 16, "bold"), width=2).pack(side="left", padx=(0, 10))

        title_box = ttk.Frame(brand, style="Side.Analytics.TFrame")
        title_box.pack(side="left")
        ttk.Label(title_box, text="METRICHE & GRAFICI", style="Side.TLabel", font=("Arial", 13, "bold")).pack(anchor="w")
        ttk.Label(title_box, text="Network telemetry", style="Muted.TLabel").pack(anchor="w")
        ttk.Label(side, text="VISTE DISPONIBILI", style="Muted.TLabel", font=("Arial", 10, "bold")).pack(anchor="w", padx=20, pady=(10, 8))

        views = [
            ("Overview Generale", "overview"),
            ("Applicazioni e Categorie", "app&cat"),
            ("Security & Risks", "security"),
            ("Host Profiling & Fingerprints", "hosts"),
            ("Flow Explorer", "explore")
        ]

        for label, view_key in views:
            btn = ttk.Button(
                side,
                text=label,
                style="Ghost.TButton",
                command=lambda vk=view_key: self._render_graphs_manager(vk)
            )
            btn.pack(fill="x", padx=12, pady=2)

        ttk.Separator(side).pack(fill="x", padx=20, pady=20)

        ttk.Button(side, text="Aggiorna metriche", style="Ghost.TButton", command=lambda: self._render_graphs_manager("overview")).pack(fill="x", padx=20, pady=(0, 8))

    def _build_dashboard(self, root):
        self.main_container = ttk.Frame(root, style="Analytics.TFrame")
        self.main_container.grid(row=0, column=1, sticky="nsew", padx=28, pady=20)
        self.main_container.columnconfigure(0, weight=1)
        self.main_container.rowconfigure(2, weight=1)

        self.header_frame = ttk.Frame(self.main_container, style="Analytics.TFrame")
        self.header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        self.view_title = ttk.Label(self.header_frame, text="Panoramica Traffico", style="Header.TLabel")
        self.view_title.pack(anchor="w")
        self.view_desc = ttk.Label(self.header_frame, text="Analisi dei dati rilevati da nDPI", style="SubHeader.TLabel")
        self.view_desc.pack(anchor="w", pady=(2, 0))

        self.summary_container = ttk.Frame(self.main_container, style="Analytics.TFrame")
        self.summary_container.grid(row=1, column=0, sticky="ew", pady=(0, 16))
        for i in range(4):
            self.summary_container.columnconfigure(i, weight=1)

        self._build_summary_slots()

        # Setting area plotting
        self.plot_container = tk.Frame(self.main_container, bg=COLORS["panel"], highlightbackground=COLORS["border"], highlightthickness=1)
        self.plot_container.grid(row=2, column=0, sticky="nsew")

    def _build_summary_slots(self):
        kb = getattr(self.session, "workspace", {}) or {}
        total_hosts = len(kb.get("hosts", []))
        (minuti, secondi) = converti_secondi_minuti(kb.get("durata_cattura", 0))
        total_ja4 = len(kb.get("ja4_to_info", {}))
        total_flows = len(kb.get("flows_list", []))
        total_risks = sum(kb.get("all_risks", {}).values())

        slots = [
            ("Host rilevati", str(total_hosts)),
            ("Durata cattura", str(f"{int(minuti)}m {int(secondi)}s")),
            ("JA4 Fingerprints", str(total_ja4)),
            ("Flussi analizzati", str(total_flows)),
            ("Anomalie / Rischi", str(total_risks))
        ]

        for idx, (title, val) in enumerate(slots):
            card = ttk.Frame(self.summary_container, style="Card.TFrame", padding=(14, 10))
            card.grid(row=0, column=idx, padx=4, sticky="nsew")
            ttk.Label(card, text=title, style="KPITitle.TLabel").pack(anchor="center")
            ttk.Label(card, text=val, style="KPIValue.TLabel").pack(anchor="center", pady=(4, 0))

    def _render_graphs_manager(self, view_key):
        # Ripulisco dai vecchi grafici prima di stamparne di nuovi
        for child in self.plot_container.winfo_children():
            child.destroy()

        titles = {
            "overview": ("Overview Generale", "Volumetria globale e riepilogo statistico"),
            "app&cat": ("Applicazioni e Macro-Categorie", "Distribuzione del volume applicativo per singolo host"),
            "security": ("Security & Threat Risks", "Rilevamento delle minacce ed anomalie strutturali dei flussi"),
            "hosts": ("Host Profiling & Software Imprints", "Associazione host di rete, Fingerprint JA4 e sistemi operativi stimati rilevati"),
            "explore": ("Deep Flow Explorer", "Ispezione approfondita dell'intera sessione")
        }
        title, description = titles.get(view_key, ("Analytics", ""))
        self.view_title.configure(text=title)
        self.view_desc.configure(text=description)

        kb = getattr(self.session, "workspace", None)
        if not kb:
            lbl = tk.Label(self.plot_container, text="Nessun dato di sessione trovato. Carica prima un file .txt.", bg=COLORS["panel"], fg=COLORS["muted"], font=("Arial", 12), justify="center")
            lbl.pack(expand=True)
            return

        # Plotting dei grafici tramite Factory Method
        render_methods = {
            "overview": self._render_overview,
            "app&cat": self._render_app_cat,
            "security": self._render_security,
            "hosts": self._render_hosts_view,
            "explore": self._render_explore
        }
        render_method = render_methods.get(view_key, self._render_overview)
        render_method(kb)

    def _render_overview(self, kb):
        global_app_bytes = {}
        for host_info in kb.get("hosts", {}).values():
            for app, tot_byte in host_info.get("volume_byte_app", {}).items():
                global_app_bytes[app] = global_app_bytes.get(app, 0) + tot_byte

        proto_bytes = kb.get("protocols", {})

        if not global_app_bytes and not proto_bytes:
            lbl = tk.Label(self.plot_container, text="Nessun dato di volume rilevato.", bg=COLORS["panel"], fg=COLORS["muted"])
            lbl.pack(expand=True)
            return

        top_apps = sorted(global_app_bytes.items(), key=lambda x: x[1], reverse=True)[:5]
        top_apps_mb = [(app, byte / (1024 * 1024)) for app, byte in top_apps]
        proto_mb = {proto: byte / (1024 * 1024) for proto, byte in proto_bytes.items() if byte > 0}

        chart = ChartFactory.create_chart("overview_dual", figsize=(11, 4.2))
        chart.embed_in(self.plot_container)
        chart.draw(
            app_data=top_apps_mb,
            proto_data=proto_mb,
            title_left="Top 5 Applicazioni per Traffico (MB)",
            title_right="Composizione Protocolli di Trasporto"
        )

    def _render_app_cat(self, kb):
        # ComboBox di scelta IP in alto
        combo = _render_combobox_ip(kb, self.plot_container)

        host_info_frame = tk.Frame(self.plot_container, bg=COLORS["panel"])
        host_info_frame.pack(fill="x", padx=12, pady=(8, 8))
        os_label = tk.Label(host_info_frame, text="Operating System: -", bg=COLORS["panel"], fg=COLORS["text"], font=("Arial", 12))
        os_label.pack(side="left", padx=(0, 20))
        total_bytes_label = tk.Label(host_info_frame, text="Total Bytes Transferred: -", bg=COLORS["panel"], fg=COLORS["text"], font=("Arial", 12))
        total_bytes_label.pack(side="left")

        multi_pie: MultiPieChart = ChartFactory.create_chart("multi_pie", figsize=(9, 4.8))
        multi_pie.embed_in(self.plot_container)
        multi_pie.show_placeholder("Seleziona un IP dal menu per visualizzare i grafici")

        def on_ip_selected(event):
            self.ip = event.widget.get()
            self.session.active_ip = self.ip
            host_info = kb.get("hosts", {}).get(self.ip, {})

            os_label.configure(text=f"Operating System: {host_info.get('os_name', '-')}")
            byte_dict = host_info.get("volume_byte_app", {})
            somma = sum(byte_dict.values())
            total_bytes_label.configure(text=f"Total Bytes Transferred: {formatta_traffico(somma) if byte_dict != {} else 0}")

            multi_pie.draw(
                host_info.get("volume_byte_app", {}),
                host_info.get("categorie", {}),
                host_info.get("breeds", {})
            )

        combo.bind("<<ComboboxSelected>>", on_ip_selected)

    def _render_security(self, kb):
        chart_frame = tk.Frame(self.plot_container, bg=COLORS["panel"])
        chart_frame.pack(fill="x", side="top", padx=12, pady=(8, 4))

        risks_dict = kb.get("all_risks", {})
        if risks_dict:
            sorted_risks = sorted(risks_dict.items(), key=lambda x: x[1], reverse=True)
            chart = ChartFactory.create_chart("horizontal_bar", figsize=(8.5, 3.0))
            chart.embed_in(chart_frame)
            chart.draw(
                categories=[k for k, _ in sorted_risks],
                values=[v for _, v in sorted_risks],
                title="Incidenza Anomalie e Indicatori di Rischio nDPI",
                color=COLORS["danger"]
            )
        else:
            lbl_no_risk = tk.Label(
                chart_frame,
                text="Nessun indicatore di rischio o anomalia rilevato nei flussi analizzati!",
                bg=COLORS["panel"],
                fg=COLORS["success"],
                font=("Arial", 11, "bold"),
                pady=20
            )
            lbl_no_risk.pack(expand=True)

        info_table_frame = tk.Frame(self.plot_container, bg=COLORS["panel"])
        info_table_frame.pack(fill="x", padx=12, pady=(10, 4))

        combo = _render_combobox_ip(kb, info_table_frame)

        host_ip_label = tk.Label(info_table_frame, text="Host IP: -", bg=COLORS["panel"], fg=COLORS["text"], font=("Arial", 11, "bold"))
        host_ip_label.pack(side="left", padx=(12, 16))
        total_risk_flow_label = tk.Label(info_table_frame, text="Flussi a rischio: -", bg=COLORS["panel"], fg=COLORS["danger"], font=("Arial", 11, "bold"))
        total_risk_flow_label.pack(side="left")

        table_frame = tk.Frame(self.plot_container, bg=COLORS["panel"])
        table_frame.pack(fill="both", expand=True, padx=12, pady=(6, 12))

        columns = ("id_flow", "score", "risks_summary", "applicazione", "dst_SNI_IP", "traffico")
        tree = ttk.Treeview(table_frame, columns=columns, show="headings", style="Custom.Treeview")

        tree.heading("id_flow", text="ID Flusso")
        tree.heading("score", text="Score")
        tree.heading("risks_summary", text="Tipologia anomalia")
        tree.heading("applicazione", text="Applicazione")
        tree.heading("dst_SNI_IP", text="Destinazione / SNI")
        tree.heading("traffico", text="Volume Dati")

        tree.column("id_flow", width=70, anchor="center", stretch=False)
        tree.column("score", width=60, anchor="center", stretch=False)
        tree.column("risks_summary", width=280, anchor="w", stretch=True)
        tree.column("applicazione", width=130, anchor="center", stretch=False)
        tree.column("dst_SNI_IP", width=260, anchor="w", stretch=True)
        tree.column("traffico", width=95, anchor="center", stretch=False)

        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)

        def on_ip_selected(event):
            selected_ip = event.widget.get()
            self.session.active_ip = selected_ip
            host_info = kb.get("hosts", {}).get(selected_ip, {})
            risk_info = host_info.get("risks", {})

            tree.delete(*tree.get_children()) # Pulisco la tabella dai record dell'IP precedente

            total_flows_count = sum(len(coppie) for coppie in risk_info.values())
            host_ip_label.configure(text=f"Host IP: {selected_ip}")
            total_risk_flow_label.configure(text=f"Flussi a rischio: {total_flows_count}")

            if not risk_info:
                tree.insert("", "end", values=("-", "-", "Nessuna attività anomala registrata per questo host", "-", "-", "-"))
                return

            flow_list = host_info.get("flows_list", [])

            all_risk_flows = []
            for risk_type, coppie in risk_info.items():
                for flow_id, score in coppie:
                    all_risk_flows.append((flow_id, score, risk_type))

            all_risk_flows.sort(key=lambda x: x[1], reverse=True)

            for flow_id, score, risk_type in all_risk_flows:
                flow = next((f for f in flow_list if str(f.get("id")) == str(flow_id)), None)
                app = flow.get("app") if flow else "-"
                dominio = flow.get("sni") or flow.get("dst") if flow else "-"
                tot_bytes = flow.get("bytes", 0) if flow else 0

                # Se è un'anomalia di entropia ==> ho catturato la stringa di dettaglio
                display_risk = risk_type
                if "entrop" in risk_type.lower() and flow and flow.get("entropy"):
                    display_risk = f"{risk_type} [{flow.get('entropy')}]"

                tree.insert("", "end", values=(flow_id, score, display_risk, app, dominio, formatta_traffico(tot_bytes)))

        combo.bind("<<ComboboxSelected>>", on_ip_selected)

    def _render_hosts_view(self, kb):
        filter_frame = tk.Frame(self.plot_container, bg=COLORS["panel"])
        filter_frame.pack(fill="x", padx=16, pady=(12, 8))

        tk.Label(filter_frame, text="Host IP:", bg=COLORS["panel"], fg=COLORS["text"], font=("Arial", 10, "bold")).pack(side="left", padx=(0, 6))
        ip_list = list(kb.get("hosts", {}).keys())
        ip_combo = Combobox(filter_frame, values=ip_list, state="readonly", width=22)
        ip_combo.set("Seleziona IP..." if ip_list else "Nessun host")
        ip_combo.pack(side="left", padx=(0, 16))

        tk.Label(filter_frame, text="Applicazione:", bg=COLORS["panel"], fg=COLORS["text"], font=("Arial", 10, "bold")).pack(side="left", padx=(0, 6))
        app_combo = Combobox(filter_frame, values=[], state="readonly", width=22)
        app_combo.set("Tutte le applicazioni")
        app_combo.pack(side="left")

        info_card = tk.Frame(self.plot_container, bg=COLORS["panel_alt"], highlightbackground=COLORS["border"], highlightthickness=1)
        info_card.pack(fill="x", padx=16, pady=8)
        lbl_os = tk.Label(info_card, text="Sistema Operativo stimato: -", bg=COLORS["panel_alt"], fg=COLORS["text"], font=("Arial", 11, "bold"))
        lbl_os.pack(anchor="w", padx=14, pady=(8, 2))
        lbl_stats = tk.Label(info_card, text="Traffico selezionato: - | Flussi TLS/QUIC: -", bg=COLORS["panel_alt"], fg=COLORS["muted"], font=("Arial", 10))
        lbl_stats.pack(anchor="w", padx=14, pady=(2, 8))


        table_frame = tk.Frame(self.plot_container, bg=COLORS["panel"])
        table_frame.pack(fill="both", expand=True, padx=16, pady=(4, 12))

        columns = ("id", "app","proto_desc", "sni_status", "sni_traffic", "alpn_ja4", "full_ja4", "check")
        tree = ttk.Treeview(table_frame, columns=columns, show="headings", style="Custom.Treeview")

        tree.heading("id", text="ID")
        tree.heading("app", text="Applicazione")
        tree.heading("proto_desc", text="Protocollo L4")
        tree.heading("sni_status", text="SNI da JA4")
        tree.heading("sni_traffic", text="SNI Rilevato da nDPI")
        tree.heading("alpn_ja4", text="ALPN (JA4)")
        tree.heading("full_ja4", text="Fingerprint JA4 Completa")
        tree.heading("check", text="Esito Confronto")

        tree.column("id", width=50, anchor="center", stretch=False)
        tree.column("app", width=120, anchor="center", stretch=False)
        tree.column("proto_desc", width=120, anchor="center", stretch=False)
        tree.column("sni_status", width=110, anchor="center", stretch=False)
        tree.column("sni_traffic", width=240, anchor="w", stretch=False)
        tree.column("alpn_ja4", width=90, anchor="center", stretch=False)
        tree.column("full_ja4", width=220, anchor="w", stretch=True)
        tree.column("check", width=110, anchor="center", stretch=False)

        tree.tag_configure("match_ok", foreground=COLORS["success"])
        tree.tag_configure("mismatch", background="#2b1a20", foreground=COLORS["danger"])
        tree.tag_configure("no_ja4", foreground=COLORS["muted"])

        scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        scroll_x = ttk.Scrollbar(table_frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

        scroll_y.pack(side="right", fill="y")
        scroll_x.pack(side="bottom", fill="x")
        tree.pack(side="left", fill="both", expand=True)

        def update_host_view(*args):
            selected_ip = ip_combo.get()
            self.session.active_ip = selected_ip
            selected_app = app_combo.get()

            host_info = kb.get("hosts", {}).get(selected_ip, {})
            if not host_info:
                return

            available_apps = sorted(list(host_info.get("frequenza_app", {}).keys()))
            app_combo.configure(values=["Tutte le applicazioni"] + available_apps)

            if selected_app not in ["Tutte le applicazioni"] + available_apps:
                app_combo.set("Tutte le applicazioni")
                selected_app = "Tutte le applicazioni"

            os_name = host_info.get("os_name", "Sconosciuto")
            flows = host_info.get("flows_list", [])
            if selected_app != "Tutte le applicazioni":
                filtered_flows = [f for f in flows if f.get("app") == selected_app]
            else:
                filtered_flows = flows

            total_bytes = sum(f.get("bytes", 0) for f in filtered_flows)
            lbl_os.configure(text=f"Sistema Operativo stimato: {os_name}")
            lbl_stats.configure(text=f"Traffico Totale: {formatta_traffico(total_bytes)}  |  Flussi selezionati: {len(filtered_flows)}  |  Domini unici host: {len(host_info.get('domains', set()))}")

            tree.delete(*tree.get_children())
            for f in filtered_flows:
                ja4_str = f.get("ja4") or ""
                sni_actual = f.get("sni") or "-"
                flow_id = f.get("id", "-")
                app_name = f.get("app", "-")

                prima_sezione = ja4_str.split("_")[0]

                if prima_sezione:
                    tipo_l4 = "TCP" if prima_sezione.startswith("t") else ("QUIC" if prima_sezione.startswith("q") else "Altro")
                else:
                    tipo_l4 = f.get("proto", "-")
                proto_desc = f"{tipo_l4}" if tipo_l4 else ""

                # SNI ('d' = domain, 'i' = ip/assente)
                sni_code = prima_sezione[3] if len(prima_sezione) >= 4 else "-"
                sni_atteso = "Dominio ('d')" if sni_code == "d" else ("IP diretto ('i')" if sni_code == "i" else "-")

                # ALPN
                alpn_val = prima_sezione[-2:] if len(prima_sezione) >= 2 else "-"

                has_sni = bool(f.get("sni"))
                if sni_code == "d":
                    if has_sni:
                        check_status = "Match!"
                        tag = "match_ok"
                    else:
                        check_status = "SNI assente!"
                        tag = "mismatch"
                elif sni_code == "i":
                    if not has_sni:
                        check_status = "Match!"
                        tag = "match_ok"
                    else:
                        check_status = "SNI inatteso!"
                        tag = "mismatch"
                else:
                    check_status = "-"
                    tag = ""

                # traffico DNS, ICMP o HTTP in chiaro
                if not ja4_str:
                    tree.insert("", "end", values=(flow_id, app_name, proto_desc, "-", sni_actual, "-", "Non cifrato / Nessuna JA4", "-"), tags=("no_ja4",))
                else:
                    tree.insert("", "end", values=(flow_id, app_name, proto_desc, sni_atteso, sni_actual, alpn_val, ja4_str, check_status), tags=(tag,))

        ip_combo.bind("<<ComboboxSelected>>", lambda e: (app_combo.set("Tutte le applicazioni"), update_host_view()))
        app_combo.bind("<<ComboboxSelected>>", update_host_view)

        #if ip_list:
            #ip_combo.set(ip_list[0])
            #update_host_view()

    def _render_explore_(self, kb):
        legend_frame = tk.Frame(self.plot_container, bg=COLORS["panel"])
        legend_frame.pack(fill="x", padx=12, pady=(8, 4))
        tk.Label(legend_frame, text="Legenda colori flussi:", bg=COLORS["panel"], fg=COLORS["text"], font=("Arial", 9, "bold")).pack(side="left", padx=(4, 12))

        legend_badges = [
            ("Flusso con anomalie / rischi", COLORS["danger"], "#2b1a20"),
            ("Upload significativo (>100 KB)", "#ffb84d", COLORS["panel"]),
            ("Flusso regolare", COLORS["text"], COLORS["panel"])
        ]

        for text, fg_col, bg_col in legend_badges:
            badge = tk.Label(legend_frame, text=text, bg=bg_col, fg=fg_col, font=("Arial", 9, "bold"), padx=6, pady=2, relief="flat")
            badge.pack(side="left", padx=6)

        table_frame = tk.Frame(self.plot_container, bg=COLORS["panel"])
        table_frame.pack(fill="both", expand=True, padx=12, pady=12)

        columns = ("id", "socket", "proto_L4", "app", "sni", "tls_ver", "cipher", "direction", "traffic_split", "duration", "speed")

        tree = ttk.Treeview(table_frame, columns=columns, show="headings", style="Custom.Treeview")
        tree.heading("id", text="ID")
        tree.heading("socket", text="Socket (Sorgente -> Destinazione)")
        tree.heading("proto_L4", text="Protocollo L4")
        tree.heading("app", text="Applicazione")
        tree.heading("sni", text="Hostname / SNI")
        tree.heading("tls_ver", text="Versione TLS")
        tree.heading("cipher", text="Cipher Suite")
        tree.heading("direction", text="Tipo traffico")
        tree.heading("traffic_split", text="Upload / Download")
        tree.heading("duration", text="Durata")
        tree.heading("speed", text="Velocità media")

        tree.column("id", width=45, anchor="center", stretch=False)
        tree.column("socket", width=250, anchor="center", stretch=True)
        tree.column("proto_L4", width=110, anchor="center", stretch=False)
        tree.column("app", width=110, anchor="center", stretch=False)
        tree.column("sni", width=200, anchor="center", stretch=True)
        tree.column("tls_ver", width=90, anchor="center", stretch=False)
        tree.column("cipher", width=210, anchor="center", stretch=False)
        tree.column("direction", width=95, anchor="center", stretch=False)
        tree.column("traffic_split", width=155, anchor="center", stretch=False)
        tree.column("duration", width=70, anchor="center", stretch=False)
        tree.column("speed", width=95, anchor="center", stretch=False)

        tree.tag_configure("upload_alert", foreground="#ffb84d")
        tree.tag_configure("alert_risk", background="#2b1a20", foreground=COLORS["danger"])
        tree.tag_configure("clear", foreground="black")

        scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        scroll_x = ttk.Scrollbar(table_frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

        scroll_y.pack(side="right", fill="y")
        scroll_x.pack(side="bottom", fill="x")
        tree.pack(side="left", fill="both", expand=True)

        for f in kb.get("flows_list", []):
            socket_str = f"{f['src']} -> {f['dst']}"

            sent_str = formatta_traffico(f.get("bytes_sent", 0))
            rcvd_str = formatta_traffico(f.get("bytes_rcvd", 0))
            split_str = f"UP: {sent_str} | DOWN: {rcvd_str}"

            speed_val = f.get("speed_kbs", 0.0)
            speed_str = f"{formatta_traffico(speed_val * 1000)}/s"

            tag_name = "clear"
            if f.get("risks"):
                tag_name = "alert_risk"
            elif f.get("direction") == "Upload" and f.get("bytes_sent", 0) > 100 * 1024:
                tag_name = "upload_alert"

            tree.insert("", "end", values=(f["id"], socket_str, f["proto"], f["app"], f.get("sni") or "-", f.get("tls_version", "-"),
                        f.get("cipher", "-"), f.get("direction", "-"), split_str, f.get("duration", "-"), speed_str),tags=(tag_name,))

    def _render_explore(self, kb):
        top_bar = tk.Frame(self.plot_container, bg=COLORS["panel"])
        top_bar.pack(fill="x", padx=12, pady=(8, 4))

        tk.Label(top_bar, text="Legenda colori flussi:", bg=COLORS["panel"], fg=COLORS["text"], font=("Arial", 9, "bold")).pack(side="left", padx=(4, 8))
        tk.Label(top_bar, text="Flusso con anomalie / rischi", bg="#2b1a20", fg=COLORS["danger"], font=("Arial", 9, "bold"), padx=6, pady=2).pack(side="left", padx=4)
        lbl_upload_badge = tk.Label(top_bar, text="Upload significativo (> soglia KB)", bg=COLORS["panel"], fg="#ffb84d", font=("Arial", 9, "bold"), padx=6, pady=2)
        lbl_upload_badge.pack(side="left", padx=4)
        tk.Label(top_bar, text="Flusso regolare", bg=COLORS["panel"], fg=COLORS["text"], font=("Arial", 9, "bold"), padx=6, pady=2).pack(side="left", padx=4)

        # soglia
        control_frame = tk.Frame(top_bar, bg=COLORS["panel"])
        control_frame.pack(side="right", padx=(8, 4))
        tk.Label(control_frame, text="Soglia Upload:", bg=COLORS["panel"], fg=COLORS["muted"], font=("Arial", 9, "bold")).pack(side="left", padx=(0, 4))

        upload_threshold_var = tk.StringVar(value="100")
        threshold_spin = ttk.Spinbox(
            control_frame,
            from_=10,
            to=10000,
            increment=50,
            textvariable=upload_threshold_var,
            width=6,
            justify="center"
        )
        threshold_spin.pack(side="left")
        tk.Label(control_frame, text="KB", bg=COLORS["panel"], fg=COLORS["muted"], font=("Arial", 9)).pack(side="left", padx=(3, 0))


        table_frame = tk.Frame(self.plot_container, bg=COLORS["panel"])
        table_frame.pack(fill="both", expand=True, padx=12, pady=12)
        columns = ("id", "socket", "proto_L4", "app", "sni", "tls_ver", "cipher", "direction", "traffic_split", "duration", "speed")

        tree = ttk.Treeview(table_frame, columns=columns, show="headings", style="Custom.Treeview")
        tree.heading("id", text="ID")
        tree.heading("socket", text="Socket (Sorgente -> Destinazione)")
        tree.heading("proto_L4", text="Protocollo L4")
        tree.heading("app", text="Applicazione")
        tree.heading("sni", text="Hostname / SNI")
        tree.heading("tls_ver", text="Versione TLS")
        tree.heading("cipher", text="Cipher Suite")
        tree.heading("direction", text="Tipo traffico")
        tree.heading("traffic_split", text="Upload / Download")
        tree.heading("duration", text="Durata")
        tree.heading("speed", text="Velocità media")

        tree.column("id", width=45, anchor="center", stretch=False)
        tree.column("socket", width=250, anchor="center", stretch=True)
        tree.column("proto_L4", width=110, anchor="center", stretch=False)
        tree.column("app", width=110, anchor="center", stretch=False)
        tree.column("sni", width=200, anchor="center", stretch=True)
        tree.column("tls_ver", width=90, anchor="center", stretch=False)
        tree.column("cipher", width=210, anchor="center", stretch=False)
        tree.column("direction", width=95, anchor="center", stretch=False)
        tree.column("traffic_split", width=155, anchor="center", stretch=False)
        tree.column("duration", width=70, anchor="center", stretch=False)
        tree.column("speed", width=95, anchor="center", stretch=False)

        tree.tag_configure("upload_alert", foreground="#ffb84d")
        tree.tag_configure("alert_risk", background="#2b1a20", foreground=COLORS["danger"])
        tree.tag_configure("clear", foreground="black")

        scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        scroll_x = ttk.Scrollbar(table_frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        scroll_y.pack(side="right", fill="y")
        scroll_x.pack(side="bottom", fill="x")
        tree.pack(side="left", fill="both", expand=True)

        def populate_tree():
            try:
                threshold_kb = float(upload_threshold_var.get().strip() or 100)
            except ValueError:
                threshold_kb = 100.0

            threshold_bytes = threshold_kb * 1024
            lbl_upload_badge.configure(text=f"Upload significativo (> {int(threshold_kb)} KB)")

            tree.delete(*tree.get_children())
            for f in kb.get("flows_list", []):
                socket_str = f"{f['src']} -> {f['dst']}"
                sent_str = formatta_traffico(f.get("bytes_sent", 0))
                rcvd_str = formatta_traffico(f.get("bytes_rcvd", 0))
                split_str = f"UP: {sent_str} | DOWN: {rcvd_str}"

                speed_val = f.get("speed_kbs", 0.0)
                speed_str = f"{formatta_traffico(speed_val * 1000)}/s"

                tag_name = "clear"
                if f.get("risks"):
                    tag_name = "alert_risk"
                elif f.get("direction") == "Upload" and f.get("bytes_sent", 0) > threshold_bytes:
                    tag_name = "upload_alert"

                tree.insert("", "end", values=(f["id"], socket_str, f["proto"], f["app"], f.get("sni") or "-",
                                                            f.get("tls_version", "-"), f.get("cipher", "-"), f.get("direction", "-"),
                                                            split_str, f.get("duration", "-"), speed_str
                                                            ), tags=(tag_name,)
                            )

        # Aggiornamento colori in base alla soglia al cambio valore
        upload_threshold_var.trace_add("write", lambda *_: populate_tree())

        populate_tree() # primo popolamento all'apertura della vista

    def refresh(self):
        """ Metodo chiamato al cambio di tab per aggiornare summary_slot e grafici leggendo la session """
        self._build_summary_slots()
        self._render_graphs_manager("overview")