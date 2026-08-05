import queue
from collections import deque
import customtkinter as ctk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.patches as mpatches
import utils

# Mappa dei colori
CLUSTER_COLORS = {
    utils.NEAR_CLUSTER: "#2ecc71",       # Verde
    utils.MEDIUM_CLUSTER: "#f1c40f",     # Giallo
    utils.FAR_CLUSTER: "#e67e22",        # Arancione
    utils.OUT_OF_RANGE_CLUSTER: "#e74c3c" # Rosso
}

DEVICE_COLORS = ["#3498db", "#9b59b6", "#1abc9c", "#95a5a6"] # AP, STA, MESH, UNIDENTIFIED
DEVICE_NAMES = ["AP", "STA", "MESH", "UNIDENTIFIED"]

class Dashboard(ctk.CTk):
    def __init__(self, stats_queue: queue.Queue):
        super().__init__()
        
        self.stats_queue = stats_queue
        
        # Impostazioni finestra
        self.title("WI-FI Analyzer Dashboard")
        self.geometry("1100x850")
        ctk.set_appearance_mode("dark")
        self.bg_color = "#242424" # Colore di sfondo di default per il dark mode CTk
        
        # Struttura per tracciare il cluster visualizzato e quello su cui passa il mouse
        self.selected_cluster = None
        self.hovered_cluster = None
        
        # Strutture dati storiche per il grafico a linee
        self.history_len = 30
        self.history = {
            utils.NEAR_CLUSTER: {'pkts': deque(maxlen=self.history_len), 'vol': deque(maxlen=self.history_len)},
            utils.MEDIUM_CLUSTER: {'pkts': deque(maxlen=self.history_len), 'vol': deque(maxlen=self.history_len)},
            utils.FAR_CLUSTER: {'pkts': deque(maxlen=self.history_len), 'vol': deque(maxlen=self.history_len)},
            utils.OUT_OF_RANGE_CLUSTER: {'pkts': deque(maxlen=self.history_len), 'vol': deque(maxlen=self.history_len)},
            'time': deque(maxlen=self.history_len)
        }
        self.current_time_step = 0
        self.last_data = None
        
        # --- Configurazione dei Container Principali ---
        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.pack(fill="both", expand=True)
        
        # Creazione Viste
        self.view_dashboard = self._create_dashboard_view()
        self.view_cluster = self._create_cluster_detail_view()
        self.view_performance = self._create_performance_view()
        
        # Mostra la view principale
        self.show_view(self.view_dashboard)
        
        # Avvia il polling della coda
        self.after(2000, self.poll_queue)
        
    def _create_dashboard_view(self):
        frame = ctk.CTkFrame(self.container, fg_color="transparent")
        
        # --- 1. GLOBAL STATS (Alto) ---
        self.global_stats_frame = ctk.CTkFrame(frame, fg_color="#2b2b2b", corner_radius=10, border_width=1, border_color="#3a3a3a")
        self.global_stats_frame.pack(fill="x", padx=10, pady=(10, 5))
        
        self.lbl_global_traffic = ctk.CTkLabel(
            self.global_stats_frame, 
            text="Global Traffic: 0 Pkts/s | 0 Bytes/s", 
            font=("Segoe UI", 15, "bold"), text_color="#2ecc71"
        )
        self.lbl_global_traffic.pack(side="left", padx=(20, 15), pady=12)
        
        # NUOVO WIDGET: Traffico Non Assegnato
        self.lbl_unassigned = ctk.CTkLabel(
            self.global_stats_frame,
            text="Unassigned Traffic (Immediate/Session): Pkts 0.0%/0.0% | Vol 0.0%/0.0%",
            font=("Segoe UI", 13, "bold"), text_color="#e67e22"
        )
        self.lbl_unassigned.pack(side="left", padx=15, pady=12)
        
        self.lbl_global_devices = ctk.CTkLabel(
            self.global_stats_frame, 
            text="AP: 0 | STA: 0 | MESH: 0 | UNID: 0", 
            font=("Segoe UI", 13), text_color="#e0e0e0"
        )
        self.lbl_global_devices.pack(side="left", padx=15, pady=12)
        
        self.lbl_global_random = ctk.CTkLabel(
            self.global_stats_frame, 
            text="Randomized MACs: 0", 
            font=("Segoe UI", 13, "bold"), text_color="#3498db"
        )
        self.lbl_global_random.pack(side="right", padx=20, pady=12)
        
        # --- 2. GRAFICO A LINEE (Centro Alto) ---
        line_chart_container = ctk.CTkFrame(frame, fg_color="#2b2b2b", corner_radius=10, border_width=1, border_color="#3a3a3a")
        line_chart_container.pack(fill="x", padx=10, pady=5)
        
        # Toggle
        self.chart_mode = ctk.StringVar(value="Packets / Sec")
        self.toggle_mode = ctk.CTkSegmentedButton(
            line_chart_container, 
            values=["Packets / Sec", "Bytes / Sec"], 
            variable=self.chart_mode, 
            command=self.update_line_chart
        )
        self.toggle_mode.pack(pady=10)
        
        # Matplotlib Figure per linee - Configurazione ottimizzata
        self.fig_line = Figure(figsize=(10, 2.8), dpi=100, facecolor=self.bg_color)
        self.ax_line = self.fig_line.add_subplot(111)
        self.ax_line.set_facecolor(self.bg_color)
        self.ax_line.tick_params(colors='white')
        self.ax_line.grid(True, linestyle='--', alpha=0.2, color='#888')
        for spine in self.ax_line.spines.values():
            spine.set_edgecolor('#555')
        
        # Inizializza gli oggetti linea vuoti per l'aggiornamento fluido
        self.lines = {}
        for c_name, color in CLUSTER_COLORS.items():
            line, = self.ax_line.plot([], [], color=color, label=c_name, linewidth=2)
            self.lines[c_name] = line
            
        self.ax_line.set_ylabel("Packets / Sec", color="white", fontsize=10)
        self.ax_line.set_xlabel("Time relative to now (s)", color="white", fontsize=10)
        self.ax_line.set_xlim(-60, 0) # Finestra temporale con lo 0 a destra
        self.ax_line.legend(loc="upper left", facecolor="#242424", edgecolor="#444", labelcolor="white", fontsize=9)
        self.fig_line.tight_layout()
            
        self.canvas_line = FigureCanvasTkAgg(self.fig_line, master=line_chart_container)
        self.canvas_line.get_tk_widget().pack(fill="both", expand=True, padx=5, pady=(0, 5))
        
        # --- 3. GRAFICI A TORTA CLUSTER (Centro Basso) ---
        pie_container = ctk.CTkFrame(frame, fg_color="#2b2b2b", corner_radius=10, border_width=1, border_color="#3a3a3a")
        pie_container.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Sub-header per indicare l'interattività
        pie_header = ctk.CTkFrame(pie_container, fg_color="transparent")
        pie_header.pack(fill="x", padx=12, pady=(8, 0))
        
        ctk.CTkLabel(
            pie_header, text="🌐 Clusters Overview", 
            font=("Segoe UI", 14, "bold"), text_color="white"
        ).pack(side="left")
        
        ctk.CTkLabel(
            pie_header, text="💡 Click on a cluster to open details", 
            font=("Segoe UI", 11, "italic"), text_color="#aaaaaa"
        ).pack(side="right")
        
        self.fig_pie = Figure(figsize=(10, 2.6), dpi=100, facecolor=self.bg_color)
        
        # Legenda Globale per i grafici a torta
        labels = ["AP", "STA", "MESH", "UNIDENTIFIED"]
        patches = [mpatches.Patch(color=DEVICE_COLORS[i], label=labels[i]) for i in range(len(labels))]
        self.fig_pie.legend(handles=patches, loc="upper center", ncol=4, facecolor=self.bg_color, labelcolor="white", frameon=False)
        
        self.axes_pie = {
            utils.NEAR_CLUSTER: self.fig_pie.add_subplot(141),
            utils.MEDIUM_CLUSTER: self.fig_pie.add_subplot(142),
            utils.FAR_CLUSTER: self.fig_pie.add_subplot(143),
            utils.OUT_OF_RANGE_CLUSTER: self.fig_pie.add_subplot(144)
        }
        
        # Binding degli eventi di click e hover sui subplots
        self.fig_pie.canvas.mpl_connect('button_press_event', self.on_pie_click)
        self.fig_pie.canvas.mpl_connect('motion_notify_event', self.on_pie_hover)
        
        self.canvas_pie = FigureCanvasTkAgg(self.fig_pie, master=pie_container)
        self.canvas_pie.get_tk_widget().pack(fill="both", expand=True, padx=5, pady=5)
        
        # --- 4. ROW PERFORMANCE (Basso) ---
        self.btn_performance = ctk.CTkButton(
            frame, 
            text="PERFORMANCE METRICS (Click to expand)", 
            height=42, 
            font=("Segoe UI", 14, "bold"),
            fg_color="#1f6aa5", hover_color="#144870",
            corner_radius=8,
            command=lambda: self.show_view(self.view_performance)
        )
        self.btn_performance.pack(fill="x", padx=10, pady=(5, 10), side="bottom")
        
        return frame

    def _create_cluster_detail_view(self):
        frame = ctk.CTkFrame(self.container, fg_color="transparent")
        
        # Header Bar
        top_bar = ctk.CTkFrame(frame, fg_color="#2b2b2b", corner_radius=10, border_width=1, border_color="#3a3a3a")
        top_bar.pack(fill="x", padx=10, pady=10)
        
        btn_back = ctk.CTkButton(
            top_bar, text="⬅ Return to Dashboard", 
            fg_color="#3a3a3a", hover_color="#4a4a4a",
            font=("Segoe UI", 13, "bold"),
            command=lambda: self.show_view(self.view_dashboard)
        )
        btn_back.pack(side="left", padx=12, pady=12)
        
        self.lbl_cluster_title = ctk.CTkLabel(
            top_bar, text="Cluster Details", 
            font=("Segoe UI", 20, "bold"), text_color="white"
        )
        self.lbl_cluster_title.pack(side="left", padx=20)
        
        self.cluster_badge = ctk.CTkLabel(
            top_bar, text=" CLUSTER ", 
            font=("Segoe UI", 12, "bold"), text_color="#1a1a1a",
            fg_color="#2ecc71", corner_radius=6
        )
        self.cluster_badge.pack(side="right", padx=15, pady=12)

        # Scrollable container per i dettagli del cluster
        content_scroll = ctk.CTkScrollableFrame(frame, fg_color="transparent")
        content_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # --- 1. Top Row KPI Cards ---
        kpi_frame = ctk.CTkFrame(content_scroll, fg_color="transparent")
        kpi_frame.pack(fill="x", pady=(0, 12))
        kpi_frame.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="kpi")

        self.cluster_kpis = {}
        kpi_configs = [
            ("total_devs", "TOTAL DEVICES", "0", "MAC Casuali: 0 (0%)", "#3498db"),
            ("round_traffic", "TRAFFIC", "0 Pkts/s", "B/s: 0", "#2ecc71"),
            ("sess_traffic", "SESSION TRAFFIC", "0 Pkts/s", "B/s: 0", "#9b59b6"),
            ("busy_channel", "BUSIEST CHANNEL", "Ch --", "Pkts: 0 | Bytes: 0", "#f1c40f")
        ]

        for idx, (key, title, def_val, def_sub, color) in enumerate(kpi_configs):
            card = ctk.CTkFrame(kpi_frame, fg_color="#2b2b2b", corner_radius=10, border_width=1, border_color="#3a3a3a")
            card.grid(row=0, column=idx, padx=4, pady=4, sticky="nsew")
            
            stripe = ctk.CTkFrame(card, width=5, fg_color=color, corner_radius=0)
            stripe.pack(side="left", fill="y", padx=(0, 8))
            
            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(side="left", fill="both", expand=True, pady=10, padx=(0, 8))
            
            lbl_title = ctk.CTkLabel(inner, text=title, font=("Segoe UI", 10, "bold"), text_color="#aaaaaa", anchor="w")
            lbl_title.pack(fill="x")
            
            lbl_val = ctk.CTkLabel(inner, text=def_val, font=("Segoe UI", 17, "bold"), text_color="white", anchor="w")
            lbl_val.pack(fill="x", pady=(2, 0))
            
            lbl_sub = ctk.CTkLabel(inner, text=def_sub, font=("Segoe UI", 11), text_color="#888888", anchor="w")
            lbl_sub.pack(fill="x", pady=(2, 0))
            
            self.cluster_kpis[key] = (lbl_val, lbl_sub)

        # --- 2. Detail Grid (2 Colonne) ---
        grid_frame = ctk.CTkFrame(content_scroll, fg_color="transparent")
        grid_frame.pack(fill="both", expand=True)
        grid_frame.grid_columnconfigure((0, 1), weight=1, uniform="grid")

        # Colonna Sinistra: Card Composizione Dispositivi
        dev_card = ctk.CTkFrame(grid_frame, fg_color="#2b2b2b", corner_radius=10, border_width=1, border_color="#3a3a3a")
        dev_card.grid(row=0, column=0, padx=4, pady=4, sticky="nsew")
        
        lbl_dev_head = ctk.CTkLabel(dev_card, text="📱 Cluster Composition", font=("Segoe UI", 15, "bold"), text_color="white")
        lbl_dev_head.pack(anchor="w", padx=15, pady=(15, 10))
        
        self.dev_bars = {}
        for dev_type, color in zip(DEVICE_NAMES, DEVICE_COLORS):
            row = ctk.CTkFrame(dev_card, fg_color="transparent")
            row.pack(fill="x", padx=15, pady=8)
            
            lbl_type = ctk.CTkLabel(row, text=dev_type, font=("Segoe UI", 12, "bold"), width=100, anchor="w")
            lbl_type.pack(side="left")
            
            pbar = ctk.CTkProgressBar(row, fg_color="#1a1a1a", progress_color=color, height=12, corner_radius=6)
            pbar.pack(side="left", fill="x", expand=True, padx=10)
            pbar.set(0)
            
            lbl_count = ctk.CTkLabel(row, text="0 (0%)", font=("Segoe UI", 12), width=85, anchor="e")
            lbl_count.pack(side="right")
            
            self.dev_bars[dev_type] = (pbar, lbl_count)

        # Colonna Destra: Card Distribuzione Tipi di Traffico
        tf_card = ctk.CTkFrame(grid_frame, fg_color="#2b2b2b", corner_radius=10, border_width=1, border_color="#3a3a3a")
        tf_card.grid(row=0, column=1, padx=4, pady=4, sticky="nsew")
        
        lbl_tf_head = ctk.CTkLabel(tf_card, text="📊 Traffic composition", font=("Segoe UI", 15, "bold"), text_color="white")
        lbl_tf_head.pack(anchor="w", padx=15, pady=(15, 10))
        
        self.traffic_bars = {}
        tf_configs = [
            ("MGMT", "Management Traffic", "#e67e22"),
            ("CTRL", "Control Traffic", "#f1c40f"),
            ("DATA", "Data Traffic", "#2ecc71")
        ]
        
        for key, name, color in tf_configs:
            row = ctk.CTkFrame(tf_card, fg_color="transparent")
            row.pack(fill="x", padx=15, pady=10)
            
            lbl_type = ctk.CTkLabel(row, text=name, font=("Segoe UI", 12, "bold"), width=130, anchor="w")
            lbl_type.pack(side="left")
            
            pbar = ctk.CTkProgressBar(row, fg_color="#1a1a1a", progress_color=color, height=12, corner_radius=6)
            pbar.pack(side="left", fill="x", expand=True, padx=10)
            pbar.set(0)
            
            lbl_perc = ctk.CTkLabel(row, text="0.0%", font=("Segoe UI", 12), width=60, anchor="e")
            lbl_perc.pack(side="right")
            
            self.traffic_bars[key] = (pbar, lbl_perc)

        return frame

    def _create_performance_view(self):
        frame = ctk.CTkFrame(self.container, fg_color="transparent")
        
        # Header Bar
        top_bar = ctk.CTkFrame(frame, fg_color="#2b2b2b", corner_radius=10, border_width=1, border_color="#3a3a3a")
        top_bar.pack(fill="x", padx=10, pady=10)
        
        btn_back = ctk.CTkButton(
            top_bar, text="⬅ Return to Dashboard", 
            fg_color="#3a3a3a", hover_color="#4a4a4a",
            font=("Segoe UI", 13, "bold"),
            command=lambda: self.show_view(self.view_dashboard)
        )
        btn_back.pack(side="left", padx=12, pady=12)
        
        ctk.CTkLabel(
            top_bar, text="Performance & System Metrics", 
            font=("Segoe UI", 20, "bold"), text_color="white"
        ).pack(side="left", padx=20)

        content_scroll = ctk.CTkScrollableFrame(frame, fg_color="transparent")
        content_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.perf_widgets = {}

        # --- Sezione 1: Performance Istantanea ---
        sec_round = ctk.CTkFrame(content_scroll, fg_color="#2b2b2b", corner_radius=10, border_width=1, border_color="#3a3a3a")
        sec_round.pack(fill="x", pady=8)
        
        lbl_r_head = ctk.CTkLabel(sec_round, text="⏱️ Performance", font=("Segoe UI", 16, "bold"), text_color="white")
        lbl_r_head.pack(anchor="w", padx=15, pady=(15, 10))

        r_grid = ctk.CTkFrame(sec_round, fg_color="transparent")
        r_grid.pack(fill="x", padx=15, pady=(0, 15))
        r_grid.grid_columnconfigure((0, 1, 2), weight=1, uniform="perf_r")

        round_items = [
            ("rnd_queue", "QUEUE SIZE", "0.0 pkts", "#e67e22"),
            ("rnd_pkts_sec", "PROCESSED PACKETS / S", "0 pkts/s", "#2ecc71"),
            ("rnd_vol_sec", "PROCESSED BYTES / S", "0 B/s", "#9b59b6")
        ]

        for idx, (key, title, def_val, color) in enumerate(round_items):
            card = ctk.CTkFrame(r_grid, fg_color="#202020", corner_radius=8, border_width=1, border_color="#333333")
            card.grid(row=0, column=idx, padx=4, pady=4, sticky="nsew")
            
            lbl_t = ctk.CTkLabel(card, text=title, font=("Segoe UI", 10, "bold"), text_color="#aaaaaa")
            lbl_t.pack(anchor="w", padx=10, pady=(10, 2))
            
            lbl_v = ctk.CTkLabel(card, text=def_val, font=("Segoe UI", 16, "bold"), text_color=color)
            lbl_v.pack(anchor="w", padx=10, pady=(0, 10))
            
            self.perf_widgets[key] = lbl_v

        # --- Sezione 2: Session Performance ---
        sec_sess = ctk.CTkFrame(content_scroll, fg_color="#2b2b2b", corner_radius=10, border_width=1, border_color="#3a3a3a")
        sec_sess.pack(fill="x", pady=8)
        
        lbl_s_head = ctk.CTkLabel(sec_sess, text="📈 Session Performance", font=("Segoe UI", 16, "bold"), text_color="white")
        lbl_s_head.pack(anchor="w", padx=15, pady=(15, 10))

        s_grid = ctk.CTkFrame(sec_sess, fg_color="transparent")
        s_grid.pack(fill="x", padx=15, pady=(0, 15))
        s_grid.grid_columnconfigure((0, 1, 2), weight=1, uniform="perf_s")

        sess_items = [
            ("sess_queue", "QUEUE SIZE", "0.0 pkts", "#e67e22"),
            ("sess_pkts_sec", "SESSION PROCESSED PKTS/S", "0 pkts/s", "#2ecc71"),
            ("sess_vol_sec", "SESSION PROCESSED BYTES/S", "0 B/s", "#9b59b6")
        ]

        for idx, (key, title, def_val, color) in enumerate(sess_items):
            card = ctk.CTkFrame(s_grid, fg_color="#202020", corner_radius=8, border_width=1, border_color="#333333")
            card.grid(row=0, column=idx, padx=4, pady=4, sticky="nsew")
            
            lbl_t = ctk.CTkLabel(card, text=title, font=("Segoe UI", 10, "bold"), text_color="#aaaaaa")
            lbl_t.pack(anchor="w", padx=10, pady=(10, 2))
            
            lbl_v = ctk.CTkLabel(card, text=def_val, font=("Segoe UI", 16, "bold"), text_color=color)
            lbl_v.pack(anchor="w", padx=10, pady=(0, 10))
            
            self.perf_widgets[key] = lbl_v

        # --- Sezione 3: Stato del Sistema ---
        health_card = ctk.CTkFrame(content_scroll, fg_color="#2b2b2b", corner_radius=10, border_width=1, border_color="#3a3a3a")
        health_card.pack(fill="x", pady=8)

        lbl_h_head = ctk.CTkLabel(health_card, text="⚙️ System state", font=("Segoe UI", 15, "bold"), text_color="white")
        lbl_h_head.pack(anchor="w", padx=15, pady=(15, 5))

        self.lbl_system_status = ctk.CTkLabel(
            health_card, text="🟢 The system is not congested", 
            font=("Segoe UI", 12), text_color="#2ecc71"
        )
        self.lbl_system_status.pack(anchor="w", padx=15, pady=(0, 15))

        return frame

    def show_view(self, view_to_show):
        self.view_dashboard.pack_forget()
        self.view_cluster.pack_forget()
        self.view_performance.pack_forget()
        view_to_show.pack(fill="both", expand=True)

    def on_pie_hover(self, event):
        hovered = None
        if event.inaxes:
            for name, ax in self.axes_pie.items():
                if event.inaxes == ax:
                    hovered = name
                    break

        if hovered != self.hovered_cluster:
            self.hovered_cluster = hovered
            if self.hovered_cluster:
                self.canvas_pie.get_tk_widget().config(cursor="hand2")
            else:
                self.canvas_pie.get_tk_widget().config(cursor="")
            
            clusters = self.last_data.get(utils.CLUSTERS, {}) if self.last_data else {}
            self.update_pie_charts(clusters)

    def on_pie_click(self, event):
        if not event.inaxes or not self.last_data: return
        
        cluster_name = None
        for name, ax in self.axes_pie.items():
            if event.inaxes == ax:
                cluster_name = name
                break
                
        if cluster_name:
            self.selected_cluster = cluster_name
            self.update_cluster_view(cluster_name)
            self.show_view(self.view_cluster)

    def poll_queue(self):
        data_found = False
        latest_data = None
        
        while not self.stats_queue.empty():
            try:
                latest_data = self.stats_queue.get_nowait()
                data_found = True
            except queue.Empty:
                break
                
        if data_found and latest_data:
            self.last_data = latest_data
            self.process_incoming_data(latest_data)
            
        self.after(2000, self.poll_queue)

    def process_incoming_data(self, data):
        # 1. Update Global Stats
        global_stats = data.get(utils.GLOBAL, {})
        devices = global_stats.get(utils.DEVICES, {})
        
        traffic = global_stats.get(utils.TRAFFIC, {})
        round_traffic = traffic.get(utils.ROUND, {})
        session_traffic = traffic.get(utils.SESSION, {})
        
        self.lbl_global_traffic.configure(text=f"Global Traffic: {round_traffic.get(utils.ROUND_PKTS_PER_SEC, 0):.0f} Pkts/s | {round_traffic.get(utils.ROUND_VOLUME_PER_SEC, 0):.0f} Bytes/s")
        
        # --- AGGIORNAMENTO DATI TRAFFICO NON ASSEGNATO ---
        r_unass_pkts = round_traffic.get(utils.PERC_ROUND_UNASSIGNED_PKTS, 0)
        r_unass_vol  = round_traffic.get(utils.PERC_ROUND_UNASSIGNED_VOLUME, 0)
        
        s_unass_pkts = session_traffic.get(utils.PERC_SESSION_UNASSIGNED_PKTS, 0)
        s_unass_vol  = session_traffic.get(utils.PERC_SESSION_UNASSIGNED_VOLUME, 0)
        
        self.lbl_unassigned.configure(
            text=f"Unassigned Traffic (Immediate/Session): Pkts {r_unass_pkts:.1f}% / {s_unass_pkts:.1f}% | Vol {r_unass_vol:.1f}% / {s_unass_vol:.1f}%"
        )
        # ---------------------------------------------------
        
        self.lbl_global_devices.configure(text=f"AP: {devices.get(utils.AP, 0)} | STA: {devices.get(utils.STA, 0)} | MESH: {devices.get(utils.MESH, 0)} | UNID: {devices.get(utils.UNIDENTIFIED, 0)}")
        self.lbl_global_random.configure(text=f"Randomized MACs: {devices.get(utils.TOTAL_RANDOMIZED, 0)}")
        
        # 2. Update History for Line Chart
        clusters = data.get(utils.CLUSTERS, {})
        self.current_time_step += 2
        self.history['time'].append(self.current_time_step)
        
        for c_name in CLUSTER_COLORS.keys():
            c_obj = clusters.get(c_name)
            if c_obj:
                pkts = getattr(c_obj, 'round_pkts_per_sec', 0) if not isinstance(c_obj, dict) else c_obj.get('round_pkts_per_sec', 0)
                vol = getattr(c_obj, 'round_volume_per_sec', 0) if not isinstance(c_obj, dict) else c_obj.get('round_volume_per_sec', 0)
                self.history[c_name]['pkts'].append(pkts)
                self.history[c_name]['vol'].append(vol)
            else:
                self.history[c_name]['pkts'].append(0)
                self.history[c_name]['vol'].append(0)
                
        self.update_line_chart()
        self.update_pie_charts(clusters)
        
        # 3. Aggiorna viste attive in background se visibili
        if self.view_performance.winfo_ismapped():
            self.update_performance_view()
            
        if self.view_cluster.winfo_ismapped() and self.selected_cluster:
            self.update_cluster_view(self.selected_cluster)

    def update_line_chart(self, *args):
        # Usa .set_data() per migliorare la fluidità senza ridisegnare da zero gli assi
        mode = self.chart_mode.get()
        data_key = 'pkts' if "Packets" in mode else 'vol'
        
        max_val = 0
        x_data = list(self.history['time'])
        
        # Calcola le posizioni X relative: l'ultimo valore letto sarà sempre 0 (a destra)
        if x_data:
            latest_time = x_data[-1]
            x_plot = [t - latest_time for t in x_data]
        else:
            x_plot = []
        
        for c_name, color in CLUSTER_COLORS.items():
            y_data = list(self.history[c_name][data_key])
            self.lines[c_name].set_data(x_plot, y_data)
            
            if len(y_data) > 0:
                current_max = max(y_data)
                if current_max > max_val:
                    max_val = current_max
                    
        y_max = max(10, max_val * 1.15)
        self.ax_line.set_ylim(0, y_max)
        
        # Asse X bloccato da -(history_len-1)*2 a 0 per mantenere lo 0 fisso a destra
        window_size = (self.history_len - 1) * 2
        self.ax_line.set_xlim(-window_size, 0)
            
        self.ax_line.set_ylabel(mode, color="white", fontsize=10)
        self.canvas_line.draw_idle()

    def update_pie_charts(self, clusters):
        for name, ax in self.axes_pie.items():
            ax.clear()
            is_hovered = (name == self.hovered_cluster)
            
            bg = "#383838" if is_hovered else self.bg_color
            ax.set_facecolor(bg)
            
            for spine in ax.spines.values():
                if is_hovered:
                    spine.set_edgecolor(CLUSTER_COLORS.get(name, "#2ecc71"))
                    spine.set_linewidth(2)
                else:
                    spine.set_edgecolor("#444444")
                    spine.set_linewidth(0.8)
            
            c_obj = clusters.get(name)
            tot_devs = getattr(c_obj, 'total_devices', 0) if c_obj and not isinstance(c_obj, dict) else (c_obj.get('total_devices', 0) if isinstance(c_obj, dict) else 0)
            p_sec = getattr(c_obj, 'round_pkts_per_sec', 0) if c_obj and not isinstance(c_obj, dict) else (c_obj.get('round_pkts_per_sec', 0) if isinstance(c_obj, dict) else 0)

            # --- Sfondo colorato del nome del cluster per il titolo ---
            cluster_color = CLUSTER_COLORS.get(name, "#777")
            bbox_props = dict(boxstyle="round,pad=0.3", facecolor=cluster_color, edgecolor="none", alpha=0.9 if is_hovered else 0.7)

            if c_obj and tot_devs > 0:
                devs = getattr(c_obj, 'devices', {}) if not isinstance(c_obj, dict) else c_obj.get('devices', {})
                sizes = [devs.get(utils.AP, 0), devs.get(utils.STA, 0), devs.get(utils.MESH, 0), devs.get(utils.UNIDENTIFIED, 0)]
                
                explode = [0.06]*4 if is_hovered else [0]*4
                ax.pie(sizes, colors=DEVICE_COLORS, startangle=90, radius=1.1, explode=explode)
                
                subtitle = "\n Click to expand" if is_hovered else ""
                ax.set_title(
                    f"{name}\n({p_sec:.0f} pkts/s){subtitle}", 
                    color="black", 
                    fontsize=9, 
                    fontweight="bold", 
                    pad=6,
                    bbox=bbox_props
                )
            else:
                subtitle = "\n Click to expand" if is_hovered else ""
                ax.set_title(
                    f"{name}\n(0 pkts/s){subtitle}", 
                    color="black", 
                    fontsize=9, 
                    fontweight="bold" if is_hovered else "normal", 
                    pad=6,
                    bbox=bbox_props
                )
                ax.pie([1], colors=["#333333"], radius=1.1)

        self.fig_pie.tight_layout(rect=[0, 0, 1, 0.85])
        self.canvas_pie.draw_idle()

    def update_cluster_view(self, cluster_name=None):
        if cluster_name:
            self.selected_cluster = cluster_name
        else:
            cluster_name = self.selected_cluster

        if not cluster_name or not self.last_data:
            return

        color = CLUSTER_COLORS.get(cluster_name, "#2ecc71")
        self.lbl_cluster_title.configure(text=f"Details: {cluster_name}")
        self.cluster_badge.configure(text=f" {cluster_name} ", fg_color=color)

        c_obj = self.last_data.get(utils.CLUSTERS, {}).get(cluster_name)
        if not c_obj:
            return

        is_dict = isinstance(c_obj, dict)
        tot_devs = c_obj.get('total_devices', 0) if is_dict else getattr(c_obj, 'total_devices', 0)
        rand_devs = c_obj.get('randomized_count', 0) if is_dict else getattr(c_obj, 'randomized_count', 0)
        rand_pct = (rand_devs / tot_devs * 100) if tot_devs > 0 else 0

        # Update KPIs
        self.cluster_kpis["total_devs"][0].configure(text=f"{tot_devs}")
        self.cluster_kpis["total_devs"][1].configure(text=f"Randomized: {rand_devs} ({rand_pct:.1f}%)")

        rk = c_obj.get('round_pkts_per_sec', 0) if is_dict else getattr(c_obj, 'round_pkts_per_sec', 0)
        rv = c_obj.get('round_volume_per_sec', 0) if is_dict else getattr(c_obj, 'round_volume_per_sec', 0)
        self.cluster_kpis["round_traffic"][0].configure(text=f"{rk:.0f} Pkts/s")
        self.cluster_kpis["round_traffic"][1].configure(text=f"Bytes: {rv:.0f} Bytes/s")

        sk = c_obj.get('session_pkts_per_sec', 0) if is_dict else getattr(c_obj, 'session_pkts_per_sec', 0)
        sv = c_obj.get('session_volume_per_sec', 0) if is_dict else getattr(c_obj, 'session_volume_per_sec', 0)
        self.cluster_kpis["sess_traffic"][0].configure(text=f"{sk:.0f} Pkts/s")
        self.cluster_kpis["sess_traffic"][1].configure(text=f"Bytes: {sv:.0f} Bytes/s")

        b_ch = c_obj.get('busiest_channel', ("--", 0, 0)) if is_dict else getattr(c_obj, 'busiest_channel', ("--", 0, 0))
        ch_num = b_ch[0] if b_ch else "--"
        ch_pkts = b_ch[1] if len(b_ch) > 1 else 0
        ch_vol = b_ch[2] if len(b_ch) > 2 else 0
        self.cluster_kpis["busy_channel"][0].configure(text=f"Channels {ch_num}")
        self.cluster_kpis["busy_channel"][1].configure(text=f"Pkts: {ch_pkts} | Bytes: {ch_vol}")

        # Update Device Bars
        devs = c_obj.get('devices', {}) if is_dict else getattr(c_obj, 'devices', {})
        for dev_type in DEVICE_NAMES:
            cnt = devs.get(dev_type, 0) if devs else 0
            pct = (cnt / tot_devs) if tot_devs > 0 else 0
            pbar, lbl = self.dev_bars[dev_type]
            pbar.set(pct)
            lbl.configure(text=f"{cnt} ({pct*100:.1f}%)")

        # Update Traffic Bars
        mgmt = c_obj.get('management_pkts_perc', 0) if is_dict else getattr(c_obj, 'management_pkts_perc', 0)
        ctrl = c_obj.get('control_pkts_perc', 0) if is_dict else getattr(c_obj, 'control_pkts_perc', 0)
        data = c_obj.get('data_pkts_perc', 0) if is_dict else getattr(c_obj, 'data_pkts_perc', 0)

        self.traffic_bars["MGMT"][0].set(mgmt / 100.0)
        self.traffic_bars["MGMT"][1].configure(text=f"{mgmt:.1f}%")

        self.traffic_bars["CTRL"][0].set(ctrl / 100.0)
        self.traffic_bars["CTRL"][1].configure(text=f"{ctrl:.1f}%")

        self.traffic_bars["DATA"][0].set(data / 100.0)
        self.traffic_bars["DATA"][1].configure(text=f"{data:.1f}%")

    def update_performance_view(self):
        if not self.last_data:
            return
        
        perf = self.last_data.get(utils.GLOBAL, {}).get(utils.PERFORMANCE, {})
        rnd = perf.get(utils.ROUND, {})
        sess = perf.get(utils.SESSION, {})
        
        # Instantaneous Metrics
        rd_q = rnd.get(utils.AVG_ROUND_QUEUE_SIZE, 0)
        rd_p = rnd.get(utils.ROUND_PROCESSED_PKTS_PER_SEC, 0)
        rd_v = rnd.get(utils.ROUND_PROCESSED_VOLUME_PER_SEC, 0)

        self.perf_widgets["rnd_queue"].configure(text=f"{rd_q:.1f} pkts")
        self.perf_widgets["rnd_pkts_sec"].configure(text=f"{rd_p:.0f} pkts/s")
        self.perf_widgets["rnd_vol_sec"].configure(text=f"{rd_v:.0f} Bytes/s")

        # Session Metrics
        ss_q = sess.get(utils.SESSION_AVG_QUEUE_SIZE, 0)
        ss_p = sess.get(utils.SESSION_PROCESSED_PKTS_PER_SEC, 0)
        ss_v = sess.get(utils.SESSION_PROCESSED_VOLUME_PER_SEC, 0)

        self.perf_widgets["sess_queue"].configure(text=f"{ss_q:.1f} pkts")
        self.perf_widgets["sess_pkts_sec"].configure(text=f"{ss_p:.0f} pkts/s")
        self.perf_widgets["sess_vol_sec"].configure(text=f"{ss_v:.0f} Bytes/s")

        # Health status check
        if rd_q > 50:
            self.lbl_system_status.configure(
                text=f"⚠️ The system is overloaded",
                text_color="#e74c3c"
            )
        else:
            self.lbl_system_status.configure(
                text="🟢 The system is not congested",
                text_color="#2ecc71"
            )