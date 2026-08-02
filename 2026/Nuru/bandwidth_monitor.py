#!/usr/bin/env python3
"""
Bandwidth Monitor per-host con RRDtool

Cattura passiva dei pacchetti con Scapy e
salvataggio delle serie temporali per-host in database RRD.

Funzionalita':
    - Cattura pacchetti in modalita' promiscua
    - Aggregazione traffico solo per host esterni (locale <-> esterno)
    - Classificazione protocolli (TCP, UDP, ICMP)
    - Serie temporali per-host con RRDtool (Round-Robin Database)
    - Generazione grafici PNG per ogni host monitorato
    - Filtri BPF per cattura selettiva

Uso:
    sudo python3 bandwidth_monitor_v3.py -i en0
    sudo python3 bandwidth_monitor_v3.py -i en0 -f "tcp port 443"
    sudo python3 bandwidth_monitor_v3.py -i en0 --graph       # genera grafici
    sudo python3 bandwidth_monitor_v3.py --list-interfaces

Requisiti:
    pip install scapy psutil
    brew install rrdtool
"""

# ============================================================================
# Import
# ============================================================================

import argparse
import heapq
import operator
import os
import socket
import sys
import time
import threading
import subprocess
from collections import OrderedDict

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
import psutil


# ============================================================================
# Costanti di configurazione
# ============================================================================

# Intervallo di campionamento (secondi). RRDtool riceve un update per
# host ogni STATS_INTERVAL secondi. Corrisponde al --step di rrd_create.
STATS_INTERVAL = 5.0

# Soglia di alert: se un host supera questo valore, viene segnalato
BANDWIDTH_ALERT_MBPS = 10

# Dopo quanti secondi un host inattivo viene rimosso dal dizionario
# per evitare crescita illimitata della struttura dati
HOST_INACTIVE_TIMEOUT = 300

# Numero massimo di host tracciati contemporaneamente.
# Se si supera questo limite, gli host meno attivi vengono rimossi (LRU).
MAX_HOSTS = 500

# Cartella dove salvare i file .rrd e i grafici generati
RRD_DIR = "rrd_data"

# Mapping protocolli -> indici array. Usa un array a 4 elementi
PROTO_TCP = 0
PROTO_UDP = 1
PROTO_ICMP = 2
PROTO_OTHER = 3
PROTO_NAMES = ("TCP", "UDP", "ICMP", "OTHER")

# Configurazione RRD
RRD_RRAS = [
    "RRA:AVERAGE:0.5:1:720",       # 1 ora a risoluzione 5s (720 campioni)
    "RRA:AVERAGE:0.5:12:1440",     # 24 ore a risoluzione 1min (1440 campioni)
    "RRA:AVERAGE:0.5:720:8760",    # 1 anno a risoluzione 1ora (8760 campioni)
    "RRA:MAX:0.5:1:720",           # 1 ora di valori massimi (per i picchi)
]


# ============================================================================
# RRDtool
# ============================================================================

def rrd_create(filepath):
    """Crea un nuovo database RRD per un host.

    Ogni file .rrd contiene due Data Source (DS):
    - bytes_in:  bytes/sec in entrata (download) per questo host
    - bytes_out: bytes/sec in uscita (upload) per questo host

    Il tipo GAUGE indica che il valore e' gia' un tasso (bytes/sec)
    """
    if os.path.exists(filepath):
        return
    cmd = [
        "rrdtool", "create", filepath,
        "--step", str(int(STATS_INTERVAL)),
        "--no-overwrite",
        # DS:nome:tipo:heartbeat:min:max
        # Heartbeat = 10s: se non riceviamo dati per 10s, il valore e' UNKNOWN
        "DS:bytes_in:GAUGE:10:0:U",
        "DS:bytes_out:GAUGE:10:0:U",
    ] + RRD_RRAS
    subprocess.run(cmd, check=True, capture_output=True)


def rrd_update(filepath, bytes_in, bytes_out):
    """Aggiorna il database RRD con i valori correnti.

    N = timestamp corrente (RRDtool usa il clock di sistema).
    Il formato e': N:valore1:valore2
    """
    cmd = [
        "rrdtool", "update", filepath,
        f"N:{bytes_in}:{bytes_out}",
    ]
    subprocess.run(cmd, capture_output=True)


def rrd_graph(filepath, output_png, title, period="1h"):
    """Genera un grafico PNG dal database RRD.

    Args:
        filepath:   percorso del file .rrd
        output_png: percorso del file PNG da generare
        title:      titolo del grafico
        period:     periodo da visualizzare (es. "1h", "6h", "24h")
    """
    cmd = [
        "rrdtool", "graph", output_png,
        "--start", f"-{period}",
        "--title", title,
        "--vertical-label", "bytes/sec",
        "--width", "800",
        "--height", "300",
        "--lower-limit", "0",
        "--rigid",
        # Colori tema scuro
        "--color", "BACK#0f172a",
        "--color", "CANVAS#1e293b",
        "--color", "FONT#e2e8f0",
        "--color", "GRID#334155",
        "--color", "MGRID#475569",
        "--color", "AXIS#94a3b8",
        "--color", "ARROW#94a3b8",
        # Definizioni dati: leggiamo bytes_in e bytes_out dal file .rrd
        f"DEF:bin={filepath}:bytes_in:AVERAGE",
        f"DEF:bout={filepath}:bytes_out:AVERAGE",
        # Aree colorate per il grafico
        "AREA:bin#38bdf880:Download (bytes/sec)",
        "LINE1:bin#38bdf8",
        "AREA:bout#a78bfa80:Upload (bytes/sec)",
        "LINE1:bout#a78bfa",
        # Statistiche in legenda (media, max, ultimo valore)
        r"GPRINT:bin:AVERAGE:  Download avg\: %.0lf B/s",
        r"GPRINT:bin:MAX:max\: %.0lf B/s\n",
        r"GPRINT:bout:AVERAGE:  Upload avg\: %.0lf B/s",
        r"GPRINT:bout:MAX:max\: %.0lf B/s\n",
    ]
    subprocess.run(cmd, check=True, capture_output=True)


def rrd_filename(ip):
    """Genera il nome del file .rrd per un IP.
    Sostituisce i punti con underscore per compatibilita' filesystem."""
    safe_ip = ip.replace(".", "_")
    return os.path.join(RRD_DIR, f"host_{safe_ip}.rrd")


# ============================================================================
# Statistiche per-host — struttura dati per aggregazione traffico
# ============================================================================

class HostStats:
    """Contatori per un singolo host IP esterno.

    Usa __slots__ per ridurre il consumo di memoria ed evitare la
    creazione di __dict__ per ogni istanza.
    """
    __slots__ = (
        "ip", "total_bytes", "total_packets",
        "bytes_in", "bytes_out",
        "proto_bytes",
        "first_seen", "last_seen",
        "current_bps",
        "_prev_bytes", "_prev_in", "_prev_out",
        "_needs_rrd_create",
    )

    def __init__(self, ip):
        self.ip = ip
        self.total_bytes = 0
        self.total_packets = 0
        self.bytes_in = 0            # Download: bytes ricevuti DA questo host
        self.bytes_out = 0           # Upload: bytes inviati A questo host
        self.proto_bytes = [0, 0, 0, 0]  # [TCP, UDP, ICMP, OTHER]
        self.first_seen = time.time()
        self.last_seen = time.time()
        # Bandwidth corrente calcolata a ogni STATS_INTERVAL
        self.current_bps = 0.0
        self._prev_bytes = 0         # Per calcolo delta bandwidth
        self._prev_in = 0            # Per calcolo delta download
        self._prev_out = 0           # Per calcolo delta upload


# ============================================================================
# Network Monitor — classe principale per la cattura
# ============================================================================

class NetworkMonitor:
    """Cattura e analizza il traffico di rete in tempo reale.

    Architettura a 2 thread:
    - Thread 1 (sniffer): chiama scapy.sniff() che cattura pacchetti
      in loop infinito
    - Thread 2 (stats): ogni STATS_INTERVAL secondi ricalcola la
      bandwidth per-host e aggiorna i database RRD

    La sincronizzazione tra thread avviene tramite self.lock (threading.Lock)

    NOTA: traccia solo traffico locale <-> esterno. I pacchetti tra due
    host esterni o tra due host locali vengono ignorati.
    """

    def __init__(self, interface, bpf_filter=None):
        self.interface = interface
        self.bpf_filter = bpf_filter

        # Strutture dati protette da self.lock
        self.hosts = OrderedDict()   # {ip: HostStats} — OrderedDict per LRU
        self.total_bytes = 0
        self.total_packets = 0
        self.start_time = time.time()
        self.lock = threading.Lock()

        # Thread di aggiornamento statistiche
        self._running = False
        self._stats_thread = None

        # IP locali per distinguere upload/download
        self.local_ips = self._detect_local_ips()

        # Crea la cartella per i file RRD
        os.makedirs(RRD_DIR, exist_ok=True)

    def _detect_local_ips(self):
        """Rileva gli IP locali della macchina usando psutil.
        Serve per sapere quali host sono 'noi' nella rete."""
        local = set()
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    local.add(addr.address)
        return local

    def _get_host(self, ip):
        """Ottiene le statistiche per un host, o le crea se e' la prima volta.

        Se il numero di host supera MAX_HOSTS, rimuove l'host meno
        recentemente attivo (LRU) per evitare crescita illimitata.
        """
        host = self.hosts.get(ip)
        if host is None:
            # LRU se troppi host: rimuove il meno recente
            if len(self.hosts) >= MAX_HOSTS:
                self.hosts.popitem(last=False)
            host = HostStats(ip)
            self.hosts[ip] = host
            host._needs_rrd_create = True
        else:
            # Sposta in fondo (most recently used) per LRU
            self.hosts.move_to_end(ip)
            host._needs_rrd_create = False
        return host

    def _classify_proto(self, packet):
        """Classifica il protocollo di trasporto del pacchetto.
        Restituisce un indice intero (PROTO_TCP, PROTO_UDP, ecc.) per
        accesso diretto all'array proto_bytes senza hashing.
        """
        if TCP in packet:
            return PROTO_TCP
        elif UDP in packet:
            return PROTO_UDP
        elif ICMP in packet:
            return PROTO_ICMP
        return PROTO_OTHER

    def _process_packet(self, packet):
        """Callback chiamata da Scapy per ogni pacchetto catturato.


        Traccia SOLO traffico locale <-> esterno:
        - Se src e' locale e dst e' esterno -> upload verso dst
        - Se src e' esterno e dst e' locale -> download da src
        - Altrimenti il pacchetto viene ignorato

        """
        pkt_len = len(packet)
        now = time.time()

        # Gestione pacchetti ARP (non contengono header IP)
        if ARP in packet and IP not in packet:
            with self.lock:
                self.total_bytes += pkt_len
                self.total_packets += 1
            return

        # Filtra pacchetti senza header IP
        if IP not in packet:
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = self._classify_proto(packet)

        # Determina direzione: traccia solo locale <-> esterno
        src_local = src_ip in self.local_ips
        dst_local = dst_ip in self.local_ips

        need_rrd = False
        new_ip = None

        with self.lock:
            self.total_bytes += pkt_len
            self.total_packets += 1

            if src_local and not dst_local:
                # UPLOAD: noi -> host esterno
                host = self._get_host(dst_ip)
                host.total_bytes += pkt_len
                host.total_packets += 1
                host.bytes_out += pkt_len
                host.proto_bytes[proto] += pkt_len
                host.last_seen = now
                need_rrd = host._needs_rrd_create
                new_ip = dst_ip

            elif not src_local and dst_local:
                # DOWNLOAD: host esterno -> noi
                host = self._get_host(src_ip)
                host.total_bytes += pkt_len
                host.total_packets += 1
                host.bytes_in += pkt_len
                host.proto_bytes[proto] += pkt_len
                host.last_seen = now
                need_rrd = host._needs_rrd_create
                new_ip = src_ip

            # Pacchetti locale<->locale o esterno<->esterno: ignorati

        # Creazione RRD fuori dal lock (I/O lento)
        if need_rrd and new_ip:
            rrd_create(rrd_filename(new_ip))

    def _update_stats_loop(self):
        """Thread che ogni STATS_INTERVAL secondi:
        1. Ricalcola la bandwidth per ogni host (delta bytes / delta tempo)
        2. Aggiorna i database RRD con i nuovi valori (in bytes/sec)
        3. Rimuove host inattivi per evitare crescita illimitata del dict
        4. Stampa le statistiche a terminale
        """
        while self._running:
            time.sleep(STATS_INTERVAL)

            with self.lock:
                now = time.time()
                inactive_ips = []

                for ip, host in list(self.hosts.items()):
                    # Calcola bandwidth: (bytes_now - bytes_prev) / intervallo
                    delta = host.total_bytes - host._prev_bytes
                    host.current_bps = delta / STATS_INTERVAL
                    host._prev_bytes = host.total_bytes

                    # Calcola bytes/sec per RRD
                    bps_in = (host.bytes_in - host._prev_in) / STATS_INTERVAL
                    bps_out = (host.bytes_out - host._prev_out) / STATS_INTERVAL
                    host._prev_in = host.bytes_in
                    host._prev_out = host.bytes_out
                    rrd_update(rrd_filename(ip), bps_in, bps_out)

                    # Segna host inattivi da troppo tempo
                    if now - host.last_seen > HOST_INACTIVE_TIMEOUT:
                        inactive_ips.append(ip)

                # Rimuovi host inattivi (evita crescita illimitata)
                for ip in inactive_ips:
                    del self.hosts[ip]

            # Stampa statistiche a terminale
            self._print_stats()

    def _print_stats(self):
        """Stampa le statistiche correnti a terminale."""
        with self.lock:
            elapsed = time.time() - self.start_time
            total_mbps = 0.0

            total_hosts = len(self.hosts)

            # Top 15 host per bandwidth
            sorted_hosts = heapq.nlargest(
                15, self.hosts.values(),
                key=operator.attrgetter("current_bps"),
            )

        # Stampa header
        print("\033[H\033[J", end="")  # Cursore a home + pulisce fino a fine schermo
        print("=" * 60)
        print(f"  Bandwidth Monitor - Uptime: {int(elapsed)}s")
        print(f"  Pkt: {self.total_packets:,} | "
              f"Traffico: {self._format_bytes(self.total_bytes)}")
        print("=" * 60)
        print(f"  {'Host esterno':<18s} {'Mb/s':>10s} {'Totale':>9s} {'Proto':>6s}")
        print("-" * 60)

        # Stampa top 15 host
        for host in sorted_hosts:
            mbps = host.current_bps * 8 / 1_000_000
            total_mbps += mbps
            # Protocollo dominante
            main_proto = PROTO_NAMES[max(range(4), key=lambda i: host.proto_bytes[i])]
            alert = " !" if mbps > BANDWIDTH_ALERT_MBPS else ""
            print(f"  {host.ip:<18s} {mbps:>8.4f}  "
                  f"{self._format_bytes(host.total_bytes):>9s} "
                  f"{main_proto:>5s}{alert}")

        print("-" * 60)
        print(f"  Host: {total_hosts} | "
              f"Totale: {total_mbps:.4f} Mbit/s")
        print(f"  RRD: {RRD_DIR}/")
        print("=" * 60)

    @staticmethod
    def _format_bytes(b):
        """Converte bytes in stringa leggibile."""
        if b < 1024:
            return f"{b} B"
        elif b < 1024 * 1024:
            return f"{b / 1024:.1f} KB"
        elif b < 1024 * 1024 * 1024:
            return f"{b / (1024 * 1024):.2f} MB"
        return f"{b / (1024 * 1024 * 1024):.2f} GB"

    def start(self):
        """Avvia cattura pacchetti e thread statistiche."""
        self._running = True
        self._stats_thread = threading.Thread(
            target=self._update_stats_loop,
            daemon=True,
            name="stats-thread",
        )
        self._stats_thread.start()

        print(f"[*] IP locali rilevati: {self.local_ips}")
        print(f"[*] Avvio cattura su interfaccia: {self.interface}")
        if self.bpf_filter:
            print(f"[*] Filtro BPF: {self.bpf_filter}")
        print(f"[*] Database RRD: {os.path.abspath(RRD_DIR)}/")
        print(f"[*] Premi Ctrl+C per terminare\n")

        # Avvia lo sniffer Scapy.
        sniff(
            iface=self.interface,
            prn=self._process_packet,
            store=0,
            filter=self.bpf_filter,
            promisc=True,
        )

    def stop(self):
        """Ferma la cattura e stampa il riepilogo finale."""
        self._running = False
        print(f"\n[*] Cattura terminata.")
        print(f"[*] Pacchetti totali: {self.total_packets:,}")
        print(f"[*] Host monitorati: {len(self.hosts)}")
        print(f"[*] File RRD salvati in: {os.path.abspath(RRD_DIR)}/")

    def generate_graphs(self, period="1h"):
        """Genera grafici PNG per tutti gli host monitorati."""
        graphs_dir = os.path.join(RRD_DIR, "graphs")
        os.makedirs(graphs_dir, exist_ok=True)

        rrd_files = [f for f in os.listdir(RRD_DIR) if f.endswith(".rrd")]
        if not rrd_files:
            print("[!] Nessun file RRD trovato. Avvia prima una cattura.")
            return

        print(f"[*] Generazione grafici per {len(rrd_files)} host (periodo: {period})...")

        for rrd_file in rrd_files:
            filepath = os.path.join(RRD_DIR, rrd_file)
            # Estrai l'IP dal nome file (host_192_168_1_86.rrd -> 192.168.1.86)
            ip = rrd_file.replace("host_", "").replace(".rrd", "").replace("_", ".")
            png_path = os.path.join(graphs_dir, rrd_file.replace(".rrd", f"_{period}.png"))

            try:
                rrd_graph(filepath, png_path, f"Host {ip} (ultimo {period})", period)
                print(f"  [OK] {png_path}")
            except subprocess.CalledProcessError as e:
                print(f"  [ERR] {ip}: {e.stderr.decode().strip()}")

        print(f"\n[*] Grafici salvati in: {os.path.abspath(graphs_dir)}/")


# ============================================================================
# Interfacce di rete disponibili
# ============================================================================

def list_interfaces():
    """Elenca le interfacce di rete disponibili sul sistema.
    """
    print("\nInterfacce di rete disponibili:")
    print("-" * 50)
    all_stats = psutil.net_if_stats()  # Chiamata UNA volta (non nel loop)
    for name, addrs in psutil.net_if_addrs().items():
        ips = [a.address for a in addrs if a.family.name == "AF_INET"]
        status = all_stats.get(name)
        up = "UP" if status and status.isup else "DOWN"
        speed = f"{status.speed}Mbps" if status and status.speed > 0 else ""
        ip_str = ", ".join(ips) if ips else "no IPv4"
        print(f"  {name:<20s} [{up}] {speed:<12s} {ip_str}")
    print()


# ============================================================================
# Main
# ============================================================================

def main():
    global BANDWIDTH_ALERT_MBPS

    parser = argparse.ArgumentParser(
        description="Bandwidth Monitor per-host con RRDtool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Esempi:
  sudo python3 %(prog)s -i en0                  # cattura su en0
  sudo python3 %(prog)s -i en0 -f "tcp port 443"  # solo HTTPS
  python3 %(prog)s --graph                        # genera grafici PNG
  python3 %(prog)s --graph --period 6h            # grafici ultime 6 ore
  python3 %(prog)s --list-interfaces              # mostra interfacce
""",
    )
    parser.add_argument("-i", "--interface", help="Interfaccia di rete da monitorare")
    parser.add_argument("-f", "--filter", default=None, help="Filtro BPF (es. 'tcp port 443')")
    parser.add_argument("-t", "--threshold", type=float, default=BANDWIDTH_ALERT_MBPS,
                        help=f"Soglia alert in Mbit/s (default: {BANDWIDTH_ALERT_MBPS})")
    parser.add_argument("--list-interfaces", action="store_true", help="Mostra le interfacce disponibili")
    parser.add_argument("--graph", action="store_true", help="Genera grafici PNG dai file RRD esistenti")
    parser.add_argument("--period", default="1h", help="Periodo per i grafici (default: 1h)")

    args = parser.parse_args()

    # Verifica che rrdtool sia installato
    try:
        subprocess.run(["rrdtool", "--version"], capture_output=True, check=True)
    except FileNotFoundError:
        print("[ERRORE] rrdtool non trovato. Installa con: brew install rrdtool")
        sys.exit(1)

    # Modalita' generazione grafici (non serve sudo)
    if args.graph:
        monitor = NetworkMonitor("dummy")
        monitor.generate_graphs(args.period)
        return

    # Modalita' lista interfacce
    if args.list_interfaces:
        list_interfaces()
        return

    if not args.interface:
        print("[ERRORE] Specificare l'interfaccia con -i (es. -i en0)")
        list_interfaces()
        sys.exit(1)

    BANDWIDTH_ALERT_MBPS = args.threshold

    print("=" * 60)
    print("  Bandwidth Monitor per-host con RRDtool")
    print("=" * 60)
    list_interfaces()

    monitor = NetworkMonitor(args.interface, args.filter)

    try:
        monitor.start()
    except KeyboardInterrupt:
        monitor.stop()
        # Genera i grafici alla fine della cattura
        print()
        monitor.generate_graphs()


if __name__ == "__main__":
    main()
