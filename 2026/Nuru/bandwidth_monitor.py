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
    python3 bandwidth_monitor.py -i en0
    python3 bandwidth_monitor.py -i en0 --web --period 5min
    python3 bandwidth_monitor.py --graph --period 5min
    python3 bandwidth_monitor.py --list-interfaces

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
import re
import socket
import sys
import time
import threading
import subprocess

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP
from scapy.layers.inet6 import _ICMPv6
import psutil

from web_dashboard import start_dashboard


# ============================================================================
# Costanti di configurazione
# ============================================================================

# Intervallo di campionamento (secondi). RRDtool riceve un update per
# host ogni STATS_INTERVAL secondi. Corrisponde al --step di rrd_create.
STATS_INTERVAL = 5.0

# Dopo quanti secondi un host inattivo viene rimosso dal dizionario
# per evitare crescita illimitata della struttura dati
HOST_INACTIVE_TIMEOUT = 300

# Database RRD con contatori DERIVE, IPv4/IPv6 e statistiche per protocollo
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

def restore_user_ownership(path):
    """Assegna all'utente che ha invocato sudo i file creati dal programma.
    """
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")
    if sudo_uid is None or sudo_gid is None:
        return

    try:
        os.chown(path, int(sudo_uid), int(sudo_gid))
    except (OSError, ValueError) as exc:
        print(f"[ATTENZIONE] Impossibile cambiare il proprietario di {path}: {exc}")

def rrd_create(filepath):
    """Crea un nuovo database RRD per un host.

    Salva contatori cumulativi. DERIVE.
    """
    if os.path.exists(filepath):
        # Corregge anche database creati da una precedente esecuzione con sudo.
        restore_user_ownership(filepath)
        return
    cmd = [
        "rrdtool", "create", filepath,
        "--step", str(int(STATS_INTERVAL)),
        "--start", str(int(time.time() - STATS_INTERVAL)),
        "--no-overwrite",
        "DS:bytes_in:DERIVE:15:0:U",
        "DS:bytes_out:DERIVE:15:0:U",
        "DS:proto_tcp:DERIVE:15:0:U",
        "DS:proto_udp:DERIVE:15:0:U",
        "DS:proto_icmp:DERIVE:15:0:U",
        "DS:proto_other:DERIVE:15:0:U",
    ] + RRD_RRAS
    subprocess.run(cmd, check=True, capture_output=True)
    # Il valore iniziale permette al primo aggiornamento reale di produrre
    # subito un punto consolidato, anche nelle catture di breve durata.
    rrd_update(filepath, 0, 0, (0, 0, 0, 0))
    restore_user_ownership(filepath)


def rrd_update(filepath, bytes_in, bytes_out, proto_bytes):
    """Aggiorna il database RRD con i contatori cumulativi correnti.

    N = timestamp corrente (RRDtool usa il clock di sistema).
    Il formato e': N:valore1:valore2
    """
    cmd = [
        "rrdtool", "update", filepath,
        "N:" + ":".join(str(value) for value in (
            bytes_in, bytes_out, *proto_bytes,
        )),
    ]
    subprocess.run(cmd, check=True, capture_output=True)


def valid_period(period):
    """Valida un periodo evitando le abbreviazioni ambigue di RRDtool."""
    period = period.strip().lower()
    match = re.fullmatch(r"[1-9][0-9]*(s|min|h|d|w)", period)
    if not match:
        raise argparse.ArgumentTypeError(
            "periodo non valido: usa s=secondi, min=minuti, h=ore, "
            "d=giorni oppure w=settimane (esempi: 30s, 5min, 6h, 7d). "
            "Non usare 'm', perche' RRDtool lo interpreta in modo ambiguo."
        )
    return period


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
        "--start", f"end-{period}",
        "--title", title,
        "--vertical-label", "bytes/sec",
        "--width", "800",
        "--height", "300",
        "--alt-autoscale",
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
        # Download sotto lo zero e upload sopra lo zero.
        "CDEF:bin_neg=bin,-1,*",
        "AREA:bin_neg#2563eb80:Download (bytes/sec)",
        "LINE1:bin_neg#2563eb",
        "AREA:bout#f9731680:Upload (bytes/sec)",
        "LINE1:bout#f97316",
        # Statistiche in legenda (media, max, ultimo valore)
        r"GPRINT:bin:AVERAGE:  Download avg\: %.0lf B/s",
        r"GPRINT:bin:MAX:max\: %.0lf B/s\n",
        r"GPRINT:bout:AVERAGE:  Upload avg\: %.0lf B/s",
        r"GPRINT:bout:MAX:max\: %.0lf B/s\n",
    ]
    subprocess.run(cmd, check=True, capture_output=True)
    restore_user_ownership(output_png)


def rrd_protocol_graph(filepath, output_png, title, period="1h"):
    """Genera un grafico storico del throughput per protocollo."""
    cmd = [
        "rrdtool", "graph", output_png,
        "--start", f"end-{period}",
        "--title", title,
        "--vertical-label", "bytes/sec",
        "--width", "800", "--height", "300",
        "--lower-limit", "0", "--alt-autoscale-max",
        "--color", "BACK#0f172a", "--color", "CANVAS#1e293b",
        "--color", "FONT#e2e8f0", "--color", "GRID#334155",
        "--color", "MGRID#475569", "--color", "AXIS#94a3b8",
        "--color", "ARROW#94a3b8",
        f"DEF:tcp={filepath}:proto_tcp:AVERAGE",
        f"DEF:udp={filepath}:proto_udp:AVERAGE",
        f"DEF:icmp={filepath}:proto_icmp:AVERAGE",
        f"DEF:other={filepath}:proto_other:AVERAGE",
        "LINE2:tcp#22c55e:TCP",
        "LINE2:udp#3b82f6:UDP",
        "LINE2:icmp#f59e0b:ICMP/ICMPv6",
        "LINE2:other#ef4444:Other",
        r"GPRINT:tcp:AVERAGE:TCP avg\: %.0lf B/s",
        r"GPRINT:udp:AVERAGE:UDP avg\: %.0lf B/s\n",
        r"GPRINT:icmp:AVERAGE:ICMP avg\: %.0lf B/s",
        r"GPRINT:other:AVERAGE:Other avg\: %.0lf B/s\n",
    ]
    subprocess.run(cmd, check=True, capture_output=True)
    restore_user_ownership(output_png)


def rrd_filename(ip):
    """Genera un nome filesystem-safe per host locale, IPv4 e IPv6."""
    if ip == "local":
        return os.path.join(RRD_DIR, "local_host.rrd")
    safe_ip = ip.replace(".", "_").replace(":", "-")
    return os.path.join(RRD_DIR, f"host_{safe_ip}.rrd")


def rrd_label(rrd_file):
    """Ricostruisce un'etichetta leggibile dal nome di un database RRD."""
    stem = os.path.basename(rrd_file).removesuffix(".rrd")
    if stem == "local_host":
        return "Host locale"
    encoded_ip = stem.removeprefix("host_")
    return (encoded_ip.replace("-", ":") if "-" in encoded_ip
            else encoded_ip.replace("_", "."))


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
        self._needs_rrd_create = False


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

    NOTA: traccia solo traffico locale <-> esterno. I pacchetti tra due
    host esterni o tra due host locali vengono ignorati.
    """

    def __init__(self, interface, bpf_filter=None):
        self.interface = interface
        self.bpf_filter = bpf_filter

        # Strutture dati protette da self.lock
        self.hosts = {}              # {ip: HostStats}
        self.total_bytes = 0
        self.total_packets = 0
        self.start_time = time.time()
        self._last_stats_update = self.start_time
        self.lock = threading.Lock()

        # Thread di aggiornamento statistiche
        self._running = False
        self._stats_thread = None

        # IP locali per distinguere upload/download
        self.local_ips = self._detect_local_ips()
        self.local_stats = HostStats("local")

        # Crea la cartella per i file RRD
        os.makedirs(RRD_DIR, exist_ok=True)
        restore_user_ownership(RRD_DIR)
        rrd_create(rrd_filename("local"))

    def _detect_local_ips(self):
        """Rileva gli indirizzi IPv4 e IPv6 locali usando psutil.
        """
        local = set()
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family in (socket.AF_INET, socket.AF_INET6):
                    local.add(addr.address.split("%", 1)[0])
        return local

    def _get_host(self, ip):
        """Ottiene le statistiche per un host, o le crea se e' la prima volta.

        Gli host vengono
        rimossi solo dal ciclo periodico dopo HOST_INACTIVE_TIMEOUT secondi
        di inattivita
        """
        host = self.hosts.get(ip)
        if host is None:
            host = HostStats(ip)
            self.hosts[ip] = host
            host._needs_rrd_create = True
        else:
            host._needs_rrd_create = False
        return host

    def _classify_proto(self, packet):
        """Classifica il protocollo di trasporto del pacchetto.
        Restituisce un indice intero (PROTO_TCP, PROTO_UDP, ecc.) per
        accesso diretto all'array proto_bytes
        """
        if TCP in packet:
            return PROTO_TCP
        elif UDP in packet:
            return PROTO_UDP
        elif ICMP in packet:
            return PROTO_ICMP
        elif any(issubclass(layer, _ICMPv6) for layer in packet.layers()):
            return PROTO_ICMP
        return PROTO_OTHER

    def _process_packet(self, packet):
        """chiamata da Scapy per ogni pacchetto catturato.

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

        if IP in packet:
            network_layer = packet[IP]
        elif IPv6 in packet:
            network_layer = packet[IPv6]
        else:
            return

        src_ip = network_layer.src
        dst_ip = network_layer.dst
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
                self.local_stats.total_bytes += pkt_len
                self.local_stats.total_packets += 1
                self.local_stats.bytes_out += pkt_len
                self.local_stats.proto_bytes[proto] += pkt_len
                self.local_stats.last_seen = now
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
                self.local_stats.total_bytes += pkt_len
                self.local_stats.total_packets += 1
                self.local_stats.bytes_in += pkt_len
                self.local_stats.proto_bytes[proto] += pkt_len
                self.local_stats.last_seen = now
                need_rrd = host._needs_rrd_create
                new_ip = src_ip

            # Pacchetti locale<->locale o esterno<->esterno: ignorati   i

        # Creazione RRD
        if need_rrd and new_ip:
            rrd_create(rrd_filename(new_ip))

    def _update_stats_loop(self):
        """Thread che ogni STATS_INTERVAL secondi:
        1. Invia a RRDtool i contatori cumulativi per ogni host
        2. Aggiorna il database complessivo della macchina locale
        3. Rimuove host inattivi per evitare crescita illimitata del dict
        4. Stampa le statistiche a terminale
        """
        while self._running:
            time.sleep(STATS_INTERVAL)

            if not self._running:
                break

            self._update_stats()

    def _update_stats(self):
        """Salva i contatori; RRDtool calcola il throughput con DERIVE."""
        with self.lock:
            now = time.time()
            inactive_ips = []

            for ip, host in list(self.hosts.items()):
                try:
                    rrd_update(
                        rrd_filename(ip), host.bytes_in, host.bytes_out,
                        host.proto_bytes,
                    )
                except subprocess.CalledProcessError as exc:
                    error = exc.stderr.decode().strip() if exc.stderr else str(exc)
                    print(f"[ERRORE RRD] Aggiornamento {ip} fallito: {error}")

                if now - host.last_seen > HOST_INACTIVE_TIMEOUT:
                    inactive_ips.append(ip)

            for ip in inactive_ips:
                del self.hosts[ip]

            try:
                rrd_update(
                    rrd_filename("local"),
                    self.local_stats.bytes_in,
                    self.local_stats.bytes_out,
                    self.local_stats.proto_bytes,
                )
            except subprocess.CalledProcessError as exc:
                error = exc.stderr.decode().strip() if exc.stderr else str(exc)
                print(f"[ERRORE RRD] Aggiornamento host locale fallito: {error}")

            self._last_stats_update = now

        self._print_stats()

    def _print_stats(self):
        """Stampa le statistiche correnti a terminale."""
        with self.lock:
            elapsed = time.time() - self.start_time
            total_hosts = len(self.hosts)

            # Il throughput e' calcolato da RRDtool
            sorted_hosts = heapq.nlargest(
                15, self.hosts.values(),
                key=operator.attrgetter("total_bytes"),
            )
            local_packets = self.local_stats.total_packets
            local_in = self.local_stats.bytes_in
            local_out = self.local_stats.bytes_out

        # Stampa header
        print("\033[H\033[J", end="")  # Cursore a home + pulisce fino a fine schermo
        print("=" * 60)
        print(f"  Bandwidth Monitor - Uptime: {int(elapsed)}s")
        print(f"  Pkt: {self.total_packets:,} | "
              f"Traffico: {self._format_bytes(self.total_bytes)}")
        print(f"  Host locale: {local_packets:,} pkt | "
              f"Download {self._format_bytes(local_in)} | "
              f"Upload {self._format_bytes(local_out)}")
        print("=" * 60)
        print(f"  {'Host esterno':<24s} {'Pacchetti':>9s} {'Totale':>9s} {'Proto':>6s}")
        print("-" * 60)

        # Stampa top 15 host
        for host in sorted_hosts:
            main_proto = PROTO_NAMES[max(range(4), key=lambda i: host.proto_bytes[i])]
            display_ip = host.ip if len(host.ip) <= 24 else host.ip[:21] + "..."
            print(f"  {display_ip:<24s} {host.total_packets:>9,d} "
                  f"{self._format_bytes(host.total_bytes):>9s} "
                  f"{main_proto:>5s}")

        print("-" * 60)
        print(f"  Host remoti attivi: {total_hosts}")
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
        # Salva anche i pacchetti arrivati dopo l'ultimo aggiornamento
        # periodico.
        if self.local_stats.total_packets and time.time() - self._last_stats_update >= 1:
            self._update_stats()
        print(f"\n[*] Cattura terminata.")
        print(f"[*] Pacchetti totali: {self.total_packets:,}")
        print(f"[*] Host remoti monitorati: {len(self.hosts)}")
        print(f"[*] Traffico host locale: {self._format_bytes(self.local_stats.total_bytes)}")
        print(f"[*] File RRD salvati in: {os.path.abspath(RRD_DIR)}/")

    def generate_graphs(self, period="1h", quiet=False):
        """Genera i grafici e restituisce le sorgenti disponibili."""
        graphs_dir = os.path.join(RRD_DIR, "graphs")
        os.makedirs(graphs_dir, exist_ok=True)
        restore_user_ownership(graphs_dir)

        rrd_files = [f for f in os.listdir(RRD_DIR) if f.endswith(".rrd")]
        if not rrd_files:
            if not quiet:
                print("[!] Nessun file RRD trovato. Avvia prima una cattura.")
            return []

        if not quiet:
            print(f"[*] Generazione grafici per {len(rrd_files)} sorgenti (periodo: {period})...")

        sources = []

        for rrd_file in sorted(rrd_files, key=lambda name: name != "local_host.rrd"):
            filepath = os.path.join(RRD_DIR, rrd_file)
            stem = rrd_file.removesuffix(".rrd")
            label = rrd_label(rrd_file)
            traffic_png = os.path.join(graphs_dir, f"{stem}_traffic_{period}.png")
            protocols_png = os.path.join(graphs_dir, f"{stem}_protocols_{period}.png")

            try:
                rrd_graph(filepath, traffic_png, f"{label} - traffico ({period})", period)
                rrd_protocol_graph(
                    filepath, protocols_png,
                    f"{label} - protocolli ({period})", period,
                )
                sources.append({
                    "label": label,
                    "traffic": os.path.basename(traffic_png),
                    "protocols": os.path.basename(protocols_png),
                    "local": stem == "local_host",
                })
                if not quiet:
                    print(f"  [OK] {traffic_png}")
                    print(f"  [OK] {protocols_png}")
            except subprocess.CalledProcessError as e:
                print(f"  [ERR] {label}: {e.stderr.decode().strip()}")

        if not quiet:
            print(f"\n[*] Grafici salvati in: {os.path.abspath(graphs_dir)}/")
        return sources


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
        ips = [
            a.address for a in addrs
            if a.family in (socket.AF_INET, socket.AF_INET6)
        ]
        status = all_stats.get(name)
        up = "UP" if status and status.isup else "DOWN"
        speed = f"{status.speed}Mbps" if status and status.speed > 0 else ""
        ip_str = ", ".join(ips) if ips else "nessun IP"
        print(f"  {name:<20s} [{up}] {speed:<12s} {ip_str}")
    print()


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Bandwidth Monitor per-host con RRDtool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Esempi:
  python3 %(prog)s -i en0                       # cattura su en0
  python3 %(prog)s -i en0 -f "tcp port 443"    # solo HTTPS
  python3 %(prog)s --graph                        # genera grafici PNG
  python3 %(prog)s --graph --period 5min          # grafici ultimi 5 minuti
  python3 %(prog)s --web --period 5min            # dashboard sui dati esistenti
  python3 %(prog)s -i en0 --web --period 5min     # cattura e dashboard live
  python3 %(prog)s --graph --period 6h            # grafici ultime 6 ore
  python3 %(prog)s --list-interfaces              # mostra interfacce
""",
    )
    parser.add_argument("-i", "--interface", help="Interfaccia di rete da monitorare")
    parser.add_argument("-f", "--filter", default=None, help="Filtro BPF (es. 'tcp port 443')")
    parser.add_argument("--list-interfaces", action="store_true", help="Mostra le interfacce disponibili")
    parser.add_argument("--graph", action="store_true", help="Genera grafici PNG dai file RRD esistenti")
    parser.add_argument("--web", action="store_true", help="Avvia la dashboard web locale")
    parser.add_argument("--web-host", default="127.0.0.1", help="Indirizzo dashboard (default: 127.0.0.1)")
    parser.add_argument("--web-port", type=int, default=8080, help="Porta dashboard (default: 8080)")
    parser.add_argument(
        "--period",
        type=valid_period,
        default="1h",
        metavar="PERIODO",
        help="Periodo grafici: s, min, h, d, w (es. 5min, 6h; default: 1h)",
    )

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

    # Dashboard sui database esistenti, senza avviare una nuova cattura.
    if args.web and not args.interface:
        monitor = NetworkMonitor("web")
        start_dashboard(
            monitor, args.web_host, args.web_port, args.period,
            RRD_DIR, valid_period,
            background=False,
        )
        return

    if not args.interface:
        print("[ERRORE] Specificare l'interfaccia con -i (es. -i en0)")
        list_interfaces()
        sys.exit(1)

    print("=" * 60)
    print("  Bandwidth Monitor per-host con RRDtool")
    print("=" * 60)
    list_interfaces()

    monitor = NetworkMonitor(args.interface, args.filter)
    web_server = None
    if args.web:
        web_server = start_dashboard(
            monitor, args.web_host, args.web_port, args.period,
            RRD_DIR, valid_period,
            background=True,
        )

    try:
        monitor.start()
    except KeyboardInterrupt:
        monitor.stop()
        # Genera i grafici alla fine della cattura
        print()
        monitor.generate_graphs()
    finally:
        if web_server:
            web_server.shutdown()
            web_server.server_close()


if __name__ == "__main__":
    main()
