"""Dashboard web locale per Bandwidth Monitor.

La cattura dei
pacchetti e la gestione dei database RRD restano in bandwidth_monitor.py.
"""

import argparse
import html
import mimetypes
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class DashboardHandler(BaseHTTPRequestHandler):
    """Espone la pagina HTML e i grafici PNG generati da RRDtool."""

    monitor = None
    rrd_dir = "rrd_data"
    default_period = "5min"
    period_validator = None
    graph_lock = threading.Lock()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._serve_dashboard(parse_qs(parsed.query))
        elif parsed.path.startswith("/graphs/"):
            self._serve_graph(parsed.path.removeprefix("/graphs/"))
        else:
            self.send_error(404, "Pagina non trovata")

    def _serve_dashboard(self, query):
        period = query.get("period", [self.default_period])[0]
        try:
            period = self.period_validator(period)
        except argparse.ArgumentTypeError:
            period = self.default_period

        with self.graph_lock:
            sources = self.monitor.generate_graphs(period, quiet=True)

        with self.monitor.lock:
            packets = self.monitor.local_stats.total_packets
            download = self.monitor._format_bytes(self.monitor.local_stats.bytes_in)
            upload = self.monitor._format_bytes(self.monitor.local_stats.bytes_out)

        stamp = int(time.time())
        cards = [self._host_card(source, stamp) for source in sources]
        if not cards:
            cards.append("""
                <div class="empty">
                    <h2>Nessun dato disponibile</h2>
                    <p>Avvia una cattura per popolare i database RRD.</p>
                </div>
            """)

        periods = ("5min", "30min", "1h", "6h", "24h")
        period_links = "".join(
            f'<a class="period {"active" if value == period else ""}" '
            f'href="/?period={value}">{value}</a>'
            for value in periods
        )

        page = f"""<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="15;url=/?period={period}">
  <title>Bandwidth Monitor</title>
  <style>
    :root {{ --background:#f4f6f8; --panel:#ffffff; --text:#1f2933;
      --muted:#52606d; --border:#d9e2ec; --blue:#2563eb; --orange:#d97706; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; color:var(--text); background:var(--background);
      font:15px/1.5 Arial,Helvetica,sans-serif; }}
    main {{ width:min(1440px,94vw); margin:auto; padding:32px 0 48px; }}
    header {{ display:flex; justify-content:space-between; align-items:flex-end;
      gap:24px; margin-bottom:24px; padding-bottom:20px; border-bottom:1px solid var(--border); }}
    h1 {{ margin:0 0 6px; font-size:32px; }}
    .subtitle {{ margin:0; color:var(--muted); max-width:760px; }}
    .status {{ display:flex; align-items:center; gap:8px; color:var(--muted); white-space:nowrap; }}
    .dot {{ width:9px; height:9px; border-radius:50%; background:#16a34a; }}
    .summary {{ display:grid; grid-template-columns:repeat(3,1fr); gap:14px; margin-bottom:20px; }}
    .metric {{ padding:16px 18px; border:1px solid var(--border); border-radius:8px;
      background:var(--panel); }}
    .metric span {{ display:block; color:var(--muted); font-size:12px; text-transform:uppercase;
      letter-spacing:.05em; }}
    .metric strong {{ font-size:23px; }}
    .download strong {{ color:var(--blue); }}
    .upload strong {{ color:var(--orange); }}
    nav {{ display:flex; gap:8px; flex-wrap:wrap; margin:20px 0; }}
    .period {{ padding:6px 12px; color:var(--text); background:var(--panel);
      border:1px solid var(--border); border-radius:5px; text-decoration:none; }}
    .period:hover,.period.active {{ color:#fff; background:#334e68; border-color:#334e68; }}
    .host-card {{ margin-top:16px; padding:18px; background:var(--panel);
      border:1px solid var(--border); border-radius:8px; }}
    .card-title {{ display:flex; align-items:center; gap:10px; margin-bottom:12px; }}
    h2 {{ margin:0; font-size:19px; }}
    .badge {{ padding:3px 8px; color:#1e40af; background:#dbeafe; border-radius:4px;
      font-size:11px; font-weight:bold; text-transform:uppercase; }}
    .charts {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; }}
    figure {{ min-width:0; margin:0; }}
    figcaption {{ margin-bottom:7px; color:var(--muted); }}
    img {{ display:block; width:100%; height:auto; border:1px solid var(--border); }}
    .empty {{ padding:60px 20px; text-align:center; background:var(--panel);
      border:1px solid var(--border); border-radius:8px; }}
    footer {{ margin-top:24px; color:var(--muted); font-size:13px; }}
    @media (max-width:850px) {{ header {{ align-items:flex-start; flex-direction:column; }}
      .charts,.summary {{ grid-template-columns:1fr; }} }}
  </style>
</head>
<body><main>
  <header>
    <div><h1>Bandwidth Monitor</h1>
      <p class="subtitle">Monitoraggio locale del traffico IPv4/IPv6 per host remoto e protocollo.</p></div>
    <div class="status"><span class="dot"></span>Aggiornamento ogni 15 secondi</div>
  </header>
  <section class="summary" aria-label="Riepilogo sessione">
    <div class="metric"><span>Pacchetti locali</span><strong>{packets:,}</strong></div>
    <div class="metric download"><span>Download sessione</span><strong>{download}</strong></div>
    <div class="metric upload"><span>Upload sessione</span><strong>{upload}</strong></div>
  </section>
  <nav aria-label="Periodo del grafico">{period_links}</nav>
  {''.join(cards)}
  <footer>Grafici calcolati da RRDtool. Download negativo, upload positivo. Periodo: {period}.</footer>
</main></body></html>"""
        self._send_bytes(page.encode("utf-8"), "text/html; charset=utf-8")

    @staticmethod
    def _host_card(source, stamp):
        label = html.escape(source["label"])
        traffic = html.escape(source["traffic"], quote=True)
        protocols = html.escape(source["protocols"], quote=True)
        badge = '<span class="badge">Questo dispositivo</span>' if source["local"] else ""
        return f"""
            <article class="host-card">
              <div class="card-title"><h2>{label}</h2>{badge}</div>
              <div class="charts">
                <figure><figcaption>Upload e download</figcaption>
                  <img src="/graphs/{traffic}?v={stamp}" alt="Upload e download di {label}"></figure>
                <figure><figcaption>Traffico per protocollo</figcaption>
                  <img src="/graphs/{protocols}?v={stamp}" alt="Protocolli di {label}"></figure>
              </div>
            </article>
        """

    def _serve_graph(self, filename):
        safe_name = os.path.basename(filename)
        if safe_name != filename or not safe_name.endswith(".png"):
            self.send_error(400, "Nome file non valido")
            return
        path = os.path.join(self.rrd_dir, "graphs", safe_name)
        if not os.path.isfile(path):
            self.send_error(404, "Grafico non trovato")
            return
        with open(path, "rb") as graph_file:
            payload = graph_file.read()
        self._send_bytes(payload, mimetypes.guess_type(path)[0] or "image/png")

    def _send_bytes(self, payload, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format_, *args):
        """Evita di riempire il terminale a ogni refresh del browser."""


def start_dashboard(
    monitor, host, port, period, rrd_dir, period_validator, background=False,
):
    """Avvia la dashboard; in background puo' convivere con la cattura."""
    DashboardHandler.monitor = monitor
    DashboardHandler.rrd_dir = rrd_dir
    DashboardHandler.default_period = period
    DashboardHandler.period_validator = staticmethod(period_validator)
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    url_host = "localhost" if host in ("127.0.0.1", "0.0.0.0") else host
    print(f"[*] Dashboard web: http://{url_host}:{server.server_port}/?period={period}")
    if background:
        thread = threading.Thread(
            target=server.serve_forever, daemon=True, name="web-dashboard",
        )
        thread.start()
        return server
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Dashboard terminata.")
    finally:
        server.server_close()
