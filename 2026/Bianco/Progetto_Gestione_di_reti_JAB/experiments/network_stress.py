#!/usr/bin/env python3
"""
network_stress.py - Simula un host che fa download pesante

Scarica ripetutamente un file HTTP per generare traffico in download osservabile da ntopng.
L'IP locale da usare deve essere specificato esplicitamente.

Uso:
    python3 network_stress.py
    python3 network_stress.py --durata <SECONDI>
"""

import argparse
import time
import urllib.error
import urllib.request

URL = "http://speedtest.tele2.net/100MB.zip"
DIMENSIONE_CHUNK = 65536

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "*/*",
}


def avvia_download(durata):
    print(f"URL sorgente : {URL}")
    print(f"Durata       : {durata}s")
    print("Avvio... Ctrl+C per fermare\n")

    byte_totali = 0
    byte_precedenti = 0
    inizio = time.time()
    ultimo_report = inizio

    try:
        while time.time() - inizio < durata:
            try:
                richiesta = urllib.request.Request(URL, headers=HEADERS)
                with urllib.request.urlopen(richiesta, timeout=30) as risposta:
                    while time.time() - inizio < durata:
                        chunk = risposta.read(DIMENSIONE_CHUNK)
                        if not chunk:
                            break

                        byte_totali += len(chunk)

                        ora = time.time()
                        if ora - ultimo_report >= 1:
                            secondi = ora - inizio
                            mb_secondo = (byte_totali - byte_precedenti) / 1_048_576
                            mb_totali = byte_totali / 1_048_576
                            print(f"  {secondi:5.0f}s | {mb_secondo:6.2f} MB/s | totale {mb_totali:7.2f} MB")
                            byte_precedenti = byte_totali
                            ultimo_report = ora
            except urllib.error.HTTPError as errore:
                print(f"Errore HTTP {errore.code}")
                time.sleep(1)
            except Exception as errore:
                print(f"Errore: {errore}")
                time.sleep(1)

    except KeyboardInterrupt:
        print("\nInterrotto.")

    secondi_totali = time.time() - inizio or 0.001
    mb_totali = byte_totali / 1_048_576
    print(f"\nFine — {mb_totali:.2f} MB in {secondi_totali:.1f}s ({mb_totali / secondi_totali:.2f} MB/s)")


def main():
    parser = argparse.ArgumentParser(description="Simulatore download pesante per ntopng")
    parser.add_argument("--durata", type=int, default=120, help="Durata in secondi")
    args = parser.parse_args()

    avvia_download(args.durata)


if __name__ == "__main__":
    main()
