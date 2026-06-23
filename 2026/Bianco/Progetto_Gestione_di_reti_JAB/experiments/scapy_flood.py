#!/usr/bin/env python3
"""
scapy_flood.py - Simula traffico UDP anomalo verso una destinazione

Genera pacchetti UDP con IP sorgente simulato, così ntopng può mostrare
un host anomalo/top talker nel traffico osservato.

Richiede:
    pip install scapy

Uso:
    sudo python3 scapy_flood.py --destinazione <IP_DESTINAZIONE> --sorgente <IP_SORGENTE>
    sudo python3 scapy_flood.py --destinazione <IP_DESTINAZIONE> --sorgente <IP_SORGENTE> --durata <SECONDI>
"""

import argparse
import time
from scapy.all import Ether, IP, UDP, Raw, sendp, conf

PAYLOAD = b"X" * 1400
PORTA_DST = 80


def avvia_flood(destinazione, sorgente, durata):

    pacchetto = (
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / IP(src=sorgente, dst=destinazione)
        / UDP(sport=12345, dport=PORTA_DST)
        / Raw(load=PAYLOAD)
    )

    byte_per_pacchetto = len(pacchetto)

    print(f"Sorgente simulata : {sorgente}")
    print(f"Destinazione      : {destinazione}:{PORTA_DST} UDP")
    print(f"Durata            : {durata}s")
    print("Avvio... Ctrl+C per fermare\n")

    byte_totali = 0
    byte_precedenti = 0
    inizio = time.time()
    ultimo_report = inizio

    try:
        while time.time() - inizio < durata:
            sendp(pacchetto, iface=conf.iface, verbose=False)
            byte_totali += byte_per_pacchetto

            ora = time.time()
            if ora - ultimo_report >= 1:
                secondi = ora - inizio
                mb_secondo = (byte_totali - byte_precedenti) / 1_048_576
                mb_totali = byte_totali / 1_048_576
                print(f"  {secondi:5.0f}s | {mb_secondo:6.2f} MB/s | totale {mb_totali:7.2f} MB")
                byte_precedenti = byte_totali
                ultimo_report = ora
    except KeyboardInterrupt:
        print("\nInterrotto.")

    secondi_totali = time.time() - inizio or 0.001
    mb_totali = byte_totali / 1_048_576
    print(f"\nFine — {mb_totali:.2f} MB in {secondi_totali:.1f}s ({mb_totali / secondi_totali:.2f} MB/s)")
    print("In ntopng controlla il traffico associato alla sorgente simulata:", sorgente)


def main():
    parser = argparse.ArgumentParser(description="Generatore traffico UDP anomalo via Scapy")
    parser.add_argument("--destinazione", help="IP di destinazione verso cui inviare i pacchetti")
    parser.add_argument("--sorgente", help="IP sorgente simulato")
    parser.add_argument("--durata", type=int, default=120, help="Durata in secondi")
    args = parser.parse_args()

    if not args.destinazione or not args.sorgente:
        parser.error("devi specificare --destinazione e --sorgente")

    avvia_flood(args.destinazione, args.sorgente, args.durata)


if __name__ == "__main__":
    main()