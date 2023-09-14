#! /usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import signal

def block_outgoing_packets():
    block_command = "iptables -A OUTPUT -j DROP"
    subprocess.call(block_command, shell=True)

def unblock_outgoing_packets():
    unblock_command = "iptables -D OUTPUT -j DROP"
    subprocess.call(unblock_command, shell=True)

try:
    # Blocca i pacchetti in uscita
    block_outgoing_packets()
    print("Bloccati i pacchetti in uscita. Premi Ctrl+C per sbloccarli.")

    # Attendi l'arrivo del segnale di interruzione
    signal.pause()

except KeyboardInterrupt:
    # Segnale di interruzione ricevuto, sblocca i pacchetti in uscita
    unblock_outgoing_packets()
    print("Sbloccati i pacchetti in uscita.")
