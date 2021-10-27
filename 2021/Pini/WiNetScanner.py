#!/usr/bin/env python

import scapy.all as scapy
import argparse
import os
import subprocess

from Client import Client
from AP import AP



# Extracted Packet Format 
Beacon_Pkt_Info = """
---------------[ Beacon Packet Captured ]-----------------------
 Access Point MAC : {}  
 Access Point Name [SSID]  : {}
"""

# Extracted Packet Format 
Probe_Pkt_Info = """
---------------[ Probe Packet Captured ]-----------------------
 Client MAC           : {}   
 Access Point Name [SSID] : {}
"""


# GetClientsAndAP Function
def GetClientsAndAP(scan_type, verbose, *args,  **kwargs):
  """
  Function for filtering Beacon Frames (to extract Access Point information) and Probe Request
  Frames (to extract Clients information) from captured packets
  """

  ap={} # Access Points dictionary
  packets=[] # Packets list
  clients={} # Clients dictionary

  def PacketFilter(pkt):

    # Interested in Clients (or both)
    if scan_type == "c" or scan_type == "b":

      # Considering packets of unseen clients, or seen client where Access Point [SSID] is unseen
      if pkt.haslayer(scapy.Dot11ProbeReq):
        ssid = pkt.sprintf("{Dot11ProbeReq:%Dot11ProbeReq.info%}")   # AP Network Name   # Needed pkt.info isn't Stringable
        bssid = pkt.addr2 # Client MAC

        if bssid not in clients:
          # New client
          packets.append(pkt)
          clients[bssid] = Client(bssid)
          if verbose:
            print("----NEW CLIENT---")
            print(Probe_Pkt_Info.format(pkt.addr2, pkt.info))
          if ssid != "b''":
            clients[bssid].add_new_requested_ssid(ssid)

        else: 
          # Not new client
          if ssid != "b''":
            packets.append(pkt)
            if clients[bssid].add_new_requested_ssid(ssid):
              if verbose:
                print("----NOT NEW CLIENT, BUT WITH UNSEEN ACCESS POINT [SSID]")
                print(Probe_Pkt_Info.format(pkt.addr2, pkt.info))

    # Interested in Access Points (or both)
    if scan_type == "a" or scan_type == "b":
      if pkt.haslayer(scapy.Dot11Beacon):
        ssid = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.info%}")  # AP Network Name     # Needed pkt.info isn't Stringable
        if pkt.addr2 not in ap:
          ap[pkt.addr2] = AP(pkt.addr2, ssid)
          packets.append(pkt)

          if verbose:
            print(Beacon_Pkt_Info.format(pkt.addr2, pkt.info))

  print("Gathering informartion...")

  # Sniffing packets
  scapy.sniff(prn=PacketFilter, *args, **kwargs)

  return (ap, clients, packets)

# Main Trigger
if __name__=="__main__":
 
  # Definition of accepted arguments
  parser = argparse.ArgumentParser(description="Scan for Access Points and/or Clients")
  parser.add_argument("-m", "--mode", help="a=access points, c=clients, b=both")
  parser.add_argument("-i", "--interface", help="specify interface to listen on")
  parser.add_argument("-t", "--time", help="specify time (in sec) listening for packets  (type 'u' for unlimited) (press 'Ctrl+C' to stop)")
  parser.add_argument("-verbose", action="store_true", default=False)

  args = parser.parse_args()

  # Setting interface
  if args.interface is not None:
    interface = args.interface
  else:
    interface = scapy.conf.route.route("0.0.0.0")[0]
    print("Using default interface: " +  interface)

  # Setting timeout value
  time_value = 60 #default timeout
  if args.time is not None:
    if args.time == "u":
        time_value = 9223372036.854776
    else:
      try:
        time_value = int(args.time)
        if time_value <= 0:
          print("ERROR: time must be > 0")
          parser.print_usage()
          exit(-1)
      except ValueError:
        print("ERROR: time must be an int")
        parser.print_usage()
        exit(-1)

  # Setting scan type
  valid_modes = ["a", "c", "b"]
  scan_type = "b" #default scan type (scanni9ng both Access Points and Clients)
  if args.mode in valid_modes:
    scan_type = args.mode
  else:
    print("ERROR: Invalid mode")
    parser.print_usage()
    exit(-1)
    

  # Starting monitor mode
  cmd_exit_code = subprocess.run(["airmon-ng", "start", interface], stdout=subprocess.DEVNULL)
  if cmd_exit_code.returncode != 0:
    print("ERROR: Was not able to start monitor mode on " + interface + " interface")
    exit(-1)

  if args.verbose:
    print("`airmon-ng  start " + interface + "` ran with exit code %d" % cmd_exit_code.returncode)
  mon_interface = interface + "mon"


  # Getting Access Points, Clients and packets seen
  ap, clients, packets = GetClientsAndAP(scan_type, args.verbose, iface=mon_interface, timeout=time_value)  

  # Stopping monitor mode
  cmd_exit_code2 = subprocess.run(["airmon-ng", "stop", interface + "mon"], stdout=subprocess.DEVNULL)
  if args.verbose:
    print("`airmon-ng  stop " + interface + "mon` ran with exit code %d" % cmd_exit_code2.returncode)
  
  # Printing Access Points informations
  if scan_type == 'a' or scan_type == 'b':
    print("\n================ ACCESS POINTS ================")
    print("Number of seen AP:  %d" % len (ap))
    print("\nAP MAC [BSSID]       AP NETWORK NAME [SSID]")
    for x in ap:
      ap[x].printAP()

  # Printing Clients informations
  if scan_type == 'c' or scan_type == 'b':
    print("\n\n=================== CLIENTS ===================")
    print("Number of seen clients:  %d" % len (clients))
    print("\nCLIENT MAC           AP NETWORK NAME [SSID]")
    for x in clients:
      clients[x].printClient()

