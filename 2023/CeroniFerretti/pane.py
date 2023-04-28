import argparse
import blacklist
import intel_sender
import pyshark

from ipaddress import ip_address


def checkIP(ip, bl_ip):
  job = -1
  if not ip_address(ip).is_private:
        if  blacklist.check_if_present(ip):
          if ip not in bl_ip:
            print("ATTENZIONE IP IN BLACKLIST: ", ip)
            bl_ip.append(ip)
            job = intel_sender.intelTest(ip)
  return job

def network_conversation(capture):
  bl_ip=[]
  jobs=[]
  for packet in capture:
    try:
      # Source
      source_address = packet.ip.src
      aux = checkIP(source_address,bl_ip)
      if aux != -1:
        jobs.append(aux)
      # Destination
      destination_address = packet.ip.dst
      aux = checkIP(destination_address, bl_ip)
      if aux != -1:
        jobs.append(aux)
    except AttributeError:
      pass
  return jobs

def main(bl, pcap):
  blacklist.load_address(bl)
  capture = pyshark.FileCapture(pcap)
  jobs = network_conversation(capture)
  while len(jobs)>0:
    if not intel_sender.status(jobs[0]):
      continue
    else:
      intel_sender.workJob(jobs[0])
      jobs.pop(0)

if __name__ == '__main__':
  ap = argparse.ArgumentParser()
  ap.add_argument('-b', '--blacklists', help='The name of file that contains the blacklists', nargs=1, required=True)
  ap.add_argument('-p', '--pcap', help='The name of pcap file to analyze', nargs=1, required=True)
  try:
    args = ap.parse_args()
  except argparse.ArgumentError as e:
    ap.print_help()
    exit(1)

  main(args.blacklists[0],args.pcap[0])
