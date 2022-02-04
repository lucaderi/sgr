import sys
import pyshark
import Address
import socket
from Address import *
import AddressTree
from AddressTree import *
import dns.resolver
import json
import datetime
from datetime import datetime

# p.transport_layer
# p.ip.src
# p[p.transport_layer].srcport
# p.ip.dst
# p[p.transport_layer].dstport


def createACL(name,list_type,resolved,unresolved,direction):

    if direction == 0: #from local host to remote
        dir = "destination"
    else : #from remote host to local
        dir = "source"

    list = {
        "name" : name,
        "type" : list_type ,
    }

    i = 0
    tmp = []
    for addr in resolved:
        protocol = addr[2]
        port = addr[1]
        address = addr[0]
        for p in port:
            element={
                "name" : name+"-"+str(i),
                "matches" : {
                    "ipv4":{
                        "ietf-acldns:dst-dnsname" : address
                    },
                    protocol : {
                        "destination-port" : {
                            "operator" : "eq",
                            "port" : p
                        }
                    }
                },
                "actions" : {
                    "forwarding" : "accept"
                }
            }
            i += 1
            tmp.append(element)


    for addr in unresolved:
        protocol = addr[2]
        port = addr[1]
        address = addr[0]
        for p in port:
            element={
                "name" : name+"-"+str(i),
                "matches" : {
                    "ipv4":{
                        dir+"-ipv4-network" : address
                    },
                    protocol : {
                        "destination-port" : {
                            "operator" : "eq",
                            "port" : p
                        }
                    }
                },
                "actions" : {
                    "forwarding" : "accept"
                }
            }
            i += 1
            tmp.append(element)

    new_l = {}
    new_l["ace"] = tmp
    list["aces"] = new_l

    return list

#------------------------------------------------------------------------------------------------------------#

def main(args):

    try:
        if args[1] == "-h" or args[1]=="--help":
            print("Use: ' python3 Creator.py path_to_pcap_file path_to_save_mud_file [ip_addr] ' ")
            return
        c = pyshark.FileCapture(args[1],display_filter='tcp || udp',keep_packets=False)
        save_path = args[2]
    except FileNotFoundError:
        print("Incorrect/invalid path for pcap file.")
        return
    except:
        print("Use: ' python3 Creator.py path_to_pcap_file path_to_save_mud_file [ip_addr] ' ")
        return

    date_and_time = datetime.now()

    resolver = dns.resolver.Resolver()
    hostname = socket.gethostname()

    if args.__len__()==4:
        IP = args[3]
        hostname = args[3]
    else:
        IP = socket.gethostbyname(hostname)

    mud_path = save_path+"/"+hostname+"("+date_and_time.__str__()+")MUD.json"
    try:
        mud_file = open(mud_path,'x')
    except:
        print("Incorrect/invalid path for MUD file.")
        return

    received = AddressTree()
    sent = AddressTree()

    for p in c:
        if p.ip.src == IP:
            new_addr=Address(p.ip.dst,p[p.transport_layer].dstport,p.transport_layer)
            sent.add(new_addr)
        elif p.ip.dst == IP:
            new_addr=Address(p.ip.src,p[p.transport_layer].dstport,p.transport_layer)
            received.add(new_addr)


    remote_to_local_addresslist = received.getAddresses()
    local_to_remote_addresslist = sent.getAddresses()

    resolved_rtl = []
    unresolved_rtl = []

    resolved_ltr = []
    unresolved_ltr = []

    for add in local_to_remote_addresslist:
        try:
            ans = (resolver.query(add[0] + ".in-addr.arpa", "PTR"))
            for r in ans:
               resolved_ltr.append((r.__str__(),add[1],add[2]))
        except:
            unresolved_ltr.append((add[0],add[1],add[2]))


    for add in remote_to_local_addresslist:
        try:
            ans = (resolver.query(add[0] + ".in-addr.arpa", "PTR"))
            for r in ans:
               resolved_rtl.append((r.__str__(),add[1],add[2]))
        except:
            unresolved_rtl.append((add[0],add[1],add[2]))

    from_name = "from-ipv4-"+hostname
    to_name = "to-ipv4-"+hostname

    lista1 = createACL("from-ipv4-"+hostname,"ipv4-acl-type",resolved_ltr,unresolved_ltr,0)
    lista2 = createACL("to-ipv4-" + hostname, "ipv4-acl-type", resolved_rtl, unresolved_rtl,1)

    mud = {
        "ietf-mud:mud": {
            "mud-version" : 1,
            "mud-url": mud_path,
            "last-update": date_and_time.__str__(),
            "cache-validity" : 100,
            "is-supported" : "true",
            "systeminfo": hostname,
            "from-device-policy": {
                "access-lists": {
                    "access-list": [{
                        "name": from_name
                    }]
                }
            },
            "to-device-policy": {
                "access-lists": {
                    "access-list": [{
                        "name": to_name
                    }]
                }
            }
        },
        "ietf-access-control-list:access-lists": {
            "acl": [
                lista1,
                lista2
            ]
        }
    }

    json.dump(mud,mud_file,indent=1)




main(sys.argv)
