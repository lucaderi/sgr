#!/usr/bin/env python

import socket, sys

if __name__ == '__main__':
    if len(sys.argv) != 2:
        exit("Usage: port")
    skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    skt.bind(("", int(sys.argv[1])))
    c = 0
    try:
        orig, addr = skt.recvfrom(1024)
        skt.sendto(orig, addr)
        c = 1
        while True:
            msg, addr = skt.recvfrom(1024)
            if msg != orig:
                exit("FAIL MESSAGES DIFFER\noriginal:" + str(orig) + "\nactual:" + str(msg))
            skt.sendto(msg, addr)
            c += 1
    except KeyboardInterrupt:
        skt.close()
        if sys.version_info[0] >= 3:
            print("count", c)
        else:
            print count, c
            
