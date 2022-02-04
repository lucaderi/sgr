#!/usr/bin/env python

import socket, sys

if __name__ == '__main__':
    if len(sys.argv) != 2:
        exit("Usage: port")
    skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    skt.bind(("", int(sys.argv[1])))
    try:
        while True:
            msg, addr = skt.recvfrom(1024)
            if sys.version_info[0] >= 3:
                print(addr, "->", str(msg))
            else:
                print addr, "->", str(msg)
    except KeyboardInterrupt:
        skt.close()
