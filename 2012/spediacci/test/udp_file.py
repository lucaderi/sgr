#!/usr/bin/env python

import socket, sys

if __name__ == '__main__':
    if len(sys.argv) != 3:
        exit("Usage: file port")
    skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    skt.bind(("", int(sys.argv[2])))
    f = open(sys.argv[1], "wb")
    try:
        while True:
            msg, addr = skt.recvfrom(1024 ** 2)
            if sys.version_info[0] >= 3:
                print(addr,len(msg), "bytes received")
            else:
                print addr,len(msg), "bytes received"
            f.write(msg)
    except KeyboardInterrupt:
        f.close()
        skt.close()
