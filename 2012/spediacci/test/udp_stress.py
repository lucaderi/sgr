#!/usr/bin/env python

import socket, sys, threading

class R(threading.Thread):

    def __init__(self, port):
        threading.Thread.__init__(self)
        self.skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.skt.bind(("", int(port)))


    def run(self):
        orig, addr = self.skt.recvfrom(1024)
        while True:
            msg, addr = self.skt.recvfrom(1024)
            if msg != orig:
                print "ERROR"
                break

class S(threading.Thread):
    
    def __init__(self, ip, port, msg):
        threading.Thread.__init__(self)
        self.skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dest = (ip, port)
        self.msg = msg

    def run(self):
        while True:
            self.skt.sendto(self.msg, self.dest)

if __name__ == '__main__':
    if len(sys.argv) != 5:
        exit("Usage: port_bind ip_dest port_dest message")
    try:
        r = R(sys.argv[1]).start()
        s = S(sys.argv[2], int(sys.argv[3]), sys.argv[4]).start()
    except KeyboardInterrupt:
        r.skt.close()
        s.skt.close()
        s.join()
        r.join()
            
