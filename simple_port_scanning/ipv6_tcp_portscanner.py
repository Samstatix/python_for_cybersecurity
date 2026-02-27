#!/usr/bin/env python2
import socket

host = "::1"          # IPv6 loopback
port = 443

sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

def portscanner(port):
    # For IPv6, connect_ex expects a tuple (address, port, flowinfo, scopeid)
    if sock.connect_ex((host, port, 0, 0)) == 0:
        print "Port %d is OPEN" % port
    else:
        print "Port %d is CLOSED" % port

portscanner(port)
sock.close()