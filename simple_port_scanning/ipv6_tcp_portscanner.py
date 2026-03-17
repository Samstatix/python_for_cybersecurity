#!/usr/bin/env python3
import socket

host = input("Enter the IP address of the host: ")      
port = int(input("Enter the port: "))

sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
socket.setdefaulttimeout(5)

def portscanner(port):
    if sock.connect_ex((host, port, 0, 0)) == 0:
        print ("Port %d is OPEN" % port)
    else:
        print ("Port %d is CLOSED" % port)
    sock.close()
portscanner(port)
