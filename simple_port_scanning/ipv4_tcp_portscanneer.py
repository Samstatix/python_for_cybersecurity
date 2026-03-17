#!/usr/bin/python3

import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.setdefaulttimeout(5)
host = input("Enter the IP address of the host: ")
port = int(input("Enter the port: "))

def portscanner(port):
    if sock.connect_ex((host, port)):
        print ("Port %d is closed" % port)
    else:
        print ("Port %d is opened" % port)

portscanner(port)
