#!/usr/bin/python3

import socket
from termcolor import colored

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.setdefaulttimeout(5)

host = input("Enter the IP address of the host: ")

def portscanner(port):
    if sock.connect_ex((host, port)):
        print(colored("Port %d is closed" % port, 'red'))
    else:
        print(colored("Port %d is opened" % port, 'green'))
    

for port in range(1,1001):
    portscanner(port)
