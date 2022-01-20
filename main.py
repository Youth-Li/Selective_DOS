import nmap
import os
import socket
import scapy
import netifaces


def getGate():
	gate = netifaces.gateways()
	return gate['default'][netifaces.AF_INET]

gateway = getGate()
print(gateway)
interface = netifaces.ifaddresses(gateway[1])
print(interface)
