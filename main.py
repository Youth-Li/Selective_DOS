from netaddr import IPAddress
import os
import socket
import scapy
import netifaces
import nmap


def getGate():
	gate = netifaces.gateways()
	return gate['default'][netifaces.AF_INET]

def netScan():
	map = nmap.PortScanner()
	cidr =IPAddress(netprop['netmask']).netmask_bits()
	map.scan(hosts=netprop['addr']+'/'+str(cidr) , arguments='-sn')

	




gateway = getGate()[0]
interface = getGate()[1]

#there is more info you can get from this like netmask addr broadcast just ask in [] when deref
netprop = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
print(netprop['netmask'])
netScan()
