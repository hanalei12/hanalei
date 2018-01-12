from scapy.all import *
import time
import requests

MAGIC_FORM_URL = 'https://api.cloudstitch.com/hanalei/hanalei-1/datasources/sheet' 

def record():
	data = {
		"FirstName": .str("Sara"),
		"LastName": .str("Brooks"),
		# "Timestamp": time.strftime("%Y-%m-%d %H:%M"), 
		"Action": 'LOG'
	}
	print str(data['FirstName']) + str(data['LastName'])
	# print str(data['Timestamp']) + " " + str(data['Action'])
	requests.post(MAGIC_FORM_URL, data)
	
def arp_display(pkt):
  timestamp = time.strftime("%Y-%m-%d %H:%M")
  if pkt[ARP].op == 1: #who-has (request)
  	if pkt[ARP].psrc == '192.168.1.101': # ARP Probe
		if pkt[ARP].hwsrc == 'AC:63:BE:89:59:0B':
			record()
		else:
			print "ARP Probe from: " + pkt[ARP].hwsrc
			
 print sniff(prn=arp_display, filter="arp", store=0, count=10)
