#!/usr/bin/env python3
import pprint
import requests
import argparse
import subprocess
import json
import scapy.all as scapy
import urllib.request as urllib2
import codecs

"""Author Amasu_Soldier :-) """
def check_vendor_of_mac(RecievedMac):
	url = "http://macvendors.co/api/"
	#Mac address to lookup vendor from
	mac_address = RecievedMac

	request = urllib2.Request(url+mac_address, headers={'User-Agent' : "API Browser"}) 
	response = urllib2.urlopen( request )
	#Fix: json object must be str, not 'bytes'
	reader = codecs.getreader("utf-8")
	obj = json.load(reader(response))
	#Print company name
	return (obj['result']['company']+"<br/>")
#	return (obj['result']['address']);

"""This method get Arguments from cmd"""

def get_arguments_from_cmd():
	parser=argparse.ArgumentParser()
	parser.add_argument("-r","--range",dest="range",help="Enter Ip range / Subnet")
	args=parser.parse_args()
	return args.range

"""This method generate the Arp Frame and Forward it to a Broadcast Mac Address and append 
Captured Response in a list of dictionaries"""

def check_arping(ip):
	arp_request=scapy.ARP(pdst=ip)
	broadcast=scapy.Ether(dst="FF:FF:FF:FF:FF")
	arp_request_broadcast=broadcast/arp_request
	answered_list=scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
	clients_list=[]

	for eachelement in answered_list:
		client_dict={"IP":eachelement[1].psrc,"MAC":eachelement[1].hwsrc}
		clients_list.append(client_dict)
	return clients_list

"""This Function Print the Mac Address And Ip Addresses of All the host which are Alive"""
def print_result(resultsList):
	if len(resultsList)==0:
		print("[-] No Results Are Found")
	else:
		print("\n")
		print("IP\t\t\tMAC Address\t\t\tCompany\n------------------------------------------------------------------------------")
		for client in resultsList:
			company=check_vendor_of_mac(client["MAC"])
			print(client["IP"] + "\t\t"+client["MAC"]+"\t\t"+company)

"""Main Function"""
def main():
	inputedRange=get_arguments_from_cmd()
	if not inputedRange:
		print("Please Enter the Range of hosts...!!!")
	else:
		scan_result=check_arping(inputedRange)
		print_result(scan_result)


"""Starting Point of the Program"""

if __name__ == "__main__":
	main()

