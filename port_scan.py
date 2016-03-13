#!/usr/bin/env

#imports
import logging
#finetuning error logs to not show some messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
#import itertools
#import thread
import sys
import getopt
import re
from netaddr import *

#example command - sudo python port_scan.py -s 192.168.207.121,192.168.207.122 -t TCP -p 22,80,445,8080
# Pull commandline arguments
def main(argv):
	#variables for port scanner
	ports_arg = ""
	scantype_arg = ""
	hosts_arg = ""
	hosts_prior = ""
	hosts = IPSet()
	hosts_up = IPSet()
	ports = []
	open_ports = []

	#attempt to pull the arguments
	try:
		#setup the flag options which are - 
		# -s for target IP address
		# -p for target ports
		# -h for help
		# -i for ICMP scan
		# -t for TCP scan
		# -u for UDP scan
		opts, args = getopt.getopt(argv, "hs:p:iTtu", ["scanTarget=", "ports="])
	#catch exceptions
	except getopt.GetoptError:
		print '\n\npython port_scan.py -s <target IP address(es)> -p <ports> -(t(TCP)|u(UDP))\n---\npython port_scan.py -s <target IP address(es)> -(i(ICMP)|T(traceroute))'
		sys.exit(2)

	#iterate through arguments pulling info from options
	for opt, arg in opts:
		#help
		if opt == '-h':
			print '\n-------------------------------------------------------------------\npython port_scan.py -s <target IP address(es)> -p <ports> -(t(TCP)|u(UDP))\n-------------------------------------------------------------------\npython port_scan.py -s <target IP address(es)> -(i(ICMP)|T(traceroute))\n-------------------------------------------------------------------\n\n-s A single IP address (i.e. - 111.111.111.111), multiple IP addresses separated by commas with no spaces (i.e. - 111.111.111.111,222.222.222.115,333.333.333.118), a range of IP addresses to scan (i.e. - 111.111.111.111-199), or a subnet of IP addresses to scan (i.e. - 111.111.111.0/24)\n-p Can be a single port num, a list separated by commas with no spaces, or a range of numbers - i.e. 123-400\n-i ICMP scan checking if hosts are up\n-T traceroute for following target IPs\n-t TCP scan, uses ICMP first to check for active hosts then runs TCP scan on specified ports\n-u UDP scan, uses ICMP first to check for active hosts then runs UDP scan on specified ports\n\n'
			sys.exit()
		#save argument for saving target IP
		elif opt in ("-s", "--scanTarget"):
			
			hosts_arg = arg

			#check for hosts
			if (hosts_arg == ""):
				print '\n\nMissing hosts!\n\n-------------------------------------------------------------------\npython port_scan.py -(t(TCP)|u(UDP))-s <target IP address(es)> -p <ports>\n-------------------------------------------------------------------\npython port_scan.py -i(ICMP) -s <target IP address(es)>\n-------------------------------------------------------------------\n'
				sys.exit()

			#call host parsing method and return resulting IP set
			hosts = ip_parsing(hosts_arg)

		#save argument for ports to scan
		elif opt in ("-p", "--ports"):
			ports_arg = arg
			ports = port_parsing(ports_arg)
		#ICMP scan
		elif opt == '-i':
			scantype_arg = "ICMP"
		elif opt == '-T':
			scantype_arg = "TRACE"
		#TCP scan
		elif opt == '-t':
			scantype_arg = "TCP"
		#UDP scan
		elif opt == '-u':
			scantype_arg = "UDP"

	#check for live hosts
	hosts = check_host(hosts)
		
	#for TCP or UDP run through ports etc
	if (scantype_arg == "TCP") or (scantype_arg == "UDP"):
		if(ports_arg == ""):
			print "\nUDP and TCP requires ports!  Please retry the command with specified ports - \npython port_scan.py -(t|u) -s <sources> -p <ports>"
			sys.exit()
		#go through hosts and ports
		open_ports = port_scanner(hosts,ports,scantype_arg)

		print_live_hosts(hosts)
		print "\n\n**************************\nList of open ports found:"
		for oPort in open_ports:
			print oPort
		print "**************************\n"
	elif scantype_arg == "TRACE":
		trace(hosts)
	else:
		print_live_hosts(hosts)
	


#print out live host list
def print_live_hosts(live_hosts):
	#print out hosts
	print "\n\n***********LIVE HOSTS LIST***********"
	for host in live_hosts:
		print "--" + str(host)
	print "\n\n*************************************"

#port scanner
def port_scanner(host_list,port_list,protocol):
	#value to store data
	temp_output = []
	#run through hosts and ports scanning each port
	for host in host_list:
		for port in port_list:
			print "Host " + str(host) + " port " + str(port)
			result = scanner_TCP_UDP(host,port,protocol)
			if result != "closed":
				temp_output.append("Host " + str(host) + " - " + protocol + " port " + str(port) + " is " + result)

	#return temp list
	return temp_output


#check if host is up
def check_host(host_list):
	#use ICMP ping to see if host is up
	hosts_temp = "\n\n***********INITIAL HOSTS LIST***********\n"
	for host in host_list:
		hosts_temp += "--" + str(host) + "\n"
		if scanner_ICMP(host) == False:
			host_list.remove(host)
	#return list
	#print hosts_temp
	return host_list

#Get IP addresses
def ip_parsing(ip_string):
	#regular expressions checking for CIDR or ip range
	regex_CIDR = "^\d+\.\d+\.\d+\.\d+\/\d+$"
	regex_IPrange = "^(\d+\.\d+\.\d+\.)(\d+)\-(\d+)$"
	
	#initializing IPSet variable
	IP_list = IPSet()

	#if CIDR addressing is used
	if re.match(regex_CIDR, ip_string) is not None:
		print "IP input matched CIDR regex!!\n"
		
		IP_list = IPSet([ip_string])
	#if IP range is used
	elif re.match(regex_IPrange, ip_string) is not None:
		IP_values = re.search(regex_IPrange, ip_string)
		print "IP input matched IP range regex!\n"
		print "captured groups for IP range are - "
		print "  " + IP_values.group(0)
		IP_3octets = IP_values.group(1)
		IP_min_range = int(IP_values.group(2))
		IP_max_range = int(IP_values.group(3))
		#input('values for IP range')

		#iterate through range adding values to IP list
		for x in range (IP_min_range, IP_max_range + 1):
			IP_list.add(IP_3octets + str(x))
	#if IP is a single or comma separated list
	else:
		for x in ip_string.split(','):
			IP_list.add(x)


	return IP_list



#Get ports to scan
def port_parsing(port_string):
	#regex to check for port range
	regex_range = "^(\d+)-(\d+)$"
	port_list = []
	
	#parse range
	if re.match(regex_range, port_string) is not None:
		
		#pull values from string
		port_values = re.search(regex_range, port_string)
		print "matched port range regex"
		
		#save min and max ports
		port_min = int(port_values.group(1))
		port_max = int(port_values.group(2))

		#iterate through the range adding to port list
		for x in range (port_min, port_max):
			port_list.append(x)
	else:
		#pull comma separated values or single port
		port_list = [int(x) for x in port_string.split(',')]

	#return port list
	return port_list


#ICMP scanner
def scanner_ICMP(target_IP):
	print "\nICMP scan starting on host " + str(target_IP)

	#ICMP packet scan
	scan = sr1(IP(dst=str(target_IP))/ICMP(), timeout=10)

	#if scan comes back empty return false
	if scan is None:
		print "\nHost " + str(target_IP) + " appears to be down!"
		return False
	#if scan comes back with response return true
	else:
		print "\nHost " + str(target_IP) + " appears to be up!"
		return True


#TCP scanner
def scanner_TCP_UDP(target_IP, target_port, scantype):

	#if TCP
	if scantype == "TCP":

		print "-Scanning host " + str(target_IP) + " port " + str(target_port) + " using TCP"

		#random source port
		source_port = RandShort()

		#send TCP packet
		scan = sr1(IP(dst=str(target_IP))/TCP(sport=source_port,dport=target_port,flags="S"),timeout=10)

		#if scan comes back empty return false
		if scan is None:
			print "-TCP port " + str(target_port) + " is closed"
			return "closed"
		#if scan comes back with response and flag is true return true
		elif (scan.haslayer(TCP)):
			if(scan.getlayer(TCP).flags==0x12):
				print "-TCP port " + str(target_port) + " is open"

				RST = sr(IP(dst=str(target_IP))/TCP(sport=source_port,dport=target_port,flags='AR'),timeout=10)

				return "open"
			#if flags = 0x14
			elif(scan.getlayer(TCP).flags==0x14):
				return "closed"
		else:
			return "*check*"
	#if UDP
	elif scantype == "UDP":
		print "-Scanning host " + str(target_IP) + " port " + str(target_port) + " using UDP"		
	
		#send UDP packet
		scan = sr1(IP(dst=str(target_IP))/UDP(dport=target_port),timeout=10)
		#if there is a response
		if scan is not None:
			#if response has UDP layer
			if(scan.haslayer(UDP)):
				#return open value
				return "open"
			#if response has ICMP layer
			if(scan.haslayer(ICMP)):
				#check for error type and code
				#if the type is 3
				if(scan.getlayer(ICMP).type == 3):
					#if the code is 3
					if(scan.getlayer(ICMP).code == 3):
						#return closed
						return "closed"
					elif(scan.getlayer(ICMP).code in [1,2,9,10,13]):
						#return filtered
						return "filtered"
		#if the scan had no response
		elif scan is None:
			#list to store the retry attempts
			resend_packets = []

			#for loop to try resending the packet several times
			for x in range(0,3):
				#add packet response to list
				resend_packets.append(sr1(IP(dst=str(target_IP))/UDP(dport=target_port),timeout=10))
			#for loop to check responses to packets
			for response in resend_packets:
				#if there was a response
				if response is not None:
					#resend data to get response
					scanner_TCP_UDP(target_IP, target_port, scantype)
			#return open|filtered for uncertain response
			return "open|filtered"

		#otherwise
		else:
			#return error message because this should never happen
			return "unknown state"

#traceroute method
def trace(target_list):
	#print list of live hosts
	print_live_hosts(target_list)
	#for loop to run traceroute for each live IP
	for ip in target_list:
		
		print traceroute(str(ip),maxttl=10)



if __name__ == "__main__":
	main(sys.argv[1:])