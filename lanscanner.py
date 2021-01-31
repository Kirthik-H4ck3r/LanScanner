#! /usr/bin/python

import scapy.all as scapy
import optparse
import os
import pyfiglet 
  
result = pyfiglet.figlet_format("LanScanner") 
print(result + "\t\t\t\tMade by: Kirthik") 

def option_maker():
    parser = optparse.OptionParser()
    parser.add_option("-r","--range" , dest ="range" ,help = "Using -r & --range To Set The Range of IP")
    range_ip = parser.parse_args()[0]
    if not range_ip.range:
        parser.error("Specify Your IP Range using -r Flag")
    else:
        return range_ip.range

def send_packet(ip):
    result_lists = []
    packet = scapy.ARP(pdst = ip)
    dst_mac = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    ready = dst_mac/packet
    results = scapy.srp(ready ,timeout =1 ,verbose =False)[0]
    for result in results:
        result_dic = {"ip": result[1].psrc, "mac": result[1].hwsrc}
        result_lists.append(result_dic)
    return result_lists

def printing(results):
    print(" \n ALIVE IP's" + "\t\t\t" + "    MAC ADDRESS\n" + "__________________________________________________")
    for result in results:
        print(result["ip"] +"\t\t\t" +  result["mac"])
    print("__________________________________________________\n" +  ".......scanning Completed-Meet You Next Time......")

ip_range = option_maker()
answered = send_packet("192.168.43.1/24")
printing(answered)


