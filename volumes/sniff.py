#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
    #pkt.show()
    if (pkt.haslayer(IP)):
        ip = pkt[IP]
        print(f"IP packet: ID: {ip.id:5}  Protocol: {ip.proto}  SRC: {ip.src:15}  DST: {ip.dst:15}")
    if (pkt.haslayer(ICMP)):
        icmp = pkt[ICMP]
        print(f"ICMP payload: Type: {icmp.type}")
    if (pkt.haslayer(TCP)):
        tcp = pkt[TCP]
        print(f"TCP payload: sport: {tcp.sport}  dport: {tcp.dport}")
        #print(ls(tcp))

pkt = sniff(iface='br-9ead867344b5', filter='net 128.230', prn=print_pkt)
