#!/usr/bin/env python3
from scapy.all import *

def print_pkt(recv_pkt):
    recv_pkt.show()
    recv_ip = pkt[IP]
    print(f"IP packet: ID: {recv_ip.id:5}  Protocol: {recv_ip.proto}  SRC: {recv_ip.src:15}  DST: {recv_ip.dst:15}")
    recv_icmp = pkt[ICMP]
    print(f"ICMP payload: Type: {icmp.type}")

    send_ip = IP()
    send_ip.src = recv_ip.dst
    send_ip.dst = recv_ip.src
    send_icmp = ICMP()
    send_icmp.type = 8
    send_pkt = send_ip/send_icmp
    send(send_pkt)

recv_pkt = sniff(iface='br-9ead867344b5', filter='icmp', prn=print_pkt)
