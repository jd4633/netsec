#!/usr/bin/env python3
from scapy.all import *

def print_pkt(recv_pkt):
    #recv_pkt.show()
    recv_ip = recv_pkt[IP]
    print(f"IP packet: ID: {recv_ip.id:5}  Protocol: {recv_ip.proto}  SRC: {recv_ip.src:15}  DST: {recv_ip.dst:15}")
    recv_icmp = recv_pkt[ICMP]
    print(f"ICMP payload: Type: {recv_icmp.type}")

    send_ip = IP()
    send_ip.src = recv_ip.dst
    send_ip.dst = recv_ip.src
    send_icmp = ICMP()
    send_icmp.type = 0
    send_icmp.id = recv_icmp.id
    send_icmp.seq = recv_icmp.seq
    send_load = recv_pkt.load
    send_pkt = send_ip/send_icmp/send_load
    send_pkt.show()
    send(send_pkt)

recv_pkt = sniff(iface='br-319968e99cab', filter='icmp and icmp[0]=8', prn=print_pkt)
