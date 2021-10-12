#!/usr/bin/env python3
from scapy.all import *
ip = IP()
ip.src = "8.8.8.8"
ip.dst = "10.9.0.7"
icmp = ICMP()
icmp.type = 8
pkt = ip/icmp
send(pkt)