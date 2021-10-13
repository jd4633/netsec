from scapy.all import *
import sys

def print_pkt(pkt, ttl):
    if (pkt.haslayer(IP)):
        ip = pkt[IP]
        src = ip.src
    if (pkt.haslayer(ICMP)):
        icmp = pkt[ICMP]
    print(f"{ttl:2}: {src}")

def send_echo(dest_ip, ttl):
    ip = IP()
    ip.dst = dest_ip
    ip.ttl = ttl
    icmp = ICMP()
    icmp.type = 8
    pkt = ip/icmp
    pkt = sr1(pkt, timeout=2, verbose=0)
    if (pkt):
        print_pkt(pkt, ttl)
        if (pkt.haslayer(IP)) and (pkt[IP].src == dest_ip):
            return True
    else:
        print(f"{ttl:2}: *")
    return False

dest_ip = sys.argv[1]
print(f"Generating traceroute to {dest_ip}")
ttl=1
reached_dest = False
while (ttl < 31 and not reached_dest):
    reached_dest = send_echo(dest_ip, ttl)
    ttl = ttl + 1
