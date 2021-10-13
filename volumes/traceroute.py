from scapy.all import *

def print_pkt(pkt, ttl):
    if (pkt.haslayer(IP)):
        ip = pkt[IP]
        src = ip.src
    if (pkt.haslayer(ICMP)):
        icmp = pkt[ICMP]
    print(f"{ttl:2}: {src}")

def send_echo(ttl):
    ip = IP()
    ip.dst = "8.8.8.8"
    ip.ttl = ttl
    icmp = ICMP()
    icmp.type = 8
    pkt = ip/icmp
    pkt = sr1(pkt, timeout=2, verbose=0)
    if (pkt):
        print_pkt(pkt, ttl)
        if (pkt.haslayer(IP)) and (pkt[IP].src == "8.8.8.8"):
            return True
    else:
        print(f"{ttl:2}: *")
    return False

ttl=1
reached_dest = False
while (ttl < 31 and not reached_dest):
    reached_dest = send_echo(ttl)
    ttl = ttl + 1
