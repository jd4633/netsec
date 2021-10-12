from scapy.all import *

def print_pkt(pkt, ttl):
    print("got packet")
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
    #icmp = ICMP()
    #icmp.type = 8
    #pkt = ip/icmp
    udp = UDP()
    udp.sport = 33334
    udp.dport = 33333
    pkt = ip/udp/"ABCDE"
    pkt = sr1(pkt, timeout=2)
    if (pkt):
        print_pkt(pkt, ttl)
    else:
        print(f"{ttl:2}: *")

for ttl in range(1, 5):
    send_echo(ttl)
#pkt = sniff(iface='ens5', filter='icmp and dst host 172.31.7.91', prn=print_pkt, count=1)
