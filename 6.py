import logging
from scapy.all import *
from datetime import datetime

# Set up logging configuration
logging.basicConfig(filename='logs.log', level=logging.DEBUG)

# Define a function to analyze ping packets
def ping_monitor(pkt):
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        logging.info("%s Ping detected from source: %s (%s)", datetime.now(), pkt[Ether].src, pkt[IP].src)

# Define a function to analyze DNS packets
def dns_monitor(pkt):
    if pkt.haslayer(DNSQR):
        logging.info("%s DNS query detected from source: %s (%s) for: %s", datetime.now(), pkt[Ether].src, pkt[IP].src, pkt[DNSQR].qname.decode())

# Define a function to analyze ARP packets
def arp_monitor(pkt):
    if pkt.haslayer(ARP):
        logging.info("%s ARP request detected from source: %s (%s) for: %s", datetime.now(), pkt[Ether].src, pkt[ARP].psrc, pkt[ARP].pdst)

# Start capturing packets and analyzing them 
sniff(filter="icmp or udp port 53 or arp", prn=lambda x: ping_monitor(x) or dns_monitor(x) or arp_monitor(x))
