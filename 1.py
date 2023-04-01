import logging
from scapy.all import *

# Set up logging configuration
logging.basicConfig(filename='example.log', level=logging.DEBUG)

# Define a function to analyze ping packets
def ping_monitor(pkt):
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        logging.info("Ping detected from source: %s", pkt[IP].src)

# Define a function to analyze DNS packets
def dns_monitor(pkt):
    if pkt.haslayer(DNSQR):
        logging.info("DNS query detected for: %s", pkt[DNSQR].qname.decode())

# Define a function to analyze HTTP packets
def http_monitor(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        if b"GET" in pkt[Raw].load:
            logging.info("HTTP GET request detected from source: %s", pkt[IP].src)

# Start capturing packets and analyzing them
sniff(filter="icmp or udp port 53 or tcp port 80", prn=lambda x: ping_monitor(x) or dns_monitor(x) or http_monitor(x))
