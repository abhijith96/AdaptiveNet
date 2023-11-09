from scapy.all import *

def print_packet(packet):
    packet.show()

# Sniff IPv6 packets on interface eth0
sniff(filter="ip6", prn=print_packet, iface="eth0")