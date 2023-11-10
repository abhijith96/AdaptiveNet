
import os
import sys

sys.path.insert(0, os.path.join(os.getcwd(), 'lib'))

from scapy.all import *
from scapy.layers.inet6 import UDP
import IPv6ExtHdrVLA


def print_packet(packet):
    if packet.haslayer(UDP):
        print(packet[UDP].load)
    if packet.haslayer(IPv6ExtHdrVLA):
        print(packet[IPv6ExtHdrVLA].summary())
    
    print(packet.summary())

  

def print_packet(packet):
    packet.show()

# Sniff IPv6 packets on interface eth0
sniff(filter="ip6", prn=print_packet, iface="h4-eth0")