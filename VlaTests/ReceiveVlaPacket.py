
import os
import sys

sys.path.insert(0, os.path.join(os.getcwd(), 'lib'))

from scapy.all import *
from scapy.layers.inet6 import UDP, IPv6
from IPv6ExtHdrVLA import IPv6ExtHdrVLA


def print_packet(packet):
    print(packet.show())
    print("packet  vla hex dump ", packet)
    if packet.haslayer(IPv6):
       payload = packet[Raw]
       vlapk = IPv6ExtHdrVLA(payload)
       print(vlapk)
    if packet.haslayer(IPv6ExtHdrVLA):
        print(packet[IPv6ExtHdrVLA].summary())
    
   


# Sniff IPv6 packets on interface eth0
def getInterfaceToListenOn():
    try:
        interface = sys.argv[1]
        return interface
    except Exception():
        raise Exception("Pass Interface name to listen on as command line argument")
def main():
   interface = getInterfaceToListenOn()
   sniff(filter="ip6", prn=print_packet, iface=interface)

if __name__ == "__main__":
    main()