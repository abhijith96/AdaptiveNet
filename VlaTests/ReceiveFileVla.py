import Utils
import NRUtils
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, UDP
import socket
from scapy.all import *
from IPv6ExtHdrVLA import IPv6ExtHdrVLA

def custom_packet_filter(packet):
    if Ether not in packet:
        return False
    # Specify the desired destination MAC address
    #print(packet)
    if IPv6 in packet and packet[IPv6].nh == 48:
        print(packet.show())
        ipPayload = IPv6ExtHdrVLA(packet[Raw].load)
        print(ipPayload)
        if(UDP in ipPayload):
            print("udp check")
            destination_port = ipPayload[UDP].dport
            if(destination_port == Utils.VLA_FILE_TRANSFER_D_PORT):
                return True


    # Check if the destination MAC address matches the desired value
    return False

def receive_file(output_file_path, listening_port):
    ifaceStatus, iface = NRUtils.getDefaultInterface()
    if(not ifaceStatus):
        return
    packets = sniff(lfilter=custom_packet_filter, count=0, iface=iface)
    file_data = b""
    print(packets)
    for packet in packets:
        ipPayload = IPv6ExtHdrVLA(packet[Raw].load)
        file_data += ipPayload[Raw].load

    with open(output_file_path, 'wb') as output_file:
        output_file.write(file_data)

if __name__ == "__main__":
    output_file_path = "output_file.txt"
    # Choose a port to listen on
    receive_file(output_file_path, Utils.VLA_FILE_TRANSFER_D_PORT)