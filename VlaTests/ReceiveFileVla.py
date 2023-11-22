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
    if IPv6 in packet and packet[IPv6].nh == 48:
        ipPayload = IPv6ExtHdrVLA(packet[Raw].load)
        #print("ip payload is ", ipPayload)
        if(UDP in ipPayload):
            destination_port = ipPayload[UDP].dport
            if(destination_port == Utils.VLA_FILE_TRANSFER_D_PORT):
                return True


    # Check if the destination MAC address matches the desired value
    return False

def receive_file(output_file_path, listening_port):
    packets = sniff(filter=f'udp and port {listening_port}'.format(listening_port), count=0, iface=NRUtils.getDefaultInterface())
    file_data = b""
    for packet in packets:
        file_data += packet[Raw].load

    with open(output_file_path, 'wb') as output_file:
        output_file.write(file_data)

if __name__ == "__main__":
    output_file_path = "output_file.txt"
    # Choose a port to listen on
    receive_file(output_file_path, Utils.VLA_FILE_TRANSFER_D_PORT)