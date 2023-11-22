import Utils
import NRUtils


import socket
from scapy.all import *

def receive_file(output_file_path, listening_port):
    packets = sniff(filter=f'udp and port {listening_port}', count=0, iface=NRUtils.getDefaultInterface())
    file_data = b""
    for packet in packets:
        file_data += packet[Raw].load

    with open(output_file_path, 'wb') as output_file:
        output_file.write(file_data)

if __name__ == "__main__":
    output_file_path = "output_file.txt"
    listening_ip = "0.0.0.0"  # Listen on all available interfaces
    listening_port = 12345  # Choose a port to listen on

    receive_file(output_file_path, Utils.VLA_FILE_TRANSFER_D_PORT)