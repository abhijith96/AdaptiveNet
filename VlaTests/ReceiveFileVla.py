import Utils
import NRUtils
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, UDP
import socket
from scapy.all import *
from IPv6ExtHdrVLA import IPv6ExtHdrVLA
import os
import math

def get_time_in_milliseconds(current_time):
    milliseconds = int((current_time - int(current_time)) * 1000) 

    time_string = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(current_time)))
    time_with_milliseconds = "{}.{:03d}".format(time_string, milliseconds)
    return time_with_milliseconds

def count_bytes_in_file(file_path):
    try:
        file_size = os.path.getsize(file_path)
        return file_size
    except OSError as e:
        print("Error: {}".format(str(e)))
        return None

def custom_packet_filter(packet):
    if Ether not in packet:
        return False
    # Specify the desired destination MAC address
    #print(packet)
    if IPv6 in packet and packet[IPv6].nh == 48:
        #print(packet.show())
        ipPayload = IPv6ExtHdrVLA(packet[Raw].load)
       # print(ipPayload)
        if(UDP in ipPayload):
            #print("udp check")
            destination_port = ipPayload[UDP].dport
            if(destination_port == Utils.VLA_FILE_TRANSFER_D_PORT):
                return True


    # Check if the destination MAC address matches the desired value
    return False

def receive_file(output_file_path, listening_port):
    file_size = count_bytes_in_file(Utils.FILE_TRANSFER_SEND_FILE)
    count = 0
    if(file_size):
        count = int(math.ceil(file_size/1024.0))
    print("count is ", count)
    ifaceStatus, iface = NRUtils.getDefaultInterface()
    if(not ifaceStatus):
        return
    packets = sniff(lfilter=custom_packet_filter, count=count, iface=iface)
    file_data = b""
    endTime = time.time()
    print("End Time is ", get_time_in_milliseconds(endTime))
    for packet in packets:
        ipPayload = IPv6ExtHdrVLA(packet[Raw].load)
        file_data += ipPayload[Raw].load

    with open(output_file_path, 'wb') as output_file:
        output_file.write(file_data)

if __name__ == "__main__":
    output_file_path = Utils.FILE_TRANSFER_RECEIVE_FILE
    # Choose a port to listen on
    receive_file(output_file_path, Utils.VLA_FILE_TRANSFER_D_PORT)