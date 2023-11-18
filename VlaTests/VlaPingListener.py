from scapy.all import sr1,sendp, sniff, send, Raw
from IPv6ExtHdrVLA import IPv6ExtHdrVLA
from scapy.all import packet
from scapy.layers.inet6 import UDP, IPv6
from scapy.layers.l2 import Ether
from Utils import createVlaReplyPacket
from NRUtils import getDefaultInterface

PING_LISTEN_PORT = 50001

def custom_packet_filter(packet):
    # Check if the packet is an Ethernet frame
    if Ether not in packet:
        return False
    # Specify the desired destination MAC address
    if IPv6 in packet:
        ipPayload = IPv6ExtHdrVLA(packet[Raw].load)
        if(UDP in ipPayload):
            destination_port = ipPayload[UDP].dport
            if(destination_port == PING_LISTEN_PORT):
                return True


    # Check if the destination MAC address matches the desired value
    return False

interface = ""

def process_udp_packet(packet):
    if IPv6 in packet and UDP in packet:
        reply = "Ping Reply"
        modified_packet = createVlaReplyPacket(packet, reply)
        sendp(modified_packet, iface=interface)  
    elif IPv6 in packet and packet[IPv6].nh == 48:
        # Extract relevant information from the received packet
        ipPayload = IPv6ExtHdrVLA(packet[IPv6].payload)
        if(UDP in ipPayload):
            reply = "Ping Reply"
            modified_packet = createVlaReplyPacket(packet, reply)
            # print("udp found , modified packet is ", modified_packet)
            # Send the modified packet back
            sendp(modified_packet, iface=interface)  
            print("reply send")
    else:
        print (packet.show())
        extension_header = IPv6ExtHdrVLA(packet[Raw].load)
        extension_header.show()
        print("UnRecognized packet")



def pingListener(interfaceName):
    global interface
    interface = interfaceName
    target_udp_port = PING_LISTEN_PORT
    sniff(prn=process_udp_packet, lfilter=custom_packet_filter)
    return None

def main():
    ifaceStatus, ifaceName = getDefaultInterface()
    if(not ifaceStatus):
        print("No network interfaces found for device")
        return
    pingListener(ifaceName)

if __name__ == "__main__":
    main()