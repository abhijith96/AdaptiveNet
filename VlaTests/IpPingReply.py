from scapy.all import sr1,sendp, sniff, send, Raw
from scapy.layers.inet6 import UDP, IPv6
from scapy.layers.l2 import Ether
from Utils import createIpPingReplyPacket, IP_PING_D_PORT
from NRUtils import getDefaultInterface



def custom_packet_filter(packet):
    # Check if the packet is an Ethernet frame
    if Ether not in packet:
        return False
    # Specify the desired destination MAC address
    if IPv6 in packet:
        if(UDP in packet):
            destination_port = packet[UDP].dport
            if(destination_port == IP_PING_D_PORT):
                return True


    # Check if the destination MAC address matches the desired value
    return False

interface = ""

def process_udp_packet(packet):
    if IPv6 in packet and UDP in packet:
        reply = "Ping Reply"
        # print("received packet is ", packet)
        modified_packet = createIpPingReplyPacket(packet, reply)
        # print("modified packet is ", modified_packet)
        sendp(modified_packet, iface=interface)  
    else:
        print("UnRecognized packet")



def pingListener(interfaceName):
    global interface
    interface = interfaceName
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