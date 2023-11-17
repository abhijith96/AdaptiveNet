from scapy.all import sr1,sendp, sniff, send, Raw
from IPv6ExtHdrVLA import IPv6ExtHdrVLA
from scapy.all import packet
from scapy.layers.inet6 import UDP, IPv6
from scapy.layers.l2 import Ether
from Utils import createVlaReplyPacket


def custom_packet_filter(packet):
    # Check if the packet is an Ethernet frame
    if Ether not in packet:
        return False
    # Specify the desired destination MAC address
    if IPv6 in packet:
        ipPayload = IPv6ExtHdrVLA(packet[Raw].load)
        if(UDP in ipPayload):
            destination_port = ipPayload[UDP].dport
            if(destination_port == 50001):
                return True


    # Check if the destination MAC address matches the desired value
    return False

interface = "h1c-eth0"

def process_udp_packet(packet):
    if IPv6 in packet and UDP in packet:
        print("cool pass")
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



def pingListner():
    # Create an IP packet with an ICMP Echo Request
    target_udp_port = 50001
    #interface = "h1c-eth0"
    # Start sniffing for UDP packets on the specified port
    #sniff(filter="ip6", prn=process_udp_packet, iface=interface, count = 1)
    sniff(prn=process_udp_packet, lfilter=custom_packet_filter)
    #sniff(filter="udp and port {}".format(target_udp_port), prn=process_udp_packet, count = 1)    
    return None

def main():
    pingListner()

if __name__ == "__main__":
    main()