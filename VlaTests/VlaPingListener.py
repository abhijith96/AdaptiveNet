from scapy.all import sr1,sendp, sniff, send, Raw
from IPv6ExtHdrVLA import IPv6ExtHdrVLA
from scapy.all import packet
from scapy.layers.inet6 import UDP, IPv6, ICMPv6EchoRequest
from scapy.layers.l2 import Ether
from Utils import createVlaReplyPacket, VLA_PING_D_PORT, CreateVlaPingReplyPacket
from NRUtils import getDefaultInterface



def custom_packet_filter(packet):
    # Check if the packet is an Ethernet frame
    if Ether not in packet:
        return False
    # Specify the desired destination MAC address
    if IPv6 in packet:
        ipPayload = IPv6ExtHdrVLA(packet[Raw].load)
        # if(ICMPv6EchoRequest in ipPayload):
        #     return True
        # print("ip payload is ", ipPayload)
        if(UDP in ipPayload):
            destination_port = ipPayload[UDP].dport
            if(destination_port == VLA_PING_D_PORT):
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
            # Send the modified packet back
            sendp(modified_packet, iface=interface)  
            print("reply send")
        elif (ICMPv6EchoRequest in ipPayload):
            reply = "Ping Reply"
            modified_packet = CreateVlaPingReplyPacket(packet)
            # print("udp found , modified packet is ", modified_packet)
            # Send the modified packet bac
            sendp(modified_packet, iface=interface)  
            print("ping found , modified packet is ", modified_packet)
            print("reply send")
    else:
        print (packet.show())
        extension_header = IPv6ExtHdrVLA(packet[Raw].load)
        extension_header.show()
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