from scapy.all import sr1,sendp, sniff, send, Raw
from scapy.layers.inet6 import UDP, IPv6
from scapy.layers.l2 import Ether
from Utils import createIpPingReplyPacket, IP_PING_D_PORT
from NRUtils import getDefaultInterface, getDefaultMacAddress

interface = ""
macAddress = ""

def custom_packet_filter(packet):
    if Ether not in packet:
        return False
    global macAddress
    if(packet[Ether].dst == macAddress):
        if IPv6 in packet:
            print(packet.show())
            if(UDP in packet):
                destination_port = packet[UDP].dport
                if(destination_port == 40001):
                    print("filter success")
                    return True
                else:
                    print("Invalid UDP port")
            elif packet[IPv6].nh == 17:
                payload = packet[IPv6].payload()
                udpP = UDP(payload)
                return udpP.dport == 40001
    return False


def process_udp_packet(packet):
    if IPv6 in packet and UDP in packet:
        reply = "Ping Reply"
        print("received packet is ", packet)
        modified_packet = createIpPingReplyPacket(packet, reply)
        print("modified packet is ", modified_packet)
        sendp(modified_packet, iface=interface)  
    else:
        print("UnRecognized packet")



def pingListener(interfaceName):
    global interface
    interface = interfaceName
    global macAddress
    macAddress = getDefaultMacAddress()
    print(macAddress)
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