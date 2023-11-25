from tabnanny import verbose
from scapy.all import sr1,sendp, sniff, send, Raw, srp1
from scapy.layers.inet6 import UDP, IPv6, ICMPv6EchoRequest
from scapy.layers.l2 import Ether
from Utils import createIpPingReplyPacket, IP_PING_D_PORT, PING_COUNT
from NRUtils import getDefaultInterface, getDefaultMacAddress

count = PING_COUNT

interface = ""
macAddress = ""


count = 0
max_count = 5


def stop_filter(packet):
    global count
    global max_count
    count += 1
    return count >= max_count


def custom_packet_filter(packet):
    if Ether not in packet:
        return False
    if IPv6 in packet:
        if(ICMPv6EchoRequest in packet):
            # print(packet.show())
            return True
    return False


def process_udp_packet(packet):
    # if IPv6 in packet and I in packet:
        replyMessage = "Ping Reply"
        global interface
        modified_packet = createIpPingReplyPacket(packet, replyMessage)
        sendp(modified_packet, iface=interface, verbose=False)  
        # print("received packet is ", packet)
        # print("modified packet is ", modified_packet)
    # else:
    #     print("UnRecognized packet")



def pingListener(interfaceName):
    global interface
    interface = interfaceName
    global macAddress
    macAddress = getDefaultMacAddress()
    print(macAddress)
    # sniff(prn=process_udp_packet, lfilter=custom_packet_filter)
    #filter_expression = "udp and dst port {}".format(IP_PING_D_PORT)
    sniff(prn=process_udp_packet, lfilter = custom_packet_filter, count = PING_COUNT)
    return None

def main():
    ifaceStatus, ifaceName = getDefaultInterface()
    if(not ifaceStatus):
        print("No network interfaces found for device")
        return
    pingListener(ifaceName)

if __name__ == "__main__":
    main()