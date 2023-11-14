from scapy.all import sr1,sendp, sniff, send, Raw
from IPv6ExtHdrVLA import IPv6ExtHdrVLA
from scapy.all import packet
from scapy.layers.inet6 import UDP, IPv6
from scapy.layers.l2 import Ether

def createIPPacket(eth_dst, eth_src,ipv6_src, ipv6_dst, data_payload, udp_sport, udp_dport):
    pktlen = 100
    ipv6_tc = 0
    ipv6_fl = 0
    ipv6_hlim = 64
    with_udp_chksum = True
    # pkt = Ether(dst=eth_dst, src=eth_src)
    # pkt /= IPv6(
    #     src=ipv6_src, dst=ipv6_dst, fl=ipv6_fl, tc=ipv6_tc, hlim=ipv6_hlim
    # )
    pkt = Ether(src=eth_src, dst=eth_dst)/IPv6(src=ipv6_src, dst=ipv6_dst)/UDP(sport = udp_sport, 
                                                                               dport = udp_dport)/Raw(load=data_payload)
    # if with_udp_chksum:
    #     pkt /= UDP(sport=udp_sport, dport=udp_dport)
    # else:
    #     pkt /= UDP(sport=udp_sport, dport=udp_dport, chksum=0)
    
    # if data_payload:
    #     pkt = pkt / data_payload
    # pkt /= "D" * (pktlen - len(pkt))
    return pkt

def insert_vla_header(pkt, sid_list, source_vla_list, current_level_param):
    """Applies Vla header to an Ipv6 packet.
    """
    # Set IPv6 dst to some valid IPV6 Address
    # Insert VLA header between IPv6 header and payload
    sid_len = len(sid_list)
    source_vla_list_len = len(source_vla_list)
    vla_hdr = IPv6ExtHdrVLA(
        nh=pkt[IPv6].nh,
        addresses=sid_list,
        source_addresses = source_vla_list,
        len=(sid_len * 2) + (source_vla_list_len * 2) + 1,
        address_type = 0b01,
        current_level = current_level_param,
        number_of_levels= sid_len,
        number_of_source_levels = source_vla_list_len
        )
    pkt[IPv6].nh = 48  # next IPv6 header is VLA header
    pkt[IPv6].payload = vla_hdr / pkt[IPv6].payload
    return pkt

def createVlaPacket(ethDst, ethSrc, srcVlaAddrList, dstVlaAddrList, vlaCurrentLevel, data_payload = None):
    ip_src = "::1"
    ip_dst = "::2"
    pkt = createIPPacket(ethDst, ethSrc, ip_src, ip_dst, data_payload)
    pkt = insert_vla_header(pkt,dstVlaAddrList, srcVlaAddrList, vlaCurrentLevel)
    return pkt



def process_udp_packet(packet):
    if IPv6 in packet and UDP in packet:
        print("cool pass")
    elif IPv6 in packet:
        # Extract relevant information from the received packet
        ipPayload = IPv6ExtHdrVLA(packet[Raw].load)
        if(UDP in ipPayload):
            source_ip = packet[IPv6].src
            dest_ip = packet[IPv6].dst

            source_port = ipPayload[UDP].sport
            destination_port = ipPayload[UDP].dport
            payload = ipPayload[UDP].payload

            source_vla =  ipPayload[IPv6ExtHdrVLA].source_addresses
            dest_vla = ipPayload[IPv6ExtHdrVLA].addresses
            current_level =  ipPayload[IPv6ExtHdrVLA].current_level

            modified_packet = createIPPacket(packet[Ether].src, packet[Ether].dst, dest_ip, source_ip, "Reply", destination_port, source_port)
            # modified_packet[UDP].sport = destination_port
            # modified_packet[UDP].dport = source_port

            modified_packet = insert_vla_header(modified_packet, source_vla, dest_vla, current_level)
            print("modified packet is ", modified_packet)
            # Send the modified packet back
            sendp(modified_packet, iface="h3-eth0")  
            print("Replied to UDP packet from %s : %s with modified ports.", source_ip, source_port)
    else:
        print (packet.show())
        extension_header = IPv6ExtHdrVLA(packet[Raw].load)

# Print the details of the extracted IPv6 Extension Header VLA
        extension_header.show()
        print("UnRecognized packet")



def pingListner():
    # Create an IP packet with an ICMP Echo Request
    target_udp_port = 50001
    interface = "h3-eth0"
    # Start sniffing for UDP packets on the specified port
    sniff(filter="ip6", prn=process_udp_packet, iface=interface)
    #sniff(filter="udp and port {}".format(target_udp_port), prn=process_udp_packet, store=0)    
    return None

def main():
    pingListner()

if __name__ == "__main__":
    main()