from scapy.all import sr1, sniff, send
from IPv6ExtHdrVLA import IPv6ExtHdrVLA
from scapy.all import packet
from scapy.layers.inet6 import UDP, IPv6
from scapy.layers.l2 import Ether

def createIPPacket(eth_dst, eth_src,ipv6_src, ipv6_dst, data_payload):
    pktlen = 100
    ipv6_tc = 0
    ipv6_fl = 0
    ipv6_hlim = 64
    udp_sport = 50000
    udp_dport = 50001
    with_udp_chksum = True
    pkt = Ether(dst=eth_dst, src=eth_src)
    pkt /= IPv6(
        src=ipv6_src, dst=ipv6_dst, fl=ipv6_fl, tc=ipv6_tc, hlim=ipv6_hlim
    )
    if with_udp_chksum:
        pkt /= UDP(sport=udp_sport, dport=udp_dport)
    else:
        pkt /= UDP(sport=udp_sport, dport=udp_dport, chksum=0)
    if data_payload:
        pkt = pkt / data_payload
    pkt /= "D" * (pktlen - len(pkt))
    return pkt

def createVlaPacket(ethDst, ethSrc, srcVlaAddrList, dstVlaAddrList, vlaCurrentLevel, data_payload = None):
    ip_src = "::1"
    ip_dst = "::2"
    pkt = createIPPacket(ethDst, ethSrc, ip_src, ip_dst, data_payload)
    insert_vla_header(pkt,dstVlaAddrList, srcVlaAddrList, vlaCurrentLevel)
    return pkt

def insert_vla_header(pkt, destination_vla_list, source_vla_list, current_level_param):
    """Applies Vla header to an Ipv6 packet.
    """
    # Set IPv6 dst to some valid IPV6 Address
    # Insert VLA header between IPv6 header and payload
    vla_dst_len = len(destination_vla_list)
    source_vla_list_len = len(source_vla_list)
    vla_hdr = IPv6ExtHdrVLA(
        nh=pkt[IPv6].nh,
        addresses=destination_vla_list,
        source_addresses = source_vla_list,
        len=(vla_dst_len * 2) + (source_vla_list_len * 2) + 1,
        address_type = 0b01,
        current_level = current_level_param,
        number_of_levels= vla_dst_len,
        number_of_source_levels = source_vla_list_len
        )
    pkt[IPv6].nh = 48  # next IPv6 header is VLA header
    pkt[IPv6].payload = vla_hdr / pkt[IPv6].payload
    return pkt



def process_udp_packet(packet):
    if IPv6 in packet and UDP in packet:
        # Extract relevant information from the received packet
        source_ip = packet[IPv6].src
        dest_ip = packet[IPv6].dst
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
        payload = packet[UDP].payload

        source_vla =  packet[IPv6ExtHdrVLA].source_addresses
        dest_vla = packet[IPv6ExtHdrVLA].addresses
        current_level =  packet[IPv6ExtHdrVLA].current_level

        modified_packet = createIPPacket(packet[Ether].dst, packet[Ether].src, source_ip, dest_ip, payload)
        packet[UDP].sport = destination_port
        packet[UDP].dport = source_port

        modified_packet = insert_vla_header(packet, source_vla, dest_vla, current_level - 1)
        # Send the modified packet back
        send(modified_packet, verbose=False)
        print("Replied to UDP packet from %s : %s with modified ports.", source_ip, source_port)
    else:
        print("UnRecognized packet")



def pingListner():
    # Create an IP packet with an ICMP Echo Request
    target_udp_port = 50001
    # Start sniffing for UDP packets on the specified port
    sniff(filter="udp and port {}".format(target_udp_port), prn=process_udp_packet, store=0)    
    return None

def main():
    pingListner()

if __name__ == "__main__":
    main()