from scapy.all import  Raw
from scapy.layers.inet6 import UDP, IPv6
from scapy.layers.l2 import Ether
from IPv6ExtHdrVLA import IPv6ExtHdrVLA


def createIPPacket(eth_dst, eth_src,ipv6_src, ipv6_dst, data_payload):
    pktlen = 100
    ipv6_tc = 0
    ipv6_fl = 0
    ipv6_hlim = 64
    udp_sport = 50000
    udp_dport = 50001
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
        # len=(sid_len * 2) + (source_vla_list_len * 2) + 1,
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

def createVlaReplyPacket(vlaPacket, replyPayload):
    ipPayload = IPv6ExtHdrVLA(vlaPacket[Raw].load)
    if(UDP in ipPayload):
        source_ip = vlaPacket[IPv6].dst
        dest_ip = vlaPacket[IPv6].src
        source_port = ipPayload[UDP].dport
        destination_port = ipPayload[UDP].sport
        payload = ipPayload[UDP].payload
        source_vla =  ipPayload[IPv6ExtHdrVLA].addresses
        dest_vla = ipPayload[IPv6ExtHdrVLA].source_addresses
        reply_current_level =  ipPayload[IPv6ExtHdrVLA].current_level - 1
        ethSource = vlaPacket[Ether].dst
        ethDst = vlaPacket[Ether].src

        modified_packet = createIPPacket(ethDst, ethSource, source_ip, dest_ip, replyPayload)
        modified_packet = insert_vla_header(modified_packet, dest_vla, source_vla, reply_current_level)

        return modified_packet