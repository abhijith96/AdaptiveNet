from scapy.all import  Raw
from scapy.layers.inet6 import UDP, IPv6
from scapy.layers.l2 import Ether
from IPv6ExtHdrVLA import IPv6ExtHdrVLA
from scapy.all import conf
from scapy.all import get_if_addr6, get_if_hwaddr, get_if_list

VLA_PING_S_PORT = 45000
VLA_PING_D_PORT = 45001

IP_PING_S_PORT = 41100
IP_PING_D_PORT = 41101

VLA_FILE_TRANSFER_S_PORT = 42000
VLA_FILE_TRANSFER_D_PORT = 42001

IP_FILE_TRANSFER_S_PORT = 43000
IP_FILE_TRANSFER_D_PORT = 43001

FILE_TRANSFER_SEND_FILE = "sample-file.txt"
FILE_TRANSFER_RECEIVE_FILE = "output-file.txt"



def createIPPacketforVla(eth_dst, eth_src,ipv6_src, ipv6_dst, data_payload, vlaSrc, vlaDst, vlaCurrentLevel, udp_sport = VLA_PING_S_PORT, udp_dport = VLA_PING_D_PORT):
    pktlen = 100
    ipv6_tc = 0
    ipv6_fl = 0
    ipv6_hlim = 64
    with_udp_chksum = True
    # pkt = Ether(dst=eth_dst, src=eth_src)
    # pkt /= IPv6( 
    #     src=ipv6_src, dst=ipv6_dst, fl=ipv6_fl, tc=ipv6_tc, hlim=ipv6_hlim
    # )

    
    vla_dst_len = len(vlaDst)
    vla_src_len = len(vlaSrc)
    padlen = 8 - ((2*(vla_dst_len + vla_src_len))%8)
    paddlistContent = list(range(padlen))

    pkt = Ether(src=eth_src, dst=eth_dst)/IPv6(nh = 48,src=ipv6_src, dst=ipv6_dst)/IPv6ExtHdrVLA(nh=17, 
        addresses=vlaDst, source_addresses = vlaSrc,address_type=0b01, current_level = vlaCurrentLevel, number_of_levels=vla_dst_len,
         number_of_source_levels = vla_src_len, pad_list_length=padlen, pad_list= paddlistContent)/UDP(sport = udp_sport,dport = udp_dport)/Raw(load=data_payload)
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
        len = None,
        # len=(sid_len * 2) + (source_vla_list_len * 2) + 1,
        address_type = 0b01,
        current_level = current_level_param,
        number_of_levels= sid_len,
        number_of_source_levels = source_vla_list_len
        )
    pkt[IPv6].nh = 48  # next IPv6 header is VLA header
    pkt[IPv6].payload = vla_hdr / pkt[IPv6].payload
    return pkt

# def insert_vla_header(pkt, sid_list, source_vla_list, current_level_param):
#     """Applies SRv6 insert transformation to the given packet.
#     """
#     # Set IPv6 dst to some valid IPV6 Address
#     pkt[IPv6].dst = HOST2_IPV6
#     # Insert VLA header between IPv6 header and payload
#     sid_len = len(sid_list)
#     source_vla_list_len = len(source_vla_list)
#     vla_hdr = IPv6ExtHdrVLA(
#         nh=pkt[IPv6].nh,
#         addresses=sid_list,
#         source_addresses = source_vla_list,
#         # len=(sid_len * 2) + (source_vla_list_len * 2) + 1,
#         len = None,
#         address_type = 0b01,
#         current_level = current_level_param,
#         number_of_levels= sid_len,
#         number_of_source_levels = source_vla_list_len
#         )
#     pkt[IPv6].nh = 48  # next IPv6 header is VLA header
#     pkt[IPv6].payload = vla_hdr / pkt[IPv6].payload
#     return pkt

def createVlaPacket(ethDst, ethSrc, srcVlaAddrList, dstVlaAddrList, vlaCurrentLevel, data_payload = None):
    ip_src = "::2"
    # ip_dst = "::2"
    ip_dst = "::2"
    pkt = createIPPacketforVla(ethDst, ethSrc, ip_src, ip_dst, data_payload, srcVlaAddrList, dstVlaAddrList, vlaCurrentLevel)
    #pkt = insert_vla_header(pkt,dstVlaAddrList, srcVlaAddrList, vlaCurrentLevel)
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

        modified_packet = createIPPacketforVla(ethDst, ethSource,source_ip, dest_ip, replyPayload, source_vla, dest_vla, reply_current_level, source_port, destination_port)
       # modified_packet = insert_vla_header(modified_packet, dest_vla, source_vla, reply_current_level)

        return modified_packet


def getMacAddress():
    ifacelist = get_if_list()
    mac = get_if_hwaddr(ifacelist[1])
    return mac

def createIpPingPacket(ethsrc, gateway_eth, ip_src, ip_dst, udp_sport = IP_PING_S_PORT, udp_dport = IP_PING_D_PORT):
    msg = "Ping Hello"
    #pkt = Ether(src=ethsrc, dst=gateway_eth)/IPv6(src=ip_src, dst = ip_dst)/UDP(sport= udp_sport, dport = udp_dport)/Raw(load=msg)
    pkt = IPv6(dst = ip_dst)/UDP(sport= udp_sport, dport = udp_dport)/Raw(load=msg)
    return pkt

def createIpUdpFilePacket(ethsrc, gateway_eth, ip_src, ip_dst, dataPayload, udp_sport = IP_FILE_TRANSFER_S_PORT, udp_dport = IP_FILE_TRANSFER_D_PORT):
    pkt = IPv6(dst = ip_dst)/UDP(sport= udp_sport, dport = udp_dport)/Raw(load=dataPayload)
    return pkt

def createIpPingReplyPacket(requestPacket, replyMsg):
    eth_src = requestPacket[Ether].dst
    eth_dst = requestPacket[Ether].src

    ip_src = requestPacket[IPv6].dst
    ip_dst = requestPacket[IPv6].src

    udp_sport = requestPacket[UDP].dport
    udp_dport = requestPacket[UDP].sport

    #pkt = Ether(src=eth_src, dst=eth_dst)/IPv6(src=ip_src, dst = ip_dst)/UDP(sport= udp_sport, dport = udp_dport)/Raw(load=replyMsg)
    pkt = IPv6(dst = ip_dst)/UDP(sport= udp_sport, dport = udp_dport)/Raw(load=replyMsg)
    return pkt

