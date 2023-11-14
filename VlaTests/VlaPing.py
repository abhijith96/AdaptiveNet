import os
import sys

sys.path.insert(0, os.path.join(os.getcwd(), 'lib'))

from scapy.all import sr1, srp, Raw
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
    # pkt = Ether(dst=eth_dst, src=eth_src)
    # pkt /= IPv6(
    #     src=ipv6_src, dst=ipv6_dst, fl=ipv6_fl, tc=ipv6_tc, hlim=ipv6_hlim
    # )
    pkt = Ether(src=eth_src, dst=eth_dst)/IPv6(src=ipv6_src, dst=ipv6_dst, plen = 44)/UDP(sport = udp_sport, 
                                                                               dport = udp_dport)/Raw(load=data_payload)
    # if with_udp_chksum:
    #     pkt /= UDP(sport=udp_sport, dport=udp_dport)
    # else:
    #     pkt /= UDP(sport=udp_sport, dport=udp_dport, chksum=0)
    
    # if data_payload:
    #     pkt = pkt / data_payload
    # pkt /= "D" * (pktlen - len(pkt))
    return pkt

def createVlaPacket(ethDst, ethSrc, srcVlaAddrList, dstVlaAddrList, vlaCurrentLevel, data_payload = None):
    ip_src = "::1"
    ip_dst = "::2"
    pkt = createIPPacket(ethDst, ethSrc, ip_src, ip_dst, data_payload)
    pkt = insert_vla_header(pkt,dstVlaAddrList, srcVlaAddrList, vlaCurrentLevel)
    return pkt

# def insert_vla_header(pkt, destination_vla_list, source_vla_list, current_level_param):
#     """Applies Vla header to an Ipv6 packet.
#     """
#     # Set IPv6 dst to some valid IPV6 Address
#     # Insert VLA header between IPv6 header and payload
#     print("debug ", pkt[IPv6].plen)
#     vla_dst_len = len(destination_vla_list)
#     source_vla_list_len = len(source_vla_list)
#     vla_hdr = IPv6ExtHdrVLA(
#         nh=pkt[IPv6].nh,
#         addresses=destination_vla_list,
#         source_addresses = source_vla_list,
#         len=(vla_dst_len * 2) + (source_vla_list_len * 2) + 1,
#         address_type = 0b01,
#         current_level = current_level_param,
#         number_of_levels= vla_dst_len,
#         number_of_source_levels = source_vla_list_len
#         )
#     pkt[IPv6].nh = 48  # next IPv6 header is VLA header
#     pkt[IPv6].payload = vla_hdr / pkt[IPv6].payload
#     return pkt

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

def ping():
    # Create an IP packet with an ICMP Echo Request
    ethSrc="00:00:00:00:00:1a" 
    ethDst="00:aa:00:00:00:01"
    vlaSrcList = [4096,4096,4096,4096,4096]
    vlaDstList = [4096, 4096, 4097]
    vlaCurrentLevel = 4
    dataPayload = "Hello"
    pkt = createVlaPacket(ethSrc, ethDst, vlaSrcList, vlaDstList, vlaCurrentLevel, dataPayload)

    print("packet is ", pkt.show())

    # Send the packet and wait for a response
    reply = srp(pkt, timeout=4, verbose=False, iface="h1a-eth0")


    # Check if a response was received
    if reply:
        # Check if the response is an ICMP Echo Reply
        if reply.haslayer(UDP) and reply[UDP].sport == 80:
            print("Ping to  successful!")
        else:
            print("Ping to failed. Unexpected response type.")
            reply.summary()
    else:
        print("No response from.")

# Example usage
def main():
    ping()

if __name__ == "__main__":
    main()