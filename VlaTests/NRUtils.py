
from scapy.layers.inet6 import *;
from scapy.utils import mac2str, inet_pton
from scapy.sendrecv import srp1, srp, sr1
import socket



IPV6_MCAST_MAC_1 = "33:33:00:00:00:01"

SWITCH1_MAC = "00:00:00:00:aa:01"
SWITCH2_MAC = "00:00:00:00:aa:02"
SWITCH3_MAC = "00:00:00:00:aa:03"
HOST1_MAC = "00:00:00:00:00:01"
HOST2_MAC = "00:00:00:00:00:1b"

MAC_BROADCAST = "FF:FF:FF:FF:FF:FF"
MAC_FULL_MASK = "FF:FF:FF:FF:FF:FF"
MAC_MULTICAST = "33:33:00:00:00:00"
MAC_MULTICAST_MASK = "FF:FF:00:00:00:00"

SWITCH1_IPV6 = "2001:0:1::1"
SWITCH2_IPV6 = "2001:0:2::1"
SWITCH3_IPV6 = "2001:0:3::1"
SWITCH4_IPV6 = "2001:0:4::1"
HOST1_IPV6 = "2001:0000:85a3::8a2e:370:1111"
HOST2_IPV6 = "2001:0000:85a3::8a2e:370:2222"
IPV6_MASK_ALL = "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"



def convert_128bit_to_16bit_list(integer_128bit):
    # Ensure the input is a valid 128-bit integer
    if not 0 <= integer_128bit < 2**128:
        raise ValueError("Input must be a 128-bit integer")

    # Initialize an empty list to store 16-bit chunks
    result_list = []

    # Extract 16-bit chunks using bitwise operations and a loop
    for _ in range(8):
        # Extract the least significant 16 bits
        chunk = integer_128bit & 0xFFFF
        # Add the chunk to the result list
        result_list.append(chunk)
        # Right shift by 16 bits to get the next chunk
        integer_128bit >>= 16

    # Reverse the list to maintain the order
    result_list.reverse()

    return result_list

def parse_vla_part_two(integer_48_bit):
    # Ensure the input is a valid 128-bit integer
    if not 0 <= integer_48_bit < 2**48:
        raise ValueError("Input must be a 128-bit integer")

    # Initialize an empty list to store 16-bit chunks
    result_list = []

    

    # Extract 16-bit chunks using bitwise operations and a loop
    for _ in range(2):
        # Extract the least significant 16 bits
        chunk = integer_48_bit & 0xFFFF
        # Add the chunk to the result list
        result_list.append(chunk)
        # Right shift by 16 bits to get the next chunk
        integer_128bit >>= 16

    # Reverse the list to maintain the order
    result_list.reverse()

    len = integer_48_bit & 0xFF

    number_of_levels = len

    return (result_list, number_of_levels)

# Example usage:
integer_128bit = 0x123456789ABCDEF0123456789ABCDEF0
result_list = convert_128bit_to_16bit_list(integer_128bit)
print(result_list)




def genNdpNrPkt(src_mac, target_host_mac, target_ip, src_ip):
    NDP_NR_MAC = "33:33:00:00:00:01"
    pkt = genNdpNsPkt(target_ip=target_ip, src_mac = src_mac, src_ip=src_ip)
    # pkt[IPv6].src="::1"
    # pkt[IPv6].dst="::1"
    pkt[ICMPv6ND_NS].type = 200
    pkt[ICMPv6ND_NS].tgt = target_ip
    pkt[ICMPv6NDOptSrcLLAddr].lladdr = target_host_mac
    # pkt[Ether].src = src_mac
    # pkt[Ether].dst = NDP_NR_MAC
    return pkt


def genNdpNsPkt(target_ip, src_mac=HOST1_MAC, src_ip=HOST1_IPV6):
    nsma = in6_getnsma(inet_pton(socket.AF_INET6, target_ip))
    d = inet_ntop(socket.AF_INET6, nsma)
    dm = in6_getnsmac(nsma)
    p = Ether(dst=dm) / IPv6(dst=d, src=src_ip, hlim=255)
    p /= ICMPv6ND_NS(tgt=target_ip)
    p /= ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    return p

def parseNdpNrReply(nr_packet):
    print("reply packet is is ", nr_packet)
    parseMessage = "Success"
    if(nr_packet[Ether] and nr_packet[IPv6]):
        gateway_ether = nr_packet[Ether].src
        payload = nr_packet[IPv6].payload
        payloadAsNSpkt = ICMPv6ND_NS(payload)
        print("payload icmp ", payloadAsNSpkt)
        payloadAsNSopt = ICMPv6NDOptSrcLLAddr( payloadAsNSpkt.payload)
        print("payload ndp", payloadAsNSopt)
        try:
            vlaPartOneString = nr_packet[IPv6].src
            vlaPartOneNumber = int(socket.inet_pton(socket.AF_INET6, vlaPartOneString).encode('hex'), 16)
            vlaAddrPartOne = convert_128bit_to_16bit_list(vlaPartOneNumber)
            print("vla part one int", vlaAddrPartOne)
            vlaPartTwoString = payloadAsNSopt.lladdr
            vlaPartTwoNumber = int(mac2str(vlaPartTwoString).encode('hex'),6)
            print(vlaPartTwoNumber)
            vlaAddrPartTwo, numLevels = parse_vla_part_two(vlaPartTwoNumber)
            vlaAddrPartOne.extend(vlaAddrPartTwo)
            vlaAddress = vlaAddrPartOne[:numLevels]
            return (True, vlaAddress, gateway_ether, parseMessage)
        except ValueError:
            parseMessage = "Integers for vla part one and vla part two not valid"
        except Exception as e:
            print(e)
            parseMessage = "Error extracting ICMP payload" 
    else:
        parseMessage = "No Ether or IP Packet in nr reply"
    return (False, None, None, parseMessage)




def genNdpNaPkt(target_ip, target_mac,
                src_mac=SWITCH1_MAC, dst_mac=IPV6_MCAST_MAC_1,
                src_ip=SWITCH1_IPV6, dst_ip=HOST1_IPV6):
    p = Ether(src=src_mac, dst=dst_mac)
    p /= IPv6(dst=dst_ip, src=src_ip, hlim=255)
    p /= ICMPv6ND_NA(tgt=target_ip)
    p /= ICMPv6NDOptDstLLAddr(lladdr=src_mac)
    return p

def resolveHostVlaAddress(hostId, outInterface):
    switch_Ip = "2001:1:2::ff"
    ndp_nr_packet = genNdpNrPkt(target_host_mac=hostId, target_ip=switch_Ip, src_ip="2001:1:1::a", src_mac="00:00:00:00:00:1a")
    print("packet is ", ndp_nr_packet)
    reply = srp1(ndp_nr_packet,outInterface)
    if(reply):
        return parseNdpNrReply(reply)
    return (False, None, None, "No reply for NR request")

    
