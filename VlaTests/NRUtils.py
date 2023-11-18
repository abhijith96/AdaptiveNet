
from scapy.layers.inet6 import *;
from scapy.sendrecv import srp1, srp, sr1



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



def genNdpNrPkt(src_mac, target_host_mac, target_ip, src_ip):
    NDP_NR_MAC = "33:33:00:00:00:01"
    pkt = genNdpNsPkt(target_ip=target_ip, src_mac = src_mac, src_ip=src_ip)
    # pkt[IPv6].src="::1"
    # pkt[IPv6].dst="::1"
    # pkt[ICMPv6ND_NS].type = 135
    # pkt[ICMPv6ND_NS].tgt = target_ip
    pkt[ICMPv6NDOptSrcLLAddr].lladdr = src_mac
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



def genNdpNaPkt(target_ip, target_mac,
                src_mac=SWITCH1_MAC, dst_mac=IPV6_MCAST_MAC_1,
                src_ip=SWITCH1_IPV6, dst_ip=HOST1_IPV6):
    p = Ether(src=src_mac, dst=dst_mac)
    p /= IPv6(dst=dst_ip, src=src_ip, hlim=255)
    p /= ICMPv6ND_NA(tgt=target_ip)
    p /= ICMPv6NDOptDstLLAddr(lladdr=src_mac)
    return p

def resolveHostVlaAddress(hostId, outInterface):
    SWITCH1_IPV6 = "2001:1:2::1:ff"
    ndp_nr_packet = genNdpNrPkt(target_host_mac=hostId, target_ip=SWITCH1_IPV6, src_ip="2001:1:1::a:ff", src_mac="00:00:00:00:00:1a")
    print("packet is ", ndp_nr_packet)
    reply = srp1(ndp_nr_packet,outInterface)
    replyMessage = ""
    if reply:
        if(Ether in reply and IPv6 in reply):
            if reply[IPv6].nh == 58:
                print("reply packet is ", reply)
                ipPayload = ICMPv6ND_NA(reply[IPv6].payload)
                print(ipPayload)
                return (True,replyMessage)
            else:
                replyMessage =  "ICMP NDP NR not detected in reply"
        else:
            print("reply packet is ", reply)
            replyMessage = "Unexpected Response Type"
    else:
        replyMessage = "No response  from gateway."
    return (False, replyMessage)

    
