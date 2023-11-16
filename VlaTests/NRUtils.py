
from scapy.layers.inet6 import *;
from scapy.layers.inet6 import _ICMPv6NDGuessPayload, _ICMPv6
from scapy.sendrecv import srp1, srp


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

class ICMPv6ND_NR(_ICMPv6NDGuessPayload, _ICMPv6, Packet):
    name = "ICMPv6 Neighbor Discovery - Neighbor Solicitation"
    fields_desc = [ByteEnumField("type", 137, icmp6types),
                   ByteField("code", 0),
                   XShortField("cksum", None),
                   IntField("res", 0),
                   IP6Field("tgt", "::")]
    overload_fields = {IPv6: {"nh": 58, "dst": "ff02::1", "hlim": 255}}

    def mysummary(self):
        return self.sprintf("%name% (tgt: %tgt%)")

    def hashret(self):
        return bytes_encode(self.tgt) + self.payload.hashret()
    
class ICMPv6ND_NRReply(_ICMPv6NDGuessPayload, _ICMPv6, Packet):
    NDP_FLAG_ROUTER    = 0x80000000
    NDP_FLAG_NAME_RESOLUTION  = 0x10000000
    name = "ICMPv6 Neighbor Discovery - Neighbor Solicitation"
    fields_desc = [ByteEnumField("type", 138, icmp6types),
                   ByteField("code", 0),
                   XShortField("cksum", None),
                   IntField("res", NDP_FLAG_ROUTER | NDP_FLAG_NAME_RESOLUTION),
                   IP6Field("tgt", "::")]
    overload_fields = {IPv6: {"nh": 58, "dst": "ff02::1", "hlim": 255}}

    def mysummary(self):
        return self.sprintf("%name% (tgt: %tgt%)")

    def hashret(self):
        return bytes_encode(self.tgt) + self.payload.hashret()
    

    
class ICMPv6NDNROptSrcLLAddr(_ICMPv6NDGuessPayload, Packet):
    name = "ICMPv6 Neighbor Discovery Option - Source Link-Layer Address"
    NDP_TARGET_VLA_ADDR = 3
    fields_desc = [ByteField("type", NDP_TARGET_VLA_ADDR),
                   ByteField("len", 1),
                   MACField("lladdr", ETHER_ANY)]

    def mysummary(self):
        return self.sprintf("%name% %lladdr%")
    
def genNdpNrPkt(target_host_mac):
    NDP_NR_MAC = "33:33:00:00:00:01"
    p = Ether(dst="00:00:00:00:aa:01", src ="00:00:00:00:00:1a") / IPv6(dst=HOST2_IPV6, src=HOST1_IPV6, hlim=255)
    p /= ICMPv6ND_NA(tgt="::", type = 137)
    p /= ICMPv6NDNROptSrcLLAddr(lladdr=target_host_mac)
    print("packet is ", p)
    return p

def resolveHostVlaAddress(hostId, outInterface):
    ndp_nr_packet = genNdpNrPkt(hostId)
    reply = srp(ndp_nr_packet,outInterface)
    replyMessage = ""
    if reply:
        if(Ether in reply and IPv6 in reply):
            if reply[IPv6].nh == 58:
                print("reply packet is ", reply)
                ipPayload = ICMPv6ND_NRReply(reply[IPv6].payload)
                print(ipPayload)
                return (True,replyMessage)
            else:
                replyMessage =  "ICMP NDP NR not detected in reply"
        else:
            replyMessage = "Unexpected Response Type"
    else:
        replyMessage = "No response  from gateway."
        return (False, replyMessage)

    
