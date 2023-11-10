from __future__ import print_function
from scapy.layers.inet6 import  _IPv6ExtHdr;
from scapy.fields import FieldListField, PadField
from scapy.sendrecv import srp
import scapy.packet
import scapy.utils
from ptf import config
from ptf import testutils as testutils
from ptf.base_tests import BaseTest
from ptf.dataplane import match_exp_pkt
from ptf.packet import IPv6
from scapy.layers.inet6 import *
from scapy.layers.l2 import Ether
from scapy.pton_ntop import inet_pton, inet_ntop
from scapy.utils6 import in6_getnsma, in6_getnsmac
#from base_test import *




MINSIZE = 0
DEFAULT_PRIORITY = 10

IPV6_MCAST_MAC_1 = "33:33:00:00:00:01"

SWITCH1_MAC = "00:00:00:00:aa:01"
SWITCH2_MAC = "00:00:00:00:aa:02"
SWITCH3_MAC = "00:00:00:00:aa:03"
HOST1_MAC = "00:00:00:00:00:01"
HOST2_MAC = "00:00:00:00:00:02"

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

ARP_ETH_TYPE = 0x0806
IPV6_ETH_TYPE = 0x86DD

ICMPV6_IP_PROTO = 58
NS_ICMPV6_TYPE = 135
NA_ICMPV6_TYPE = 136

# FIXME: this should be removed, use generic packet in test
PACKET_IN_INGRESS_PORT_META_ID = 1





def insert_vla_header(pkt, sid_list, current_level_param):
    """Applies SRv6 insert transformation to the given packet.
    """
    # Set IPv6 dst to some valid IPV6 Address
    pkt[IPv6].dst = HOST2_IPV6
    # Insert VLA header between IPv6 header and payload
    sid_len = len(sid_list)
    srv6_hdr = IPv6ExtHdrVLA(
        nh=pkt[IPv6].nh,
        addresses=sid_list,
        len=(sid_len * 2) - 1,
        address_type = 0b01,
        current_level = current_level_param,
        number_of_levels= sid_len
        )
    pkt[IPv6].nh = 48  # next IPv6 header is VLA header
    pkt[IPv6].payload = srv6_hdr / pkt[IPv6].payload
    return pkt


class IPv6ExtHdrVLA(_IPv6ExtHdr):

    name = "IPv6 Option Header VLA"
    # RFC8754 sect 2. + flag bits from draft 06
    fields_desc = [ByteEnumField("nh", 59, ipv6nh),
                   ByteField("len", None),
                BitField("address_type", 0, 2),
                   BitField("current_level", 0, 16),
                   BitField("number_of_levels", 0, 16),
                    BitField("pad", 0, 6),
                 FieldListField("addresses", [], ShortField("", 0), 
                                 count_from=lambda pkt: (pkt.number_of_levels), length_from=lambda pkt,x: 16)
    ]

    overload_fields = {IPv6: {"nh": 48}}

    def post_build(self, pkt, pay):

        # if self.len is None:

            # The extension must be align on 8 bytes
            # tmp_mod = (-len(pkt) + 8) % 8
            # if tmp_mod == 1:
            #     tlv = IPv6ExtHdrSegmentRoutingTLVPad1()
            #     pkt += raw(tlv)
            # elif tmp_mod >= 2:
            #     # Add the padding extension
            #     tmp_pad = b"\x00" * (tmp_mod - 2)
            #     tlv = IPv6ExtHdrSegmentRoutingTLVPadN(padding=tmp_pad)
            #     pkt += raw(tlv)

            # tmp_len = (len(pkt) - 8) // 8
            # pkt = pkt[:1] + struct.pack("B", tmp_len) + pkt[2:]

        if self.number_of_levels is None:
            tmp_len = len(self.addresses)
            if tmp_len:
                tmp_len -= 1
            pkt = pkt[:3] + struct.pack("B", tmp_len) + pkt[4:]

        if self.current_level is None:
            self.current_level = 0
            pkt = pkt[:4] + struct.pack("B", self.current_level) + pkt[5:]

        return _IPv6ExtHdr.post_build(self, pkt, pay)
    

def create_vla_current_address_entry(address_list, max_level_limit, level_size):
    result  = int("0", 2)
    for i in range(0, max_level_limit):
        if(i == 0):
            if i < len(address_list):
                result  += address_list[i]
        else:
            result = result << level_size
            if i < len(address_list):
                result  += address_list[i]   
    return int(result)    

sidList = [4096,4097,4097]
currentLevel = 2
data = "HELLO WORLD"
packet = Ether(src="00:00:00:00:00:1a", dst="00:aa:00:00:00:01")/IPv6()/IPv6ExtHdrVLA()/UDP()/Raw(load=data)
packet = insert_vla_header(packet, sidList, currentLevel)

# Send the packet as a ping on interface eth0
srp(packet, iface="h1a-eth0")
