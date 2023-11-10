from __future__ import print_function
from scapy.layers.inet6 import  _IPv6ExtHdr;
from scapy.fields import FieldListField, PadField
from ptf.testutils import group
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

""" A pluggable packet module

This module dynamically imports definitions from packet manipulation module,
specified in config or provided as an agrument.
The default one is Scapy, but one can develop its own packet manipulation framework and
then, create an implementation of packet module for it (for Scapy it is packet_scapy.py)
"""

from ptf import config

__module = __import__(
    config.get("packet_manipulation_module", "ptf.packet_scapy"), fromlist=["*"]
)
__keys = []

# import logic - everything from __all__ if provided, otherwise everything not starting
# with underscore
print("Using packet manipulation module: %s" % __module.__name__)
if "__all__" in __module.__dict__:
    __keys = __module.__dict__["__all__"]
else:
    __keys = [k for k in __module.__dict__ if not k.startswith("_")]

locals().update({k: getattr(__module, k) for k in __keys})



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

        if self.len is None:

            # The extension must be align on 8 bytes
            tmp_mod = (-len(pkt) + 8) % 8
            if tmp_mod == 1:
                tlv = IPv6ExtHdrSegmentRoutingTLVPad1()
                pkt += raw(tlv)
            elif tmp_mod >= 2:
                # Add the padding extension
                tmp_pad = b"\x00" * (tmp_mod - 2)
                tlv = IPv6ExtHdrSegmentRoutingTLVPadN(padding=tmp_pad)
                pkt += raw(tlv)

            tmp_len = (len(pkt) - 8) // 8
            pkt = pkt[:1] + struct.pack("B", tmp_len) + pkt[2:]

        if self.number_of_levels is None:
            tmp_len = len(self.addresses)
            if tmp_len:
                tmp_len -= 1
            pkt = pkt[:3] + struct.pack("B", tmp_len) + pkt[4:]
        if self.current_level is None:
            self.current_level = 0
            pkt = pkt[:4] + struct.pack("B", self.current_level) + pkt[5:]

        return _IPv6ExtHdr.post_build(self, pkt, pay)
    
def ip_make_tos(tos, ecn, dscp):
    if ecn is not None:
        tos = (tos & ~(0x3)) | ecn

    if dscp is not None:
        tos = (tos & ~(0xFC)) | (dscp << 2)

    return tos
    

def simple_udpv6_packet(
    pktlen=100,
    eth_dst="00:01:02:03:04:05",
    eth_src="00:06:07:08:09:0a",
    dl_vlan_enable=False,
    vlan_vid=0,
    vlan_pcp=0,
    ipv6_src="2001:db8:85a3::8a2e:370:7334",
    ipv6_dst="2001:db8:85a3::8a2e:370:7335",
    ipv6_tc=0,
    ipv6_ecn=None,
    ipv6_dscp=None,
    ipv6_hlim=64,
    ipv6_fl=0,
    udp_sport=1234,
    udp_dport=80,
    with_udp_chksum=True,
    udp_payload=None,
):
    """
    Return a simple IPv6/UDP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destination MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ipv6_src IPv6 source
    @param ipv6_dst IPv6 destination
    @param ipv6_tc IPv6 traffic class
    @param ipv6_ecn IPv6 traffic class ECN
    @param ipv6_dscp IPv6 traffic class DSCP
    @param ipv6_ttl IPv6 hop limit
    @param ipv6_fl IPv6 flow label
    @param udp_dport UDP destination port
    @param udp_sport UDP source port
    @param with_udp_chksum Valid UDP checksum

    Generates a simple UDP request. Users shouldn't assume anything about this
    packet other than that it is a valid ethernet/IPv6/UDP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    ipv6_tc = ip_make_tos(ipv6_tc, ipv6_ecn, ipv6_dscp)
    pkt = packet.Ether(dst=eth_dst, src=eth_src)
    if dl_vlan_enable or vlan_vid or vlan_pcp:
        pkt /= packet.Dot1Q(vlan=vlan_vid, prio=vlan_pcp)
    pkt /= packet.IPv6(
        src=ipv6_src, dst=ipv6_dst, fl=ipv6_fl, tc=ipv6_tc, hlim=ipv6_hlim
    )
    if with_udp_chksum:
        pkt /= packet.UDP(sport=udp_sport, dport=udp_dport)
    else:
        pkt /= packet.UDP(sport=udp_sport, dport=udp_dport, chksum=0)
    if udp_payload:
        pkt = pkt / udp_payload
    pkt /= "D" * (pktlen - len(pkt))

    return pkt


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

sidList = [4096, 4096, 4096]
currentLevel = 2
packet = simple_udpv6_packet()
packet = insert_vla_header(packet, sidList, currentLevel)

# Send the packet as a ping on interface eth0
srp(packet, iface="h1a-eth0")
