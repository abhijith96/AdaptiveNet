
from __future__ import print_function
import os
import sys

from scapy.all import get_if_hwaddr

sys.path.insert(0, os.path.join(os.getcwd(), 'lib'))

from scapy.layers.inet6 import  _IPv6ExtHdr;
from scapy.fields import FieldListField, PadField
from scapy.sendrecv import srp
import scapy.packet
import scapy.utils
from IPv6ExtHdrVLA import IPv6ExtHdrVLA
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

def ConvertVlaAddressStringToVlaList(vlaAddressString):
    vlaList = vlaAddressString.split(":")
    integer_list = [int(x) for x in vlaList]
    return integer_list

def getCommandLineArguments():
    try:
        interface = sys.argv[1]
        vlaAddressString = sys.argv[2]
        vlaLevel = int(sys.argv[3])
        vlaAddressList = ConvertVlaAddressStringToVlaList(vlaAddressString)
        return (interface,vlaAddressList, vlaLevel)
    except Exception():
        raise Exception("Pass Comandline Arguments Properly") 

def main():
    # interface, vlaList, currentLevel = getCommandLineArguments()
    data = "HELLO WORLD"
    # interfaceMacAddress = get_if_hwaddr(interface)
    # print("printing commandline arguments")
    # print("interface mac address ", interfaceMacAddress)
    # print("interface", interface)
    sourceVlaList = [4096,4096,4098]
    # print("vla list is ", vlaList)
   
    interface = "h1a-eth0"
    vlaList = [4096,4096,4096,4096]
    currentLevel = 2
    packet = Ether(src="00:00:00:00:00:1a", dst="00:aa:00:00:00:01")/IPv6(src="::1", dst= "2002::2")/UDP()/Raw(load=data)

    packet = insert_vla_header(packet, vlaList,sourceVlaList, currentLevel)
    print("data is ", data)
    print("vla list  ", vlaList)
    srp(packet, iface=interface)   

if __name__ == "__main__":
    main()

