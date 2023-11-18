

import sys
from scapy.all import get_if_hwaddr

from scapy.sendrecv import srp
from IPv6ExtHdrVLA import IPv6ExtHdrVLA
from scapy.layers.inet6 import *
from scapy.layers.l2 import Ether
from scapy.pton_ntop import inet_pton, inet_ntop
from scapy.utils6 import in6_getnsma, in6_getnsmac
from NRUtils import resolveHostVlaAddress, getCurrentHostVlaAddress
#from base_test import *




MINSIZE = 0
DEFAULT_PRIORITY = 10

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

ARP_ETH_TYPE = 0x0806
IPV6_ETH_TYPE = 0x86DD

ICMPV6_IP_PROTO = 58
NS_ICMPV6_TYPE = 135
NA_ICMPV6_TYPE = 136

# FIXME: this should be removed, use generic packet in test
PACKET_IN_INGRESS_PORT_META_ID = 1




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
    return vlaList

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
#  interface, vlaList, vlaCurrentLevel = getCommandLineArguments()
    data = "HELLO WORLD"
#    interfaceMacAddress = get_if_hwaddr(interface)
    targetHostMac = "00:00:00:00:00:1b"
    responseStatus, vlaAddress, gatewayEther, responseMsg = resolveHostVlaAddress(targetHostMac)
    print(responseMsg)
    if(responseStatus):
        print(vlaAddress)
        print(gatewayEther)

    responseStatus2, currentVlaAddress, currentGatewayEther, responseMsg = getCurrentHostVlaAddress()
    if(responseStatus2):
        print(currentVlaAddress)
        print(currentGatewayEther)
        print(responseMsg)

if __name__ == "__main__":
    main()

