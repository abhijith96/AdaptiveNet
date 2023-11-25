from ipaddress import ip_address
from optparse import TitledHelpFormatter
from tabnanny import verbose
from scapy.all import sr1, srp1, srp, Raw, sendp, sr
from scapy.utils6 import *
import sys
from IPv6ExtHdrVLA import IPv6ExtHdrVLA
from scapy.all import get_if_addr6, get_if_hwaddr, get_if_list
from scapy.layers.inet6 import UDP, IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.l2 import Ether
from Utils import createVlaPacket, getMacAddress, createIpPingPacket, IP_PING_D_PORT, IP_PING_S_PORT
import time
from scapy.all import conf
from NRUtils import resolveHostVlaAddress, getCurrentHostVlaAddress, getDefaultMacAddress, getDefaultInterface
import time
import socket
from scapy.utils import  inet_pton
import subprocess

def resolve_hostname(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        return (True,ip_address)
    except socket.error as e:
        print("Error resolving hostname {} ".format(str(e)))
        return (False,None)
    
def replace_last_16_bytes_with_ff(ipv6_address):
    # Check if the input string is a valid IPv6 address

    # Split the address and replace the last 16 bytes with "ff"
    parts = ipv6_address.split(':')
    parts[-1] = 'ff'

    # Join the parts to form the modified IPv6 address
    modified_ipv6_address = ':'.join(parts)

    return modified_ipv6_address
    
def getIPAddress(interface):
    try:
        ipv6_address = get_if_addr6(interface)
        return  (True,ipv6_address)
    except Exception as e:
        print("Error getting IPv6 address for interface {}: {}".format(interface, e))
        return (False,None)

def genNdpNsPkt(target_ip, src_mac, src_ip):

    target_gateway = replace_last_16_bytes_with_ff(target_ip)

   # print("gateway is ", target_gateway)

    nsma = in6_getnsma(inet_pton(socket.AF_INET6, target_ip))
    d = inet_ntop(socket.AF_INET6, nsma)
    dm = in6_getnsmac(nsma)
    #print(" d is ", d)
   # print("dm is ", dm)
    p = Ether(dst=dm) / IPv6(dst=d, src=src_ip, hlim=255)
    p /= ICMPv6ND_NS(tgt=target_gateway)
    p /= ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    return p

def getGatewayMacAddress(interface, target_ip, src_mac, src_ip):
    gateWaystatus, vlaAddress, gatewayMac, message = getCurrentHostVlaAddress()
    if(gateWaystatus):
        return gateWaystatus, gatewayMac
    return (False, None)




def getCommandLineArguments():
    try:
        targetHost = sys.argv[1]
        targetPid = sys.argv[2]
        return targetHost, targetPid
    except Exception():
        raise Exception("Pass Comandline Arguments Properly") 
    
def pingHandler(targetHostId, targetIp):
    # Create an VLA IP packet with an UDP Ping
    replyMessage = ""
    ifaceStatus, defaultInterface = getDefaultInterface()
    if(not ifaceStatus):
        replyMessage = "No network interfaces found for device"
        return (False, replyMessage, None)
    ethSrcStatus, ethSrc= getDefaultMacAddress()
    if(not ethSrcStatus):
        replyMessage = "mac address not found for current device"
        return (False, replyMessage, None)
    hostIpStatus, hostIpAddress =getIPAddress(defaultInterface)
    if(not hostIpStatus):
        replyMessage = "ip address for current Device Not found"
        return (False, replyMessage, None)

  
    targetIPAddress = targetIp
        #return (False, replyMessage, None)
    
    gatewayMacStatus, gatewayMac = getGatewayMacAddress(defaultInterface, targetIPAddress, ethSrc, hostIpAddress)
    
    if(not gatewayMacStatus):
        replyMessage = "gateway mac  address for target device {} not found".format(targetHostId)
        return (False, replyMessage, None)
    count = 5
    pingStatus, rttAverage = doIpPingMultipleTimes(defaultInterface, ethSrc, gatewayMac, hostIpAddress, targetIp, count=count)
    if(pingStatus):
        replyMessage = "Sucess"
        print("Ping sucessfully done {} ".format(int(count)))
        print("IpRoundTripTimeis  {:.3f}".format(rttAverage*1000))
        return (True, replyMessage, rttAverage)
    else:
        print("Ping Failed")
        replyMessage = "Ping Failed"
    return (False, replyMessage, None)

    
def doIpPingMultipleTimes(defaultInterface, ethSrc, gatewayMac, hostIpAddress, targetIPAddress, count):
    rttValues = []
    packet = createIpPingPacket(ethSrc, gatewayMac, hostIpAddress, targetIPAddress)
    for _ in range(0, count):
        start_time = time.time()
        reply = srp1(packet, timeout=20, iface = defaultInterface, verbose=False)
        if ICMPv6EchoReply in reply:
            replyMessage = "Ping  successful!"
        elif IPv6 in reply:
            replyMessage = "Ping partial failure, Scapy Issue "
            return False,None
        else:
            replyMessage = "Ping Failed No Reply"
            return False,None
        end_time = time.time()
        rtt = end_time - start_time
        rttValues.append(rtt)
    average = sum(rttValues) / count
    return True,average
    


def ip_ping(targetHostId, targetIp):
    # Create an VLA IP packet with an UDP Ping
    replyMessage = ""
    ifaceStatus, defaultInterface = getDefaultInterface()
    if(not ifaceStatus):
        replyMessage = "No network interfaces found for device"
        return (False, replyMessage, None)
    ethSrcStatus, ethSrc= getDefaultMacAddress()
    if(not ethSrcStatus):
        replyMessage = "mac address not found for current device"
        return (False, replyMessage, None)
    hostIpStatus, hostIpAddress =getIPAddress(defaultInterface)
    if(not hostIpStatus):
        replyMessage = "ip address for current Device Not found"
        return (False, replyMessage, None)

  
    targetIPAddress = targetIp
        #return (False, replyMessage, None)
    
    gatewayMacStatus, gatewayMac = getGatewayMacAddress(defaultInterface, targetIPAddress, ethSrc, hostIpAddress)
    
    if(not gatewayMacStatus):
        replyMessage = "gateway mac  address for target device {} not found".format(targetHostId)
        return (False, replyMessage, None)

    packet = createIpPingPacket(ethSrc, gatewayMac, hostIpAddress, targetIPAddress)
    #packet = IPv6(dst = targetIPAddress)/UDP(sport=IP_PING_S_PORT, dport = IP_PING_D_PORT)

    #print("packet is ", packet)
    # Send the packet and wait for a response
    start_time = time.time()

    #reply = sr(packet,iface=defaultInterface)
    reply = srp1(packet, timeout=20, iface = defaultInterface, verbose=False)
    
    end_time = time.time()


    rtt = 0

    # Check if a response was received
   
    if not reply is None:
        print("reply is ", reply)
        # if  UDP in reply and reply[UDP].sport == IP_PING_D_PORT:
        #     replyMessage = "Ping  successful! " + reply[Raw].load
        #     rtt = end_time - start_time
        #     return (True,replyMessage, rtt)
        if ICMPv6EchoReply in reply:
            replyMessage = "Ping  successful!"
            rtt = end_time - start_time
            return (True,replyMessage, rtt)
        elif IPv6 in reply:
            replyMessage = "Ping partial failure, Scapy Issue "
            return (True,replyMessage, rtt)
    else:
        replyMessage = "No response from ping."
    return (False, replyMessage, rtt)

    
def main():
    targetHost =""
    targetIp = ""
    try:
        targetHost, targetIp = getCommandLineArguments()
    except Exception as e:
            print("ping target not found as command line argument using default target : " +  str(e))
    pingStatus, replyMessage, rttAverage = pingHandler(targetHost, targetIp)
    if(not pingStatus): 
        print(replyMessage)
  

if __name__ == "__main__":
    main()