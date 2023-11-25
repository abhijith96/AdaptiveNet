
from scapy.all import sr1, srp1, srp, Raw
import sys
from IPv6ExtHdrVLA import IPv6ExtHdrVLA
from scapy.layers.inet6 import UDP, IPv6, ICMPv6EchoReply
from scapy.layers.l2 import Ether
from Utils import  VLA_PING_S_PORT, VLA_PING_D_PORT, createVlaPingPacket, PING_COUNT
import time
from NRUtils import resolveHostVlaAddress, getCurrentHostVlaAddress, getDefaultMacAddress, getDefaultInterface


def getCommandLineArguments():
    try:
        targetHost = sys.argv[1]
        return targetHost
    except Exception():
        raise Exception("Pass Comandline Arguments Properly") 
    
def DoVlaPingMultipleTimes(defaultInterface, ethSrc, ethDst, hostVla, targetVla, count):
    

    dataPayload = "Ping Request"

    #packet = createVlaPacket(ethDst, ethSrc, vlaSrcList, vlaDstList, vlaCurrentLevel, dataPayload)
    vlaCurrentLevel = len(hostVla) - 1
    packet = createVlaPingPacket(ethDst, ethSrc, hostVla, targetVla, vlaCurrentLevel)

    replyMessage = "Ping Sucessful {} times ".format(count)

    rttList = []
    for i in range(0, count):
        start_time = time.time()
        reply = srp1(packet,iface=defaultInterface, verbose=False)
        end_time = time.time()
        rtt = end_time - start_time
        if(reply and Ether in reply and IPv6 in reply and reply[IPv6].nh == 48):
            ipPayload = IPv6ExtHdrVLA(reply[IPv6].payload)
            if ipPayload[UDP] and ipPayload[UDP].sport == VLA_PING_D_PORT:
                rttList.append(rtt)
            else:
                replyMessage = "Ping {} failed  Problem with UDP Packet".format(str(i + 1))
                return (False, replyMessage, None)
        else:
            replyMessage = "Ping {} failed ".format(str(i + 1))
            return (False, None)
    
    rttAverage = sum(rttList)/count

    return (True, replyMessage, rttAverage)


def VlaPingHandler(targetHostId):
    replyMessage = ""
    ifaceStatus, defaultInterface = getDefaultInterface()
    if(not ifaceStatus):
        replyMessage = "No network interfaces found for device"
        return (False, replyMessage, None)
    ethSrcStatus, ethSrc= getDefaultMacAddress()
    if(not ethSrcStatus):
        replyMessage = "mac address not found for current device"
        return (False, replyMessage, None)
    hostVlaStatus, hostVlaAddress, gatewayMac, message = getCurrentHostVlaAddress()
    if(not hostVlaStatus):
        replyMessage = "vla address for current Device Not found"
        return (False, replyMessage, None)
    

    targetVlaStatus, targetVlaAddress, gatewayMac, message = resolveHostVlaAddress(targetHostId)
    if(not hostVlaStatus):
        replyMessage = "vla address for target device %s not found".format(targetHostId)
        return (False, replyMessage, None)
    
    #print("Target vla address is ", targetVlaAddress)
    
    ethDst=gatewayMac
    vlaSrcList = hostVlaAddress
    vlaDstList = targetVlaAddress
    vlaCurrentLevel = len(hostVlaAddress) - 1
    dataPayload = "Ping Request"
    count = PING_COUNT
    status, message, rttAverage = DoVlaPingMultipleTimes(defaultInterface, ethSrc, gatewayMac, hostVlaAddress, targetVlaAddress, count)

    return status, message, rttAverage

def vla_ping(targetHostId):
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
    hostVlaStatus, hostVlaAddress, gatewayMac, message = getCurrentHostVlaAddress()
    if(not hostVlaStatus):
        replyMessage = "vla address for current Device Not found"
        return (False, replyMessage, None)
    
    #print("host vla Addrsss is ", hostVlaAddress)

    targetVlaStatus, targetVlaAddress, gatewayMac, message = resolveHostVlaAddress(targetHostId)
    if(not hostVlaStatus):
        replyMessage = "vla address for target device %s not found".format(targetHostId)
        return (False, replyMessage, None)
    
    #print("Target vla address is ", targetVlaAddress)
    
    ethDst=gatewayMac
    vlaSrcList = hostVlaAddress
    vlaDstList = targetVlaAddress
    vlaCurrentLevel = len(hostVlaAddress) - 1
    dataPayload = "Ping Request"

    #packet = createVlaPacket(ethDst, ethSrc, vlaSrcList, vlaDstList, vlaCurrentLevel, dataPayload)
    packet = createVlaPingPacket(ethDst, ethSrc, vlaSrcList, vlaDstList, vlaCurrentLevel)

    #print("packet is ", packet)

    # Send the packet and wait for a response
    start_time = time.time()

    reply = srp1(packet,iface=defaultInterface)
    
    end_time = time.time()


    rtt = 0

    # Check if a response was received
   
    print(reply)
    if not reply is None:
        if(Ether in reply and IPv6 in reply):
            if reply[IPv6].nh == 48:
                #print("reply packet is ", reply)
                ipPayload = IPv6ExtHdrVLA(reply[IPv6].payload)
                if ipPayload[UDP] and ipPayload[UDP].sport == VLA_PING_D_PORT:
                    replyMessage = "Ping  successful! " + ipPayload[Raw].load
                    rtt = end_time - start_time
                    return (True,replyMessage, rtt)
                elif ipPayload[ICMPv6EchoReply]:
                    replyMessage = "Ping  successful! "
                    rtt = end_time - start_time
                    return (True,replyMessage, rtt)
                else:
                    replyMessage = "Ping Failed UDP not found or UDP src port does not match "
            else:
                replyMessage =  "Vla not detected in reply"
        else:
            replyMessage = "Ping to failed. Unexpected response type."
    else:
        replyMessage = "No response from ping."
    return (False, replyMessage, rtt)

    
def main():
    targetHost = "00:00:00:00:00:1b"
    try:
        targetHost = getCommandLineArguments()
    except Exception as e:
            print("ping target not found as command line argument using default target : " +  str(e))
    (pingStatus,replyMessage, rttAverage) = VlaPingHandler(targetHost)
    if(pingStatus):
        print("RoundTripTimeis  {:.3f} average obervation".format(rttAverage*1000))
    print(replyMessage)
    

if __name__ == "__main__":
    main()