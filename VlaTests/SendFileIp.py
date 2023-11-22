from scapy.all import sendp, send
import Utils
import NRUtils
import sys
import os
import time
from scapy.all import get_if_addr6, get_if_hwaddr, get_if_list

class CommandLineArgumentExeception(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.custom_message = message

    def __str__(self):
        return "CommandLineArgumentExeception: {}".format(self.custom_message)
    
def createFile(filePath, file_size_mb):
    
    character_to_repeat = 'H'

    num_repetitions = file_size_mb * 1024 * 1024 // len(character_to_repeat)
    with open(filePath, 'w') as file:
        file.write(character_to_repeat * num_repetitions)

    print("File created successfully.")

def getIPAddress(interface):
    try:
        ipv6_address = get_if_addr6(interface)
        return  (True,ipv6_address)
    except Exception as e:
        print("Error getting IPv6 address for interface {}: {}".format(interface, e))
        return (False,None)
    
def get_time_in_milliseconds(current_time):
    milliseconds = int((current_time - int(current_time)) * 1000) 

    time_string = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(current_time)))
    time_with_milliseconds = "{}.{:03d}".format(time_string, milliseconds)
    return time_with_milliseconds

def delete_file(file_path):
    absolute_path = os.path.abspath(file_path)
    if os.path.exists(absolute_path):
        os.remove(absolute_path)
        print("File '{}' deleted.".format(absolute_path))
    else:
        print("File '{}' does not exist.".format(absolute_path))

def getCommandLineArguments():
    try:
        targetHost = sys.argv[1]
        targetHostIp = sys.argv[2]
        return targetHost, targetHostIp
    except Exception():
        raise Exception("Pass Comandline Arguments Properly") 

def resolveAddresses(targetHostId):
    # Create an VLA IP packet with an UDP Ping
    replyMessage = ""
    ifaceStatus, defaultInterface = NRUtils.getDefaultInterface()
    if(not ifaceStatus):
        replyMessage = "No network interfaces found for device"
        return (False, replyMessage, None)
    ethSrcStatus, ethSrc= NRUtils.getDefaultMacAddress()
    if(not ethSrcStatus):
        replyMessage = "mac address not found for current device"
        return (False, replyMessage, None)
    hostVlaStatus, hostVlaAddress, gatewayMac, message = NRUtils.getCurrentHostVlaAddress()
    if(not hostVlaStatus):
        replyMessage = "vla address for current Device Not found"
        return (False, replyMessage, None)
    
    #print("host vla Addrsss is ", hostVlaAddress)

    targetVlaStatus, targetVlaAddress, gatewayMac, message = NRUtils.resolveHostVlaAddress(targetHostId)
    if(not hostVlaStatus):
        replyMessage = "vla address for target device %s not found".format(targetHostId)
        return (False, replyMessage, None)
    
    hostIpStatus, hostIpAddress = getIPAddress(defaultInterface)

    if(not hostIpStatus):
        return (False, replyMessage, None)

    
    #print("Target vla address is ", targetVlaAddress)
    
    iface = defaultInterface
    ethDst=gatewayMac
    vlaSrcList = hostVlaAddress
    vlaDstList = targetVlaAddress
    return (True, replyMessage, (iface, ethSrc, ethDst, vlaSrcList, vlaDstList, hostIpAddress))


def send_file(targetHostId,targetHostIp):
    resolveStatus, message, addressTuple = resolveAddresses(targetHostId)
    file_path = Utils.FILE_TRANSFER_SEND_FILE
    if(resolveStatus):
        iface, ethSrc, ethDst, vlaSrcList, vlaDstList, hostIpAddress = addressTuple
        with open(file_path, 'rb') as file:
            file_data = file.read()
            packets = [Utils.createIpUdpFilePacket(gateway_eth=ethDst, ethsrc=ethSrc,ipv6_src=hostIpAddress, ipv6_dst=targetHostIp, udp_sport=Utils.VLA_FILE_TRANSFER_S_PORT,
                                                udp_dport= Utils.VLA_FILE_TRANSFER_D_PORT, data_payload=file_data[i:i+1024]) for i in range(0, len(file_data), 1024)]
            print("packet count ", len(packets))
            startTime = time.time()
            for packet in packets:
                send(packet, iface=iface, verbose=False)
            endTime =  time.time()
            totalTime = endTime - startTime
            print("total time is ", get_time_in_milliseconds(totalTime))
            print("start time is ", get_time_in_milliseconds(startTime))
            print("end time is " , get_time_in_milliseconds(endTime))

    else:
        print(message)
        print("File count not be send, address resolution error")

if __name__ == "__main__":
    try:
        targetHostId, targetHostIP = getCommandLineArguments()
        send_file(targetHostId, targetHostIP)
    except CommandLineArgumentExeception as e:
        print("pass valid commandline arguments , syntax is  FileName targetHostId filePath")
