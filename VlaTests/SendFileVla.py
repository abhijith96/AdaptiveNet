from scapy.all import sendp
import Utils
import NRUtils
import sys
import os
import time

class CommandLineArgumentExeception(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.custom_message = message

    def __str__(self):
        return "CommandLineArgumentExeception: {}".format(self.custom_message)
    
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
        filePath = sys.argv[2]
        return targetHost, filePath
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
    
    #print("Target vla address is ", targetVlaAddress)
    
    iface = defaultInterface
    ethDst=gatewayMac
    vlaSrcList = hostVlaAddress
    vlaDstList = targetVlaAddress
    return (True, replyMessage, (iface, ethSrc, ethDst, vlaSrcList, vlaDstList))


def send_file(targetHostId, file_path):
    resolveStatus, message, addressTuple = resolveAddresses(targetHostId)
    if(resolveStatus):
        iface, ethSrc, ethDst, vlaSrcList, vlaDstList = addressTuple
        with open(file_path, 'rb') as file:
            file_data = file.read()
            packets = [Utils.createIPPacketforVla(eth_dst=ethDst, eth_src=ethSrc,ipv6_src="::2", ipv6_dst="::3", vlaSrc=vlaSrcList,
                                                vlaDst = vlaDstList, vlaCurrentLevel= len(vlaSrcList) - 1, udp_sport=Utils.VLA_FILE_TRANSFER_S_PORT,
                                                udp_dport= Utils.VLA_FILE_TRANSFER_D_PORT, data_payload=file_data[i:i+1024]) for i in range(0, len(file_data), 1024)]
            startTime = time.time()
            for packet in packets:
                sendp(packet, iface=iface)
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
        targetHostId, file_path = getCommandLineArguments()
        delete_file("output_file.txt")
        send_file(targetHostId, file_path)
    except CommandLineArgumentExeception as e:
        print("pass valid commandline arguments , syntax is  FileName targetHostId filePath")
