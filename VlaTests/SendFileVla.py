from scapy.all import sendp
import Utils
import NRUtils
import sys

class CommandLineArgumentExeception(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.custom_message = message

    def __str__(self):
        return "CommandLineArgumentExeception: {}".format(self.custom_message)

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
            for packet in packets:
                sendp(packet, iface=iface)
    else:
        print(message)
        print("File count not be send, address resolution error")

if __name__ == "__main__":
    try:
        targetHostId, file_path = getCommandLineArguments()
        send_file(targetHostId, file_path)
    except CommandLineArgumentExeception as e:
        print("pass valid commandline arguments , syntax is  FileName targetHostId filePath")
