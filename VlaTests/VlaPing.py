
from scapy.all import sr1, srp1, srp, Raw
import sys
from IPv6ExtHdrVLA import IPv6ExtHdrVLA
from scapy.all import get_if_addr6, get_if_hwaddr, get_if_list
from scapy.layers.inet6 import UDP, IPv6
from scapy.layers.l2 import Ether
from Utils import createVlaPacket, getMacAddress
import time
from scapy.all import conf
from NRUtils import resolveHostVlaAddress, getCurrentHostVlaAddress, getDefaultMacAddress, getDefaultInterface
import subprocess
import os
import signal
import time

def test():

    ifacelist = get_if_list()
    print(ifacelist)
    ip = get_if_addr6(ifacelist[1])
    print(ip)
    mac = get_if_hwaddr(ifacelist[1])
    print(mac)
    print(conf.route)
    #print(conf.ifaces)

def getCommandLineArguments():
    try:
        targetHost = sys.argv[1]
        return targetHost
    except Exception():
        raise Exception("Pass Comandline Arguments Properly") 

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

    targetVlaStatus, targetVlaAddress, gatewayMac, message = resolveHostVlaAddress(targetHostId)
    if(not hostVlaStatus):
        replyMessage = "vla address for target device %s not found".format(targetHostId)
        return (False, replyMessage, None)
    
    ethDst=gatewayMac
    vlaSrcList = hostVlaAddress
    vlaDstList = targetVlaAddress
    vlaCurrentLevel = len(hostVlaAddress) - 1
    dataPayload = "Ping Request"

    packet = createVlaPacket(ethDst, ethSrc, vlaSrcList, vlaDstList, vlaCurrentLevel, dataPayload)

    # Send the packet and wait for a response
    start_time = time.time()

    reply = srp1(packet,iface=defaultInterface)
    
    end_time = time.time()


    rtt = 0

    # Check if a response was received
   
    if reply:
        if(Ether in reply and IPv6 in reply):
            if reply[IPv6].nh == 48:
                #print("reply packet is ", reply)
                ipPayload = IPv6ExtHdrVLA(reply[IPv6].payload)
                if ipPayload[UDP] and ipPayload[UDP].sport == 50001:
                    replyMessage = "Ping  successful! " + ipPayload[Raw].load
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

def run_python_file_in_namespace(namespace_name, python_file_path):
    try:
        # Use nsenter to enter the network namespace and run the Python file
        nsenter_command = ["nsenter", "--net --mount --ipc --pid --uts", "--target", namespace_name, "python", python_file_path]
        process = subprocess.Popen(nsenter_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return process

    except subprocess.CalledProcessError as e:
            print(f"Error: {e}")
            return None
    
def main():
    targetHost = "00:00:00:00:00:1b"
    try:
        targetHost = getCommandLineArguments()
    except Exception as e:
            print("ping target not found as command line argument using default target : " +  e)
    (pingStatus,replyMessage, rtt) = vla_ping(targetHost)
    print(replyMessage)
    print("Round Trip Time is  {:.3f} ".format(rtt*1000))

    namespace_name_1 = "10"
    namespace_name_2 = "12"
    python_file_path_2 = "/home/VlaTests/VlaPing.py"
    python_file_path_1 = "/home/VlaTests/VlaPingListener.py"

    # Run the first Python file in the first namespace
    process_1 = run_python_file_in_namespace(namespace_name_1, python_file_path_1)

    # Wait for a moment to ensure the first file is running
    time.sleep(5)

    # Run the second Python file in the second namespace
    process_2 = run_python_file_in_namespace(namespace_name_2, python_file_path_2)

    # Wait for the second file to finish and capture its output
    output, errors = process_2.communicate()

    # Terminate the first file when the second file ends
    process_1.terminate()

    # Optionally wait for the first file to terminate gracefully
    process_1.wait()

    print("Output of the second file:")
    print(output.decode('utf-8'))
    print("Errors of the second file:")
    print(errors.decode('utf-8'))
    print("Both files completed.")


if __name__ == "__main__":
    main()