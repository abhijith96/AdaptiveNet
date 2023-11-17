
from scapy.all import sr1, srp1, srp, Raw
from IPv6ExtHdrVLA import IPv6ExtHdrVLA
from scapy.all import get_if_addr6, get_if_hwaddr, get_if_list
from scapy.layers.inet6 import UDP, IPv6
from scapy.layers.l2 import Ether
from Utils import createVlaPacket, getMacAddress
import time
from scapy.all import conf

def test():

    ifacelist = get_if_list()
    print(ifacelist)
    ip = get_if_addr6(ifacelist[1])
    print(ip)
    mac = get_if_hwaddr(ifacelist[1])
    print(mac)
    print(conf.route)
    #print(conf.ifaces)

def ping():
    # Create an IP packet with an ICMP Echo Request
    ethSrc= getMacAddress()
    ethDst="00:aa:00:00:00:01"
    vlaSrcList = [4096,4097,4098]
    vlaDstList = [4096, 4096, 4098]
    vlaCurrentLevel = 2
    dataPayload = "Ping Request"
    
    # packet = Ether(src="00:00:00:00:00:1a", dst="00:aa:00:00:00:01")/IPv6(src="::1", dst= "2002::2")/UDP()/Raw(load=dataPayload)

    # packet = insert_vla_header(packet, [4096,4096,4097],[4096,4096,4096,4096,4096], 4)

    packet = createVlaPacket(ethDst, ethSrc, vlaSrcList, vlaDstList, vlaCurrentLevel, dataPayload)

    # Send the packet and wait for a response
    start_time = time.time()

    reply = srp1(packet,iface="h1c-eth0")
    
    end_time = time.time()


    rtt = 0

    # Check if a response was received
    replyMessage = ""
    if reply:
        if(Ether in reply and IPv6 in reply):
            if reply[IPv6].nh == 48:
                print("reply packet is ", reply)
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

# Example usage
def main():
   test()
   (pingStatus,replyMessage, rtt) = ping()
   print(replyMessage)
   print("Round Trip Time is  {:.3f} ".format(rtt*1000))

if __name__ == "__main__":
    main()