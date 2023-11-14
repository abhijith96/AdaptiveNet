
from scapy.all import sr1, srp1, srp, Raw
from IPv6ExtHdrVLA import IPv6ExtHdrVLA
from scapy.all import packet
from scapy.layers.inet6 import UDP, IPv6
from scapy.layers.l2 import Ether
from Utils import createVlaPacket

def ping():
    # Create an IP packet with an ICMP Echo Request
    ethSrc="00:00:00:00:00:1a" 
    ethDst="00:aa:00:00:00:01"
    vlaSrcList = [4096,4096,4097]
    vlaDstList = [4096, 4096, 4096, 4096, 4096]
    vlaCurrentLevel = 2
    dataPayload = "Ping Request"
    
    # packet = Ether(src="00:00:00:00:00:1a", dst="00:aa:00:00:00:01")/IPv6(src="::1", dst= "2002::2")/UDP()/Raw(load=dataPayload)

    # packet = insert_vla_header(packet, [4096,4096,4097],[4096,4096,4096,4096,4096], 4)

    packet = createVlaPacket(ethDst, ethSrc, vlaSrcList, vlaDstList, vlaCurrentLevel, dataPayload)
    # Send the packet and wait for a response
    reply = srp1(packet,iface="h1a-eth0")


    # Check if a response was received
    if reply:
        if(Ether in reply and IPv6 in reply):
            if reply[IPv6].nh == 48:
                print("reply packet is ", reply)
                ipPayload = IPv6ExtHdrVLA(reply[IPv6].payload)
                if ipPayload[UDP] and ipPayload[UDP].sport == 50001:
                    print("Ping  successful!", ipPayload[Raw].load)
                    return True
                else:
                    print("Ping Failed UDP not found or UDP src port does not match", ipPayload)
            else:
                print("Vla not detected in reply")
                return False
        print("Ping to failed. Unexpected response type.")
        return False
    else:
        print("No response from ping.")
        return False

# Example usage
def main():
   pingStatus = ping()

if __name__ == "__main__":
    main()