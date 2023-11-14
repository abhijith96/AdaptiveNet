
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
    dataPayload = "Hello"
    
    # packet = Ether(src="00:00:00:00:00:1a", dst="00:aa:00:00:00:01")/IPv6(src="::1", dst= "2002::2")/UDP()/Raw(load=dataPayload)

    # packet = insert_vla_header(packet, [4096,4096,4097],[4096,4096,4096,4096,4096], 4)

    packet = createVlaPacket(ethDst, ethSrc, vlaSrcList, vlaDstList, vlaCurrentLevel, dataPayload)

    print("packet is ", packet.show())

    # Send the packet and wait for a response
    reply = srp1(packet,iface="h1a-eth0")


    # Check if a response was received
    if reply:
        print("reply is ", reply.show2())
        if(Ether in reply and IPv6 in reply):
            if reply[IPv6].nh == 48:
                if(IPv6ExtHdrVLA in reply):
                    if reply[UDP] and reply[UDP].sport == 50001:
                        print("Ping  successful!", reply[Raw])
                        return True
                else:
                    print("reply packet is ", packet.show())
                    print("packet raw is ", packet[Raw].load)
                    ipPayload = IPv6ExtHdrVLA(packet[IPv6].payload)
                    if ipPayload[UDP] and ipPayload[UDP].sport == 50001:
                        print("Ping  successful!", ipPayload[Raw])
                        return True
                    else:
                        print("ip payload is ", ipPayload)
            else:
                print("Vla not detected in reply")
                return False
        print("Ping to failed. Unexpected response type.")
        return False
    else:
        print("No response from ping.")

# Example usage
def main():
    ping()

if __name__ == "__main__":
    main()