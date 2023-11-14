
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
    vlaSrcList = [4096,4096,4096,4096,4096]
    vlaDstList = [4096, 4096, 4097]
    vlaCurrentLevel = 4
    dataPayload = "Hello"
    
    # packet = Ether(src="00:00:00:00:00:1a", dst="00:aa:00:00:00:01")/IPv6(src="::1", dst= "2002::2")/UDP()/Raw(load=dataPayload)

    # packet = insert_vla_header(packet, [4096,4096,4097],[4096,4096,4096,4096,4096], 4)

    packet = createVlaPacket(ethDst, ethSrc, vlaSrcList, vlaDstList, vlaCurrentLevel, dataPayload)

    print("packet is ", packet.show())

    # Send the packet and wait for a response
    reply = srp1(packet,iface="h1a-eth0")


    # Check if a response was received
    if reply:
        print("reply is ", reply)
        if(Ether in reply and IPv6 in reply):
            ipPayload = IPv6ExtHdrVLA(packet[Raw].load)
            if ipPayload[UDP] and ipPayload[UDP].sport == 50001:
                print("Ping  successful!", ipPayload[Raw].load)
                return True
           
        print("Ping to failed. Unexpected response type.")
        print(reply.show())
    else:
        print("No response from.")

# Example usage
def main():
    ping()

if __name__ == "__main__":
    main()