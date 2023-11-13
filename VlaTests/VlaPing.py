from scapy.all import IP, ICMP, sr1
from IPv6ExtHdrVLA import IPv6ExtHdrVLA

def ping(destination_ip):
    # Create an IP packet with an ICMP Echo Request
    packet = IP(dst=destination_ip) / ICMP()

    # Send the packet and wait for a response
    reply = sr1(packet, timeout=2, verbose=False)

    # Check if a response was received
    if reply:
        # Check if the response is an ICMP Echo Reply
        if reply.haslayer(ICMP) and reply[ICMP].type == 0:
            print(f"Ping to {destination_ip} successful!")
        else:
            print(f"Ping to {destination_ip} failed. Unexpected response type.")
    else:
        print(f"No response from {destination_ip}.")

# Example usage
ping("8.8.8.8") 