from scapy.all import Ether, ARP, wrpcap

# Create a basic ARP request packet
arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
    pdst="192.168.1.1",
    hwsrc="00:11:22:33:44:55",
    psrc="192.168.1.100",
    op=1  # ARP request
)

# Save the packet to a .pcap file
wrpcap("legal_ARP_request.pcap", [arp_request])
