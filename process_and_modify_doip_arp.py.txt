import time
from scapy.all import *
# from someip.eth_scapy_someip import eth_scapy_someip
# from someip.eth_scapy_someip import eth_scapy_sd

# pcap_root_dir = r"C:\Users\Arilou\OneDrive - NNG Kft\ethernet\v1.5\PCAPs_for_demo\in_progress"
in_pcap_root_dir = r"C:\Users\user\Desktop\Arilou\Sentinel\configuration_create_py_Nir_SE\eth_ids-py_new\noam\Lear_demo_2\in_Pcaps"
out_pcap_root_dir = r"C:\Users\user\Desktop\Arilou\Sentinel\configuration_create_py_Nir_SE\eth_ids-py_new\noam\Lear_demo_2\out_Pcaps"

# orignal fiel
orig_file = os.path.join(in_pcap_root_dir, 'legal_DoIP.pcap')

# new file locaition
new_file = os.path.join(out_pcap_root_dir, 'illegal_legal_DoIP_entity.pcap')

# rd_pcap comes from scapy and loads in our pcap file - read file - into *packets*
packets = list(rdpcap(orig_file))
new_packets = packets

# src
# new_packets[0][Ether].src = '02:00:00:00:01:03'    # src

# dst
# new_packets[0][Ether].dst = '02:00:00:00:01:05'    # dst

# VLAN
# new_packets[0][Ether][Dot1Q].vlan = 3  # vlan

# AVTP_stream_id
# new_packets[0][Ether][Dot1Q].load = b'\x02\x81\x00\x00\x02\x00\x00\x00\x01\x03\x00\x01yq\xc3\xe1\x04\x00\x01\x10\x00\x08\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
# new_packets[0][Ether][Dot1Q].load = b'\x02\x81\x00\x00\x02\x00\x00\x00\x01\x07\x00\x01yq\xc3\xe1\x04\x00\x01\x10\x00\x08\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

# PTPv2_ClockIdentity
# new_packets[0][Ether][Dot1Q].load = b'\x10\x02\x00,\x00\x00\x02\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\xff\xfe\x00\x01\x03\x00\x01\x00\x01\x00\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
# new_packets[0][Ether][Dot1Q].load = b'\x10\x02\x00,\x00\x00\x02\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\xff\xfe\x00\x01\x07\x00\x01\x00\x01\x00\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

# ARP op_mode - request
# new_packets[0][Ether][ARP].op=4

# ARP spoof - response
# new_packets[0][Ether][ARP].hwdst = '08:28:27:3f:1c:8f'

# ARP psrc - response
# new_packets[0][Ether][ARP].psrc = '192.168.1.10'

# ARP hwdst- response
# new_packets[0][Ether][ARP].hwdst = '02:00:00:00:01:03'

# ARP pdst - request
# new_packets[0][Ether][ARP].pdst = '192.168.1.3'

# ARP poison - request     src_mac, hwsrc, hwdst
# new_packets[0][Ether].src = '02:01:01:01:01:01'    # src
# new_packets[0][Ether][ARP].hwsrc = '02:01:01:01:01:01'
# new_packets[0][Ether][ARP].hwdst = 'ff:ff:ff:ff:ff:ff'

# ARP ICMP smurf poison
# new_packets[0][Ether].src = '02:00:00:00:01:01'    # src
# new_packets[0][Ether].dst = 'FF:FF:FF:FF:FF:FF'    # dst

# AR_PDU_IP_protocol
# new_packets[0][Ether][Dot1Q][IP].proto = 6  # vlan

# AR_PDU_Source_IP
# new_packets[0][Ether][Dot1Q][IP].src = '192.168.1.1'  # vlan

# AR_PDU_Source_IP
# new_packets[0][Ether][Dot1Q][IP].dst = '192.168.1.2'  # vlan


# AR_PDU_Source_IP
# new_packets[0][Ether][Dot1Q][IP][UDP].sport = 30000  # vlan  - sport == source

# AR_PDU_Source_IP
# new_packets[0][Ether][Dot1Q][IP][UDP].dport = 30000  # vlan   - dport == destination

# AR_PDU_service_id_1 ,  (mark packet as SOME-IP in Wireshark)
# new_packets[0][Ether][Dot1Q][IP][UDP].load = b'\x03\xe8\x00d\x00\x00\x00\x04\x00\x00\x01\x00\x03\xe9\x00d\x00\x00\x00\x0c\x00\x00_\x0b@B\x0f\x00@B\x0f\x00\x03\xe8\x00e\x00\x00\x00\x08\x80\x96\x98\x00R.\xfc\x00\x03\xea\x00d\x00\x00\x00\n_\x0b@\x9c\x00\x00@\x9c\x00\x00'
# new_packets[0][Ether][Dot1Q][IP][UDP].load = b'\x03\xe9\x00d\x00\x00\x00\x04\x00\x00\x01\x00\x03\xe9\x00d\x00\x00\x00\x0c\x00\x00_\x0b@B\x0f\x00@B\x0f\x00\x03\xe8\x00e\x00\x00\x00\x08\x80\x96\x98\x00R.\xfc\x00\x03\xea\x00d\x00\x00\x00\n_\x0b@\x9c\x00\x00@\x9c\x00\x00'

# AR_PDU_method_id_1 ,  (mark packet as SOME-IP in Wireshark)
# new_packets[0][Ether][Dot1Q][IP][UDP].load = b'\x03\xe8\x00d\x00\x00\x00\x04\x00\x00\x01\x00\x03\xe9\x00d\x00\x00\x00\x0c\x00\x00_\x0b@B\x0f\x00@B\x0f\x00\x03\xe8\x00e\x00\x00\x00\x08\x80\x96\x98\x00R.\xfc\x00\x03\xea\x00d\x00\x00\x00\n_\x0b@\x9c\x00\x00@\x9c\x00\x00'
# new_packets[0][Ether][Dot1Q][IP][UDP].load = b'\x03\xe8\x00e\x00\x00\x00\x04\x00\x00\x01\x00\x03\xe9\x00d\x00\x00\x00\x0c\x00\x00_\x0b@B\x0f\x00@B\x0f\x00\x03\xe8\x00e\x00\x00\x00\x08\x80\x96\x98\x00R.\xfc\x00\x03\xea\x00d\x00\x00\x00\n_\x0b@\x9c\x00\x00@\x9c\x00\x00'

# AR_PDU_service_ID_2 ,  (mark packet as SOME-IP in Wireshark)
# new_packets[0][Ether][Dot1Q][IP][UDP].load = b'\x03\xe8\x00d\x00\x00\x00\x04\x00\x00\x01\x00\x03\xe9\x00d\x00\x00\x00\x0c\x00\x00_\x0b@B\x0f\x00@B\x0f\x00\x03\xe8\x00e\x00\x00\x00\x08\x80\x96\x98\x00R.\xfc\x00\x03\xea\x00d\x00\x00\x00\n_\x0b@\x9c\x00\x00@\x9c\x00\x00'
# new_packets[0][Ether][Dot1Q][IP][UDP].load = b'\x03\xe8\x00d\x00\x00\x00\x04\x00\x00\x01\x00\x03\xe8\x00d\x00\x00\x00\x0c\x00\x00_\x0b@B\x0f\x00@B\x0f\x00\x03\xe8\x00e\x00\x00\x00\x08\x80\x96\x98\x00R.\xfc\x00\x03\xea\x00d\x00\x00\x00\n_\x0b@\x9c\x00\x00@\x9c\x00\x00'


# AR_PDU_method_ID_2 ,  (mark packet as SOME-IP in Wireshark)
# new_packets[0][Ether][Dot1Q][IP][UDP].load = b'\x03\xe8\x00d\x00\x00\x00\x04\x00\x00\x01\x00\x03\xe9\x00d\x00\x00\x00\x0c\x00\x00_\x0b@B\x0f\x00@B\x0f\x00\x03\xe8\x00e\x00\x00\x00\x08\x80\x96\x98\x00R.\xfc\x00\x03\xea\x00d\x00\x00\x00\n_\x0b@\x9c\x00\x00@\x9c\x00\x00'
# new_packets[0][Ether][Dot1Q][IP][UDP].load = b'\x03\xe8\x00d\x00\x00\x00\x04\x00\x00\x01\x00\x03\xe9\x00e\x00\x00\x00\x0c\x00\x00_\x0b@B\x0f\x00@B\x0f\x00\x03\xe8\x00e\x00\x00\x00\x08\x80\x96\x98\x00R.\xfc\x00\x03\xea\x00d\x00\x00\x00\n_\x0b@\x9c\x00\x00@\x9c\x00\x00'


# DoIP_entity (src MAC)
new_packets[0][Ether].src = '02:00:00:00:01:03'    # src

# DoIP_VIN (manufacturer)
# new_packets[0][Ether][Dot1Q][IP][UDP].load = b'\x02\xfd\x00\x04\x00\x00\x00!AR1LU0VEH1CLE0001 \x00\x02\x00\x00\x00\x01\x01\x02\x00\x00\x00\x01\x01\x00\x01'
# new_packets[0][Ether][Dot1Q][IP][UDP].load = b'\x02\xfd\x00\x04\x00\x00\x00!AR1LU0VEH1CLE0002 \x00\x02\x00\x00\x00\x01\x01\x02\x00\x00\x00\x01\x01\x00\x01'

# DoIP_LA (logical_address)
# new_packets[0][Ether][Dot1Q][IP][UDP].load = b'\x02\xfd\x00\x04\x00\x00\x00!AR1LU0VEH1CLE0001 \x00\x02\x00\x00\x00\x01\x01\x02\x00\x00\x00\x01\x01\x00\x01'
# new_packets[0][Ether][Dot1Q][IP][UDP].load = b'\x02\xfd\x00\x04\x00\x00\x00!AR1LU0VEH1CLE0002 \x00\x01\x00\x00\x00\x01\x01\x02\x00\x00\x00\x01\x01\x00\x01'


# DoIP_EID (logical_address)
# new_packets[0][Ether][Dot1Q][IP][UDP].load = b'\x02\xfd\x00\x04\x00\x00\x00!AR1LU0VEH1CLE0001 \x00\x02\x00\x00\x00\x01\x01\x02\x00\x00\x00\x01\x01\x00\x01'
# new_packets[0][Ether][Dot1Q][IP][UDP].load = b'\x02\xfd\x00\x04\x00\x00\x00!AR1LU0VEH1CLE0002 \x00\x02\x00\x00\x00\x01\x01\x02\x00\x00\x00\x01\x03\x00\x01'






#---------------------------------------------------------------------------



prev_time = time.time()
packets_in_loop = []

for packet_i in new_packets:
    # packet_i.time = prev_time + random.randint(1, 20) / 1.0e4
    packet_i.time = prev_time + 1/1.0e4
    prev_time = packet_i.time
    #print("packet_i.time is: {}".format(packet_i.time))
    packets_in_loop.append(packet_i)

wrpcap(new_file, packets_in_loop)
