import requests
import os
import pprint
import time
import subprocess
import psutil
import netifaces
# from analyze_syslog_pcap import analyze_syslog_pcap_class
from scapy.all import PcapReader, Ether, sendp
from business_logic.tests.manual_tests.logic import burn
from analyze_syslog_pcap import analyze_syslog_pcap_class



class RecordingRunner(object):
    # code Definitions
    def __init__(self, send_interface="enp15s0", recording_interface="enp16s0"):
        self.send_interface = send_interface
        self.recording_interface = recording_interface
        self.send_file = ""
        self.recording_file = ""

    # PCAP location Capture, received and operation
    def run_recording(self, timeout=1, recording_file="dump_file.pcap", send_file=''):
        self.recording_file = recording_file
        self.send_file = send_file

        # TCP_Dump:
        a = subprocess.Popen("sudo timeout %d tcpdump -i %s -U --immediate-mode -s0 -v -w %s" % (timeout, self.recording_interface, self.recording_file),
                             stdout=subprocess.PIPE, shell=True)

        print("sudo tcpdump -i %s -U --immediate-mode -s0 -v -w %s" % (self.recording_interface, self.recording_file))

        # TCP_Replay:
        os.system("sudo tcpreplay -i %s -p 100 -K %s" % (self.send_interface, send_file))

        print("sudo tcpreplay -i %s -p 100 -K %s" % (self.send_interface, send_file))
        time.sleep(timeout+0.1)
        print("finished dump")


class CM_Handler(object):

    def __init__(self, host='localhost', port=247, MGMT_port = None, port_NIC_dict = None, injection_ingress_port = None, print_flag = None
                 , Syslog_port = None , RMU_port = None):
        self.host = host
        self.port = port
        self.url_base = "http://%s:%d/sentinel/" % (self.host, self.port)
        self.status_dict = dict()
        print('url = ', self.url_base)
        self.status = ""

        self.MGMT_port = MGMT_port
        self.Syslog_port = Syslog_port
        self.RMU_port =  RMU_port
        self.port_NIC_dict = port_NIC_dict
        self.injection_ingress_port = injection_ingress_port
        self.print_flag = print_flag
        # get MGMT NIC MAC
        addrs = psutil.net_if_addrs()
        MGMT_NIC = self.port_NIC_dict[self.MGMT_port]
        if addrs[MGMT_NIC][0].netmask:
            # This is is an IP address. Use the next element.
            self.MGMT_NIC_MAC = addrs[MGMT_NIC][1].address
        else:
            self.MGMT_NIC_MAC = addrs[MGMT_NIC][0].address


    def print_state(self):
        # tries to get context: None and  default bahavior: None
        self.get_status()
        print("context: %s\ndefault bahavior: %s" % (
        self.status_dict.get('context'), self.status_dict.get('default_behavior')))


    def upload_firmware(self):
        # clear board counters
        # http://localhost:247/sentinel/upload_firmware
        os.system("sudo ifconfig enp16s0 192.168.1.241 netmask 255.255.255.0 up")

        url = self.url_base + "upload_firmware"
        response = requests.request("POST", 'http://localhost:247/sentinel/firmware/upload')

        os.system("ifconfig enp16s0 0.0.0.0")
        print('counters_cleared')




    def get_status(self):
        # get board status
        # http://localhost:247/sentinel/status
        # Example:
        # {"fw_version": "MRVL50xx-Sentinel-ETH-1.2.0 (dev_STNETH.1.2.0 #ebc99e9-dirty)", "conf_version": "1.2.0",
        #  "security_event_counter": 0, "processed_msg_counter": 6558, "processed_allow": "105", "processed_deny": "84",
        #  "processed_default_behvaior": "6369", "worst_processing_time": "60", "avg_processing_time": "23",
        #  "current_cpu_load": "0", "avg_cpu_load": "0", "max_cpu_load": "2", "restart_uptime": 713, "after_init": 22638,
        #  "system_mode": "167772160", "default_behavior": "4100", "active_ruleset": "0", "active_context": "5"}

        os.system("sudo ifconfig enp16s0 192.168.1.241 netmask 255.255.255.0 up")

        url = self.url_base + "status"
        response = requests.request("GET", url)

        os.system("ifconfig enp16s0 0.0.0.0")
        print(response.text)


    def set_context(self, context):
        # modify board context    : http://localhost:247/sentinel/context/1

        os.system("sudo ifconfig enp16s0 192.168.1.241 netmask 255.255.255.0 up")

        url = self.url_base + "context/%d" % context
        response = requests.request("GET", url)
        print(url)
        os.system("ifconfig enp16s0 0.0.0.0")

    def set_default_behavior(self, behavior):
        # http://localhost:247/sentinel/default_behavior/2

        # modify board default behavior
        url = self.url_base + "default_behavior/%d" % behavior
        response = requests.request("GET", url)
        pass

    # ports firewall added (so not to all Marvell generated packets)
    def assign_IP_to_MGMT_NIC(self):
        addrs = psutil.net_if_addrs()
        MGMT_NIC = self.port_NIC_dict[self.MGMT_port]
        if addrs[MGMT_NIC][0].netmask:
            # This is is an IP address. Do nothing. Use the next element.
            MGMT_NIC_MAC = addrs[MGMT_NIC][1].address
        else:
            MGMT_NIC_MAC = addrs[MGMT_NIC][0].address

            # assign IP address for MGMT commands to work.
            assign_IP_cmd = 'ifconfig %s 192.168.1.241 netmask 255.255.255.0' % MGMT_NIC
            os.system(assign_IP_cmd)

    def remove_IP_from_MGMT_NIC(self):
        remove_IP_cmd = 'ifconfig %s 0.0.0.0' % self.port_NIC_dict[self.MGMT_port]
        os.system(remove_IP_cmd)

    def set_tcfilter_rules(self):
        read_cmd_dict = {}

        # get MAC list
        MAC_list = []
        for interface in netifaces.interfaces():
            interface_AF_LINK = netifaces.ifaddresses(interface)[netifaces.AF_LINK]
            interface_addr = interface_AF_LINK[0]['addr']
            if interface_addr != '00:00:00:00:00:00':
                MAC_list += [interface_addr]
        MAC_list.sort()

        # injection ports filter
        if self.injection_ingress_port is not list:
            port_list = [self.injection_ingress_port]
        else:
            port_list = self.injection_ingress_port

        # add the MGMT port
        if self.MGMT_port not in port_list:
            port_list += [self.MGMT_port]

        # add Syslog port
        if self.Syslog_port not in port_list:
            port_list += [self.Syslog_port]

        # add RMU port
        if self.RMU_port not in port_list:
            port_list += [self.RMU_port]

        for port in port_list:
            NIC = self.port_NIC_dict[port]

            read_root_cmd = 'sudo tc -s filter ls dev %s parent 1:0 protocol all' % NIC
            filter_0x9101_cmd = 'sudo tc filter add dev %s protocol all parent 1:0 prio 1 u32 match u32 0x00009101 0x0000ffff at -4 action pass' % NIC
            filter_0x6559_cmd = 'sudo tc filter add dev %s protocol all parent 1:0 prio 1 u32 match u32 0x00006559 0x0000ffff at -4 action pass' % NIC
            read_cmd_dict.update({port: {'NIC': NIC, 'print_cmd': read_root_cmd}})
            proc = subprocess.Popen([read_root_cmd], stdout=subprocess.PIPE, shell=True)
            (out, err) = proc.communicate()
            proc.terminate()
            if out:
                clear_root_cmd = 'sudo tc qdisc del dev %s root' % NIC
                os.system(clear_root_cmd)
            create_root_cmd = 'sudo tc qdisc add dev %s root handle 1:0 htb' % NIC
            filter_SRC_MAC_cmd_list = []
            for MAC in MAC_list:
                filter_SRC_MAC_cmd_list += [
                    'sudo tc filter add dev %s protocol all parent 1:0 prio 1 u32 match ether src %s action drop' % (
                    NIC, MAC)]
            os.system(create_root_cmd)
            os.system(filter_0x9101_cmd)
            os.system(filter_0x6559_cmd)
            for str_elem in filter_SRC_MAC_cmd_list:
                os.system(str_elem)

        if self.print_flag:
            for port in port_list:
                print('port %d, NIC %s, %s' % (port, read_cmd_dict[port]['NIC'], read_cmd_dict[port]['print_cmd']))
                os.system(read_cmd_dict[port]['print_cmd'])


    def inject_pcap_per_port(self, pcap_full_filename):

        switch_address_system_pc1 = ('02:00:00:00:00:01', '192.168.1.111')  # 5072
        port_NIC_dict_system_pc1 = {1: 'enp8s0',  # 00:0A:CD:39:EE:8B
                                    2: 'enp7s0',  # 00:0A:CD:39:EE:8A
                                    3: 'enp6s0',  # 00:0A:CD:39:EE:89
                                    4: 'enp5s0',  # 00:0A:CD:39:EE:88
                                    5: 'eno1',  # 00:D8:61:73:2A:1C
                                    6: '',  # 00:D8:61:73:2A:1B enp10s0
                                    7: 'enp15s0',  # 00:e0:4c:68:ab:d1
                                    8: 'enp16s0'}  # 00:e0:4c:68:ab:d2
        self.src_mac_port_dict = {'02:00:00:00:01:01': 7, '02:00:00:00:00:33': 8}

        self.port_NIC_dict = port_NIC_dict_system_pc1

        packets = PcapReader(pcap_full_filename)
        for i, p in enumerate(packets):
            # msg_bytes = binascii.hexlify(bytes(p))
            # msg_raw = msg_bytes.decode("utf-8")

            src_mac = p[Ether].src
            ingress_port = self.src_mac_port_dict[src_mac]
            iface = self.port_NIC_dict[ingress_port]
            sendp(p, iface=iface, verbose=0)
            if (i + 1) % 100 == 0:
                print('%d' % (i + 1))

        print('%s: %d packets' % (pcap_full_filename, i + 1))
        packets.close()


if __name__ == '__main__':

    dumped_syslog_pcap_full_filename = '/home/system-pc1-linux/noam/eth_ids-py/15_packets_basic_88Q5072/rsg_basic_results.pcap'
    injected_pcap_full_filename = '/home/system-pc1-linux/noam/eth_ids-py/pcaps/rsg_basic_88Q5072/rsg_basic.pcap'

    port_NIC_dict_system_pc1 = {1: 'enp8s0',
                                2: 'enp7s0',
                                3: 'enp6s0',
                                4: 'enp5s0',
                                5: 'eno1',
                                6: 'enp13s0',
                                7: 'enp15s0',
                                8: 'enp16s0'}

    burn_question = input('Would you like to burn .bin file (y/n) ?')
    if burn_question == 'y':
    #    burn_file = '/home/system-pc1-linux/noam/eth_ids-py/pcaps/rsg_basic_88Q5072/configuration/ARILOU_CONFIGURATION_10_10_2021-08_30_42/ARILOU_CONFIGURATION.bin'
        burn_file = '/home/system-pc1-linux/noam/eth_ids-py/pcaps/rsg_basic_88Q5072/configuration/local_basic_13_10_2021-10_48_41/local_basic.bin'
        burn(burn_file)
    else:
        print('Not burning bin file')

    CM = CM_Handler(host='localhost', port=247, MGMT_port = 8, port_NIC_dict = port_NIC_dict_system_pc1, injection_ingress_port = 7, print_flag = 1, Syslog_port = 8 , RMU_port =8)

    CM.set_tcfilter_rules()

    # to clear counters of HW:
    CM.upload_firmware()


    if os.path.isfile(dumped_syslog_pcap_full_filename):
        os.remove(dumped_syslog_pcap_full_filename)

    # TCPDUMP:
    # tcpdump_cmd_list = ['tcpdump', '-i', port_NIC_dict[MGMT_port], 'port 514', '-s0', '-w', syslog_pcap_full_filename]
    tcpdump_cmd_list = ['tcpdump', '-i', 'enp16s0', 'port 514', '-s0', '-w', dumped_syslog_pcap_full_filename]
    tcpdump_process = subprocess.Popen(tcpdump_cmd_list, stdout=subprocess.PIPE)

    time.sleep(1)  # Sleep for 1 second



    # definition update:
    CM.set_default_behavior(3)

    rr = RecordingRunner()

    recording_name = "dump.pcap"
    rr.run_recording(send_file=injected_pcap_full_filename)

    print('_______________________')

    time.sleep(1)  # Sleep for 1 second
    tcpdump_process.terminate()  # close tcpdump


    # verify CEF reports
    analyze_syslog_flag = 1
    # baseline_name - cef txt full name
    # input_CEF_report_filename = baseline_name + '_BL_and_CEF_report_with_hash.txt'
    # input_CEF_report_full_filename = os.path.join(test_result_dir, input_CEF_report_filename)
    # input_CEF_report_full_filename = os.path.abspath(input_CEF_report_full_filename)
    input_CEF_report_full_filename = '/home/system-pc1-linux/noam/eth_ids-py/15_packets_basic_88Q5072/test/rsg_basic_BL_and_CEF_report_with_hash.txt'
    # syslog_pcap_filename = baseline_name + '_CEF_report.pcap'
    # syslog_pcap_full_filename = os.path.join(test_on_switch_dir, syslog_pcap_filename)


    if analyze_syslog_flag:
        time.sleep(1)
        analyze_syslog_pcap_i = analyze_syslog_pcap_class(input_CEF_report_full_filename, dumped_syslog_pcap_full_filename)
        print('\n====CEF_analysis:')
        result_dict = analyze_syslog_pcap_i.analyze_syslog(print_flag=1)
        print('%d errors in %d CEF reports.' % (result_dict['err_counter'], result_dict['report_counter']))


    # unlock all files in pcap_root_dir
    # pcap_root_dir = '2'
    # os.system('chmod 777 -R %s' % pcap_root_dir)

