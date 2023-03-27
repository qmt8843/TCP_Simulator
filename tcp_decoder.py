import binascii
#packet = "0000c09fa09700a0cc3bbffa08004510003c463c40004006731cc0a80002c0a80001060e001799c5a0ec00000000a0027d78e0a30000020405b40402080a009c27240000000001030300"
#packet = "00005e000101f077c32279a0080045000028ddd6400080060000811548a5a29f87eac90f01bbc6848684edfba882501001fff45e0000"
packet = "f077c32279a030b64f86fe2d08004500002c76490000f706490cb9e080db811548a5eac4c06b6af5fe8700000000600204007b020000020405b4"

eth2_header = packet[0:28]
dst_mac = eth2_header[0:12]
src_mac = eth2_header[12:24]
eth2_types = {"0800":"Internet Protocol version 4 (IPv4)","0806":"Address Resolution Protocol (ARP)","0842":"Wake-on-LAN[8]","22F0":"Audio Video Transport Protocol (AVTP)",
                "22F3":"IETF TRILL Protocol","22EA":"Stream Reservation Protocol","6002":"DEC MOP RC","6003":"DECnet Phase IV, DNA Routing","6004":"DEC LAT",
                "8035":"Reverse Address Resolution Protocol (RARP)","809B":"AppleTalk (Ethertalk)","80F3":"AppleTalk Address Resolution Protocol (AARP)",
                "8100":"VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility","8102":"Simple Loop Prevention Protocol (SLPP)",
                "8103":"Virtual Link Aggregation Control Protocol (VLACP)","8137":"IPX","8204":"QNX Qnet","86DD":"Internet Protocol Version 6 (IPv6)","8808":"Ethernet flow control",
                "8809":"Ethernet Slow Protocols[10] such as the Link Aggregation Control Protocol (LACP)","8819":"CobraNet","8847":"MPLS unicast","8848":"MPLS multicast",
                "8863":"PPPoE Discovery Stage","8864":"PPPoE Session Stage","887B":"HomePlug 1.0 MME","888E":"EAP over LAN (IEEE 802.1X)","8892":"PROFINET Protocol",
                "889A":"HyperSCSI (SCSI over Ethernet)","88A2":"ATA over Ethernet","88A4":"EtherCAT Protocol","88A8":"Service VLAN tag identifier (S-Tag) on Q-in-Q tunnel.",
                "88AB":"Ethernet Powerlink[citation needed]","88B8":"GOOSE (Generic Object Oriented Substation event)","88B9":"GSE (Generic Substation Events) Management Services",
                "88BA":"SV (Sampled Value Transmission)","88BF":"MikroTik RoMON (unofficial)","88CC":"Link Layer Discovery Protocol (LLDP)",
                "88CD":"SERCOS III","88E1":"HomePlug Green PHY","88E3":"Media Redundancy Protocol (IEC62439-2)","88E5":"IEEE 802.1AE MAC security (MACsec)",
                "88E7":"Provider Backbone Bridges (PBB) (IEEE 802.1ah)","88F7":"Precision Time Protocol (PTP) over IEEE 802.3 Ethernet","88F8":"NC-SI",
                "88FB":"Parallel Redundancy Protocol (PRP)","8902":"IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)",
                "8906":"Fibre Channel over Ethernet (FCoE)","8914":"FCoE Initialization Protocol","8915":"RDMA over Converged Ethernet (RoCE)",
                "891D":"TTEthernet Protocol Control Frame (TTE)","893a":"1905.1 IEEE Protocol","892F":"High-availability Seamless Redundancy (HSR)",
                "9000":"Ethernet Configuration Testing Protocol","F1C1":"Redundancy Tag (IEEE 802.1CB Frame Replication and Elimination for Reliability)"}
eth2_type_raw = eth2_header[24:28]
eth2_type = eth2_types[eth2_type_raw]

ip_version_raw = packet[28]
ip_version = int(ip_version_raw, 16)
if ip_version == 4:
    ip_header_length_raw = packet[29]
    ip_header_length = (int(ip_header_length_raw, 16)*32)/8
    ip_end = int(28+(ip_header_length*2))
    ip_header = packet[28:ip_end]
    ip_total_length_raw = packet[32:36]
    ip_total_length = int(ip_total_length_raw, 16)

    ip_id_raw = packet[36:40]
    ip_id = int(ip_id_raw, 16)

    ip_flags_raw = packet[40]
    ip_flags_dec = int(ip_flags_raw, 16)
    ip_flags_bin = format(ip_flags_dec, "04b")
    ip_flag_reserved = ip_flags_bin[0]
    ip_flag_dont = ip_flags_bin[1]
    ip_flag_more = ip_flags_bin[2]

    ip_flag_offset_lead = ip_flags_bin[3]
    ip_flag_offset_rest_hex = packet[41:44]
    ip_flag_offset_rest_dec = int(ip_flag_offset_rest_hex, 16)
    ip_flag_offset_rest_bin = format(ip_flag_offset_rest_dec, "013b")
    ip_flag_offset_bin = ip_flag_offset_lead + ip_flag_offset_rest_bin

    ip_ttl_raw = packet[44:46]
    ip_ttl = int(ip_ttl_raw, 16)

    ip_protocol_raw = packet[46:48]
    ip_protocol_list = {"0":"HOPOPT","01":"ICMP","02":"IGMP","03":"GGP","04":"IP-in-IP","05":"ST","06":"TCP","07":"CBT","08":"EGP","09":"IGP","0A":"BBN-RCC-MON","0B":"NVP-II",
                        "0C":"PUP","0D":"ARGUS","0E":"EMCON","0F":"XNET","10":"CHAOS","11":"UDP","12":"MUX","13":"DCN-MEAS","14":"HMP","15":"PRM","16":"XNS-IDP","17":"TRUNK-1",
                        "18":"TRUNK-2","19":"LEAF-1","1A":"LEAF-2","1B":"RDP","1C":"IRTP","1D":"ISOTP4","1E":"NETBLT","1F":"MFE-NSP","20":"MERIT-INP","21":"DCCP","22":"3PC","23":"IDPR",
                        "24":"XTP","25":"DDP","26":"IDPR-CMTP","27":"TP++","28":"IL","29":"IPv6","2A":"SDRP","2B":"IPv6-Route","2C":"IPv6-Frag","2D":"IDRP","2E":"RSVP",
                        "2F":"GRE","30":"DSR","31":"BNA","32":"ESP","33":"AH","34":"I-NLSP","35":"SwIPe","36":"NARP","37":"MOBILE","38":"TLSP","39":"SKIP","3A":"IPv6-ICMP",
                        "3B":"IPv6-NoNxt","3C":"IPv6-Opts","3D":"UNKNOWN","3E":"CFTP","3F":"UNKNOWN","40":"SAT-EXPAK","41":"KRYPTOLAN","42":"RVD","43":"IPPC","44":"UNKNOWN",
                        "45":"SAT-MON","46":"VISA","47":"IPCU","48":"CPNX","49":"CPHB","4A":"WSN","4B":"PVP","4C":"BR-SAT-MON","4D":"SUN-ND","4E":"WB-MON","4F":"WB-EXPAK",
                        "50":"ISO-IP","51":"VMTP","52":"SECURE-VMTP","53":"VINES","54":"TTP","54":"IPTM","55":"NSFNET-IGP","56":"DGP","57":"TCF","58":"EIGRP","59":"OSPF",
                        "5A":"Sprite-RPC","5B":"LARP","5C":"MTP","5D":"AX.25","5E":"OS","5F":"MICP","60":"SCC-SP","61":"ETHERIP","62":"ENCAP","63":"UNKNOWN","64":"GMTP",
                        "65":"IFMP","66":"PNNI","67":"PIM","68":"ARIS","69":"SCPS","6A":"QNX","6B":"A/N","6C":"IPComp","6D":"SNP","6E":"Compaq-Peer","6F":"IPX-in-IP",
                        "70":"VRRP","71":"PGM","72":"UNKOWN","73":"L2TP","74":"DDX","75":"IATP","76":"STP","77":"SRP","78":"UTI","79":"SMP","7A":"SM","7B":"PTP",
                        "7C":"IS-IS over IPv4","7D":"FIRE","7E":"CRTP","7F":"CRUDP","80":"SSCOPMCE","81":"IPLT","82":"SPS","83":"PIPE","84":"SCTP","85":"FC","86":"RSVP-E2E-IGNORE",
                        "87":"Mobility Header","88":"UDPLite","89":"MPLS-in-IP","8A":"manet","8B":"HIP","8C":"Shim6","8D":"WESP","8E":"ROHC","8F":"Ethernet","FF":"Reserved"}
    ip_protocol = ip_protocol_list[ip_protocol_raw]

    ip_checksum = packet[48:52]

    ip_src_raw = packet[52:60]
    src_octets = [ip_src_raw[i:i+2] for i in range(0, len(ip_src_raw), 2)]
    src_ip_list = [int(i, 16) for i in reversed(src_octets)]
    src_ip_list.reverse()
    ip_src = '.'.join(str(i) for i in src_ip_list)

    ip_dst_raw = packet[60:68]
    dst_octets = [ip_dst_raw[i:i+2] for i in range(0, len(ip_dst_raw), 2)]
    dst_ip_list = [int(i, 16) for i in reversed(dst_octets)]
    dst_ip_list.reverse()
    ip_dst = '.'.join(str(i) for i in dst_ip_list)

tcp_header_length_raw = packet[ip_end+24]
tcp_header_length = (int(tcp_header_length_raw, 16)*32)/8
tcp_end = int(ip_end+(tcp_header_length*2))
tcp_header = packet[ip_end:tcp_end]

tcp_src_port_hex = tcp_header[0:4]
tcp_src_port_dec = int(tcp_src_port_hex, 16)

tcp_dst_port_hex = tcp_header[4:8]
tcp_dst_port_dec = int(tcp_dst_port_hex, 16)

tcp_seq_hex = tcp_header[8:16]
tcp_seq_dec = int(tcp_seq_hex, 16)

tcp_ack_hex = tcp_header[16:24]
tcp_ack_dec = int(tcp_ack_hex, 16)

tcp_header_len_hex = tcp_header[24:25]
tcp_header_len_dec = int(tcp_header_len_hex, 16)

tcp_flags_reserved = tcp_header[25:28]

tcp_win_size_hex = tcp_header[28:32]
tcp_win_size_dec = int(tcp_win_size_hex, 16)

tcp_check_sum = tcp_header[32:36]

tcp_urgent_pointer = tcp_header[36:40]

tcp_options_raw = tcp_header[40:48]

def print_test():
    print(tcp_header_len_dec)
    print(tcp_win_size_dec)
    print(tcp_check_sum)
    print(tcp_urgent_pointer)
    print(tcp_options_raw)

def print_all():
    print("Eth2 Header: ", eth2_header)
    print("\tDestination MAC: ", eth2_header)
    print("\tSource MAC: ", eth2_header)
    print("\tType: ", eth2_type)
    print("IP Header: ", ip_header)
    print("\tVersion: ", ip_version)
    print("\tHeader length: ", ip_header_length)
    print("\tTotal Length: ", ip_total_length)
    print("\tIdentification: ", ip_id)
    print("\tReserved Bit: ", ip_flag_reserved)
    print("\tDon't Fragment: ", ip_flag_dont)
    print("\tMore Fragments: ", ip_flag_more)
    print("\tFlag Offset: ", ip_flag_offset_bin)
    print("\tTime to live: ", ip_ttl)
    print("\tProtocol: ", ip_protocol)
    print("\tHeader checksum: ", ip_checksum)
    print("\tSource Address: ", ip_src)
    print("\tDestination Address: ", ip_dst)
    print("TCP Header: ", tcp_header)

print_test()
