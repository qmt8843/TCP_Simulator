import copy
import random
import time
import math

tcp_template = {"src":"0.0.0.0", "dst":"0.0.0.0",
                "seq":0, "ack":0,"headLen":"",
                "resv":"", "flags":"8", "window":"",
                "checksum":"", "urgent":0, "options":[]}

max_segment_size_option = [0x02,0x04,0x05,0xb4]
nop_option = [0x01]
win_scale_option = [0x03,0x03,0x02]
sack_perm_option = [0x04,0x02]

def getTimestampOption():
    tsval = time.time()
    sub_time = round(tsval, -4)
    sub_time /= 100000
    sub_time = math.floor(sub_time)
    sub_time *= 100000
    tsval = tsval-sub_time
    tsval = int(round(tsval, 3)*1000)
    timestamp_option = [0x08,0x0a,0x00,0x00,0x00,0x00]
    print(hex(tsval))

client_ip = "168.198.0.1"
server_ip = "168.198.0.2"
just_syn = "000000000010"

#Create SYN request to server
syn_packet = copy.deepcopy(tcp_template)
syn_packet["src"] = client_ip
syn_packet["dst"] = server_ip
seq_num = random.randint(0, 4294967295) #Get a starting sequence number
syn_packet["seq"] = seq_num
syn_packet["ack"] = 0
syn_packet["flags"] = just_syn
syn_packet["window"] = 8192
syn_packet["checksum"] = 3
syn_packet["options"] = [[0x02,0x04,0x05,0xb4], ]

getTimestampOption()
