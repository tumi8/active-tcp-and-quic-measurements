# Python code for Extracting
# TCP flows from a pcap

#!/usr/bin/python

import argparse
import json
import os

from helper.parse_config import *

# Create a command line arguments parser
parser = argparse.ArgumentParser(description='Refined TCP RCA tool')

# Add necessary arguments
parser.add_argument('-c','--conf', metavar='config_file', type=str, help='Name of the configuration file', required=True)
parser.add_argument('-i','--input_pcap', metavar='input_pcap_file', type=str, help='Name of the input PCAP file', required=True)
parser.add_argument('-o','--output_pcap', metavar='output_pcap_file', type=str, help='Name of the output PCAP file', required=True)

# Extract arguments
sys.stdout.write("\n===============================")
sys.stdout.write("\n====== START PCAP FILTER ======")
sys.stdout.write("\n===============================")
sys.stdout.write("\nExtracting Arguments")
args = vars(parser.parse_args())

# Parse Configuration file
sys.stdout.write("\nParsing Config")
config = parse_config(args['conf'])

# Get list of TCP flows
sys.stdout.write("\nFetching all tcp flows")
tshark_cmd = "tshark -q -z conv,tcp -r " + args['input_pcap'] + " > flows_list.txt"
os.system(tshark_cmd)

SRC_ADDR    = 0
DST_ADDR    = 2
TOT_PKTS    = 7
DURATION    = 10

min_pkt_count = 0
min_flow_duration = 0

flows_file = open('flows_list.txt', 'r')
Flows = flows_file.readlines()
Flows = Flows[5:-1]

if (int(config["filter"]["count_based"]["enabled"]) == 1):
    min_pkt_count = int(config["filter"]["count_based"]["min_count"])

if (int(config["filter"]["duration_based"]["enabled"]) == 1):
    min_flow_duration = float(config["filter"]["duration_based"]["min_flow_duration"])

if (int(config["filter"]["port_based"]["enabled"]) == 1):
    ports_list = config["filter"]["port_based"]["port_nr"].split(',')
    ports_count = len(ports_list)

tshark_extract_cmd = "tshark -r " + args['input_pcap'] + " -w "
merge_cmd = "mergecap -w " + args['output_pcap']
count = 0

sys.stdout.write("\nFiltering out flows")
for flow in Flows:
    x = flow.split()

    src = x[SRC_ADDR].split(':')
    dst = x[DST_ADDR].split(':')

    if (len(src) != 2) or (len(dst) != 2):
        continue

    src_ip   = src[0]
    src_port = src[1]
    dst_ip   = dst[0]
    dst_port = dst[1]

    if (int(x[TOT_PKTS]) >= min_pkt_count) and \
       (float(x[DURATION]) >= min_flow_duration) and \
       (src_port in ports_list) or (dst_port in ports_list):
           tshark_filter_cmd = tshark_extract_cmd + "temp_pcap_" + str(count) + ".pcap -Y \"(ip.addr eq " + src_ip + " and ip.addr eq " + dst_ip + ") and (tcp.port eq " + src_port + " and tcp.port eq " + dst_port + ")\""
           os.system(tshark_filter_cmd)
           count += 1

# Merge all flows into one pcap
sys.stdout.write("\nMerging all filtered flows into output pcap")
for x in range(count):
    merge_cmd += " temp_pcap_" + str(x) + ".pcap"

os.system(merge_cmd)

# Remove all temporary files created
remove_cmd = "rm temp_pcap_*.pcap"
os.system(remove_cmd)
sys.stdout.write("\n===============================\n")
