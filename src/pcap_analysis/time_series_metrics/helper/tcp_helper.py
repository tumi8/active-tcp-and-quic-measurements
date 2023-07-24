# TCP helper functions file
#!/usr/bin/python

import bisect
from scapy import *
import numpy as np
from dataclasses import dataclass, field

from time_series_metrics.helper.PPrate import *
from time_series_metrics.helper.process_pcap import *

# TCP Flags
FIN = 'F'
SYN = 'S'
RST = 'R'
PSH = 'P'
ACK = 'A'
URG = 'U'
ECE = 'E'
CWR = 'C'
NS = 'N'

# Defaults
DEFAULT_ETH_MSS = 1460


# Data class to store all tcp flow sequence analysis info
@dataclass
class tcp_sequence_info:
    prev_max_next_seq_nr: int = 0
    prev_segment_time: float = 0.0
    next_seq_nr: int = 0
    max_next_seq_nr: int = 0
    last_seen_ack_nr: int = 0
    last_seen_ack_time: float = 0.0
    last_seen_ack_rwnd: int = 0
    last_seen_dup_ack_cnt: int = 0

    def __init__(self):
        return


# Functions to find the direction of flow
def get_direction(flow, ip, tcp):
    direction = -1  # Does not belong to flow

    if flow.src_ip == str(ip.src) and \
            flow.dst_ip == str(ip.dst) and \
            flow.src_port == tcp.sport and \
            flow.dst_port == tcp.dport:
        direction = 0  # Forward
    elif flow.dst_ip == str(ip.src) and \
            flow.src_ip == str(ip.dst) and \
            flow.dst_port == tcp.sport and \
            flow.src_port == tcp.dport:
        direction = 1  # Reverse
    return direction


# Function to check for presence of flags
def has_flag(flags, flag):
    if flag in str(flags):
        return 1
    return 0


# Get ECN option from IP header
def get_ip_ECN(ip):
    if(ip.haslayer(IP)):
        return (ip.tos & 3)
    else:
        return (ip.tc & 3)


# Extract TCP options
def extract_tcp_options(flow, packet, pkt):
    ip = packet[IP] if packet.haslayer(IP) == 1 else packet[IPv6]
    tcp = packet[TCP]

    for opt, val in tcp.options:
        if opt == 'MSS':
            if pkt.direction == 0:
                flow.src_MSS = val
            else:
                flow.dst_MSS = val
        elif opt == 'Timestamp':
            TSval, TSecr = val  # decode the value of the option
            pkt.TSval = TSval
            pkt.TSecr = TSecr
            flow.timestamp_option_available = 1
        elif opt == "WScale":
            wscale_value = pow(2, val)
            if (pkt.direction == 0):
                flow.src_wscale = wscale_value
            else:
                flow.dst_wscale = wscale_value


# Find if flow has 3-way handshake
def has_tcp_handshake(flow):
    syn_found = 0
    synack_found = 0
    ack_found = 0

    for packet in flow.packet_list:
        if (has_flag(packet.flags, SYN) == 1) and \
                (has_flag(packet.flags, ACK) == 0):
            syn_found = 1
            break

    if (syn_found == 0):
        return 0

    for packet in flow.packet_list:
        if (has_flag(packet.flags, SYN) == 1) and \
                (has_flag(packet.flags, ACK) == 1):
            synack_found = 1
            break

    if (synack_found == 0):
        return 0

    for packet in flow.packet_list:
        if (has_flag(packet.flags, SYN) == 0) and \
                (has_flag(packet.flags, ACK) == 1):
            ack_found = 1
            break

    if (ack_found == 0):
        return 0

    return 1


def get_mp_time_deltas(flow):
    pkt1 = []
    pkt2 = []
    pkt3 = []

    for packet in flow.packet_list:
        if (has_flag(packet.flags, SYN) == 1) and \
                (has_flag(packet.flags, ACK) == 0):
            pkt1.append(packet)

    if len(pkt1) == 0:
        return 0, 0

    syn_packet = pkt1[-1]
    for packet in flow.packet_list:
        if ((has_flag(packet.flags, SYN) == 1) and (has_flag(packet.flags, ACK) == 1)) and \
                (packet.ack_nr >= syn_packet.seq_nr + 1):
            pkt2.append(packet)
            break

    if len(pkt2) == 0:
        return 0, 0

    synack_packet = pkt2[-1]
    for packet in flow.packet_list:
        if ((has_flag(packet.flags, SYN) == 0) and (has_flag(packet.flags, ACK) == 1)) and \
                (packet.ack_nr >= synack_packet.seq_nr + 1):
            pkt3.append(packet)
            break

    if len(pkt3) == 0:
        return 0, 0

    ack_packet = pkt3[-1]

    return (synack_packet.timestamp - syn_packet.timestamp), (ack_packet.timestamp - synack_packet.timestamp)


def get_measurement_position(config, flow):
    if (flow.time_interval_d2 / flow.time_interval_d1) < config["measurement_position"]["threshold"]:
        flow.mp_sender_side = 1
    else:
        flow.mp_sender_side = 0
    return


def get_capacity_measurement_position(config, flow):
    if (flow.time_interval_d2 / flow.time_interval_d1) < config["measurement_position"]["capacity_threshold"]:
        return 1
    else:
        return 0


def get_shifted_timestamp(config, flow, packet, curr_rtt):
    try:
        if flow.mp_sender_side == 1:
            # Close to sender
            if (flow.dst_type == "Sender"):
                if (packet.direction == 1):
                    return packet.timestamp - (curr_rtt / 2)
                else:
                    return packet.timestamp + (curr_rtt / 2)
        else:
            # away from sender
            if (flow.src_type == "Sender"):
                if (packet.direction == 0):
                    return packet.timestamp - (curr_rtt / 2)
                else:
                    return packet.timestamp + (curr_rtt / 2)
        return packet.timestamp
    except:
        # Handle divide by zero
        return packet.timestamp


def get_bottleneck_capacity_sender(config, flow):
    ret = []
    iats = []
    prev_ack_nr = 0
    prev_ack_time = 0

    # Find MSS
    mss = flow.dst_MSS
    if (flow.forward_direction == 1):
        mss = flow.src_MSS
    if (mss == 0):
        mss = DEFAULT_ETH_MSS

    for packet in list(flow.packet_list):
        if (packet.direction != flow.forward_direction):
            if (has_flag(packet.flags, ACK) == 1) and \
                    (packet.payload_len == 0):
                if (prev_ack_time == 0):
                    prev_ack_nr = packet.ack_nr
                    prev_ack_time = packet.timestamp
                    continue
                ack = packet.ack_nr - prev_ack_nr
                if ((ack % (mss - 12)) == 0) and (ack != 0):
                    cnt = ack / (mss - 12)
                    dif = float(packet.timestamp - prev_ack_time)
                    ret.append(dif / cnt)
                    prev_ack_nr = packet.ack_nr
                    prev_ack_time = packet.timestamp
                    continue
                prev_ack_nr = packet.ack_nr
                prev_ack_time = packet.timestamp

    if len(ret) == 0:
        return -1
    iats = np.array(ret, dtype=float)

    return find_capacity(mss, iats) / 10 ** 6


def get_bottleneck_capacity_receiver(config, flow):
    mss = []
    iats = []
    data_pkts_ts = []

    for packet in list(flow.packet_list):
        if (packet.direction == flow.forward_direction):
            if packet.payload_len > 0:
                data_pkts_ts.append(packet.timestamp)
                mss.append(packet.payload_len)

    mss = mss[1:]
    ret = list(map(lambda t: t[1] - t[0], zip(data_pkts_ts, data_pkts_ts[1:])))
    iats = np.array(ret, dtype=float)
    length = len(iats)

    if length == 0:
        print('No data to process was found. IAT = 0')
        return -1

    if length < 250:
        # Replicate data if less than 250 samples
        print('Not enough data for estimation! Trying to replicate data, result may be overestimated...')
        if length < 100:
            return -1
        iats, mss = replicate_data(iats, mss)

    return find_capacity(mss, iats) / 10 ** 6


def get_scaled_window(flow, direction, tcp_rwnd):
    if (direction == 0):
        wscale = flow.src_wscale
    else:
        wscale = flow.dst_wscale

    if (wscale > 0):
        return (tcp_rwnd * wscale)
    else:
        return tcp_rwnd


def perform_sequence_analysis(flow):
    curr_rtt = 0
    max_seq_nr = 0
    unacked_list = []
    prev_seg_time = 0
    dup_ack_count = 0
    last_ack_seq_nr = 0
    last_seen_ack_nr = 0
    last_seen_ack_time = 0
    last_seen_ack_rwnd = 0

    for packet in list(flow.packet_list):
        if (packet.direction == flow.forward_direction):
            curr_rtt = packet.rtt
        # Compute shifted timestamps for every packet
        # packet.shifted_timestamp = packet.timestamp
        packet.shifted_timestamp = float(get_shifted_timestamp(config, flow, packet, curr_rtt))

        if (packet.direction == flow.forward_direction):
            packet.tcp_seq_info.prev_max_next_seq_nr = max_seq_nr
            packet.tcp_seq_info.prev_segment_time = prev_seg_time

            if (has_flag(packet.flags, SYN) == 1) or (has_flag(packet.flags, FIN) == 1):
                packet.tcp_seq_info.next_seq_nr = (packet.seq_nr + packet.payload_len + 1) % (2 ** 32)

            else:
                packet.tcp_seq_info.next_seq_nr = (packet.seq_nr + packet.payload_len) % (2 ** 32)

            if (packet.tcp_seq_info.next_seq_nr > max_seq_nr):
                prev_seg_time = packet.shifted_timestamp
                max_seq_nr = packet.tcp_seq_info.next_seq_nr
            elif ((packet.seq_nr + packet.payload_len) > (2 ** 32)):
                prev_seg_time = packet.shifted_timestamp
                max_seq_nr = packet.tcp_seq_info.next_seq_nr

            packet.tcp_seq_info.max_next_seq_nr = max_seq_nr
            packet.tcp_seq_info.last_seen_ack_nr = last_seen_ack_nr
            packet.tcp_seq_info.last_seen_ack_time = last_seen_ack_time
            packet.tcp_seq_info.last_seen_ack_rwnd = last_seen_ack_rwnd
            packet.tcp_seq_info.last_seen_dup_ack_cnt = dup_ack_count

            if packet.seq_nr not in unacked_list:
                bisect.insort(unacked_list, packet.seq_nr)
            packet.tcp_seq_info.next_seq_to_be_ackd = unacked_list[0]
        else:
            unacked_list = [entry for entry in list(unacked_list) if (entry > packet.ack_nr)]
            # Check if packet is a dulpicate ack
            packet.is_dup_ack = is_dup_ack(packet, last_ack_seq_nr, last_seen_ack_nr, last_seen_ack_rwnd)
            # Update dup_ack count
            if (packet.ack_nr == last_seen_ack_nr) and (packet.is_dup_ack == 1):
                dup_ack_count += 1
            else:
                dup_ack_count = 0
            last_ack_seq_nr = packet.seq_nr
            last_seen_ack_nr = packet.ack_nr
            last_seen_ack_time = packet.shifted_timestamp
            last_seen_ack_rwnd = packet.rwnd


def is_dup_ack(packet, last_ack_seq_nr, last_seen_ack_nr, prev_rwnd):
    # Duplicate ack conditions: https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html
    # The segment size is zero.
    # The window size is non-zero and hasn’t changed.
    # The next expected sequence number and last-seen acknowledgment number are non-zero (i.e., the connection has been established).
    # SYN, FIN, and RST are not set.
    if (packet.payload_len == 0) and \
            (packet.rwnd > 0) and (packet.rwnd == prev_rwnd) and \
            (packet.seq_nr == last_ack_seq_nr) and \
            (packet.ack_nr == last_seen_ack_nr) and \
            (has_flag(packet.flags, SYN) == 0) and \
            (has_flag(packet.flags, FIN) == 0) and \
            (has_flag(packet.flags, RST) == 0):
        return 1
    return 0


def is_keep_alive(packet, next_exp_seq_nr):
    # Keep Alive conditions: https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html
    # The segment size is zero or one
    # The current sequence number is one byte less than the next expected sequence number
    # None of SYN, FIN, or RST are set.
    seq_nr = packet.seq_nr
    if (packet.tcp_seq_info.prev_max_next_seq_nr - packet.seq_nr) > (2 ** 30):
        seq_nr = packet.seq_nr + (2 ** 30)
    if ((packet.payload_len == 0) or (packet.payload_len == 1)) and \
            (seq_nr == packet.tcp_seq_info.prev_max_next_seq_nr - 1) and \
            (has_flag(packet.flags, SYN) == 0) and \
            (has_flag(packet.flags, FIN) == 0) and \
            (has_flag(packet.flags, RST) == 0):
        return 1
    return 0


def is_retransmission(packet, next_exp_seq_nr):
    # Retransmission conditions: https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html
    # This is not a keepalive packet.
    # In the forward direction, the segment length is greater than zero or the SYN or FIN flag is set.
    # The next expected sequence number is greater than the current sequence number.
    if (packet.is_keep_alive == 0) and \
            ((packet.direction == flow.forward_direction) and \
             ((packet.payload_len > 0) or \
              ((has_flag(packet.flags, SYN) == 1) or (has_flag(packet.flags, FIN) == 1)))) and \
            (next_exp_seq_nr > packet.seq_nr):
        return 1
    return 0


def is_out_of_order(packet, seq_not_advanced):
    # Out-of-order conditions: https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html
    # This is not a keepalive packet.
    # In the forward direction, the segment length is greater than zero or the SYN or FIN is set.
    # The next expected sequence number is greater than the current sequence number.
    # The next expected sequence number and the next sequence number differ.
    # The last segment arrived within the Out-Of-Order RTT threshold.
    # The threshold is either initial_rtt or the default value of 3ms if it is not.
    ooo_threshold = 0.003
    next_seq = packet.tcp_seq_info.next_seq_nr
    if (packet.tcp_seq_info.prev_max_next_seq_nr > packet.tcp_seq_info.next_seq_nr):
        if (packet.tcp_seq_info.prev_max_next_seq_nr - packet.tcp_seq_info.next_seq_nr) > (2 ** 30):
            next_seq = packet.tcp_seq_info.next_seq_nr + (2 ** 32)
    if (packet.rtt > 0):
        ooo_threshold = packet.rtt
    if (seq_not_advanced == 1) and \
            ((packet.shifted_timestamp - packet.tcp_seq_info.prev_segment_time) < ooo_threshold) and \
            (packet.tcp_seq_info.prev_max_next_seq_nr != next_seq):
        return 1
    return 0


def is_fast_retransmission(packet, seq_not_advanced):
    # Fast Retransmission conditions: https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html
    # This is a retransmitted packet
    # We have more than two duplicate ACKs in the reverse direction.
    # The current sequence number equals the last seen acknowledgement number.
    # We saw the last acknowledgement less than 20ms ago.
    if (seq_not_advanced == 1) and \
            (packet.tcp_seq_info.last_seen_dup_ack_cnt >= 2) and \
            (packet.tcp_seq_info.last_seen_ack_nr == packet.seq_nr) and \
            ((packet.shifted_timestamp - packet.tcp_seq_info.last_seen_ack_time) < 0.02):
        return 1
    return 0


def is_spurious_retransmission(packet):
    # Spurious Retransmission conditions: https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html
    # In the forward direction,
    # The segment length is greater than zero (or)
    # The SYN or FIN is set.
    # This is not a keepalive packet.
    # The segment length is greater than zero.
    # Data for this flow has been acknowledged. That is, the last-seen acknowledgement number has been set.
    # The next sequence number is less than or equal to the last-seen acknowledgement number.
    next_seq = packet.tcp_seq_info.next_seq_nr
    if (packet.tcp_seq_info.last_seen_ack_nr > packet.tcp_seq_info.next_seq_nr):
        if (packet.tcp_seq_info.last_seen_ack_nr - packet.tcp_seq_info.next_seq_nr) > (2 ** 30):
            next_seq = packet.tcp_seq_info.next_seq_nr + (2 ** 30)
    if (packet.payload_len > 0) and \
            (packet.tcp_seq_info.last_seen_ack_nr > 0) and \
            (next_seq <= packet.tcp_seq_info.last_seen_ack_nr):
        return 1
    return 0


