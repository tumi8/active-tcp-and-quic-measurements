# Our own approach implementation file
#!/usr/bin/python

import numpy as np
import matplotlib.pyplot as plt

from time_series_metrics.helper.rca import *
from time_series_metrics.helper.utils import *
from time_series_metrics.helper.process_pcap import *

# Periods of IM algorithm
IM_ALP = 0
IM_STP = 1
IM_BTP = 2


def is_MSS_sized(mss, size):
    if size >= mss:
        return 1
    return 0


def is_packet_retransmitted(packet):
    if (packet.is_retransmission == 1) or \
            (packet.is_fast_retransmission == 1) or \
            (packet.is_spurious_retransmission == 1):
        return 1
    return 0


def avg_throughput_last_n_sec(flow, packet_number, n):
    curr_packet = flow.packet_list[packet_number]
    packet_list = flow.packet_list[:packet_number]
    reverse_list = packet_list[::-1]
    data_sent = 0
    prev_timestamp = 0
    avg_throughput = 0
    cnt = 0
    for packet in list(reverse_list):
        prev_timestamp = packet.timestamp
        if ((curr_packet.timestamp - packet.timestamp) <= n):
            if (packet.direction == flow.forward_direction):
                data_sent += packet.payload_len + packet.options_len
        else:
            break
        cnt += 1
    if (prev_timestamp <= 0):
        return 0
    total_time = curr_packet.timestamp - prev_timestamp
    if (total_time > 0):
        avg_throughput = (data_sent * 8) / total_time
    return avg_throughput


def retransmission_last_n_pkts(flow, packet_number, n):
    retransmission_count = 0
    retransmission_rate = 0
    total_packet_count = 0

    packet_list = flow.packet_list[:packet_number]
    rev_list = packet_list[::-1]

    for packet in list(rev_list):
        if (n > 0):
            if (packet.direction == flow.forward_direction):
                if (is_packet_retransmitted(packet) == 1):
                    retransmission_count += 1
                n -= 1
                total_packet_count += 1

    if (total_packet_count > 0):
        retransmission_rate = (retransmission_count / total_packet_count)

    return retransmission_rate


def get_avg_rtt_n_pkts(flow, packet_number, n):
    tot_rtt = 0
    avg_rtt = 0
    tot_pkt = 0

    packet_list = flow.packet_list[:packet_number]
    rev_list = packet_list[::-1]

    for packet in list(rev_list):
        if (n > 0):
            if (packet.direction == flow.forward_direction):
                tot_rtt += packet.rtt
                tot_pkt += 1
                n -= 1

    if (tot_pkt > 0):
        avg_rtt = tot_rtt / tot_pkt

    return avg_rtt


def is_zero_ob_last_n_time(flow, packet_number, n):
    current = flow.tseries.outstanding_bytes[packet_number]
    ob_list = flow.tseries.outstanding_bytes[:packet_number]
    reverse_list = ob_list[::-1]
    prev_timestamp = 0
    avg_throughput = 0

    for entry in list(reverse_list):
        if ((current[0] - entry[0]) <= n):
            if (entry[1] > 0):
                return 0
    return 1


######################################################################################
######################### Limitation Condition Checks ################################
######################################################################################

def check_slow_sender_limitation(config, flow, packet_number):
    current_ob = flow.tseries.outstanding_bytes[packet_number]
    current_pkt = flow.packet_list[packet_number]

    if (current_ob[1] == 0) and (is_zero_ob_last_n_time(flow, packet_number, flow.avg_rtt / 4) == 1):
        return 1

    return 0


def check_slow_receiver_limitation(config, flow, count, prev_state):
    # In assumption that rwnd and ob are calculated
    # for every packet during timeseries generation
    curr_pkt = flow.packet_list[count]
    curr_rwnd = flow.tseries.receiver_advertised_window[count]
    curr_ob = flow.tseries.outstanding_bytes[count]
    mss = flow.src_MSS if (flow.forward_direction == 1) else flow.dst_MSS
    mss -= curr_pkt.options_len
    n = int(config["packet_based_rca"]["slow_receiver_limitation"]["last_rwnd_count"])

    pkt_list = flow.packet_list[:count]
    rev_list = pkt_list[::-1]

    last_n_rwnd_list = []

    for pkt in list(rev_list):
        if pkt.direction != flow.forward_direction:
            if (n > 0):
                last_n_rwnd_list.append(pkt.rwnd)
                n -= 1
    if ((curr_rwnd[1] - curr_ob[1]) < (
            float(config["packet_based_rca"]["slow_receiver_limitation"]["begin_threshold"]) * (mss))) and \
            (is_list_decreasing_order(last_n_rwnd_list) == 1):
        return 1
    elif (((curr_rwnd[1] - curr_ob[1]) >= (
            float(config["packet_based_rca"]["slow_receiver_limitation"]["begin_threshold"]) * (mss))) and \
          ((curr_rwnd[1] - curr_ob[1]) <= (
                  float(config["packet_based_rca"]["slow_receiver_limitation"]["end_threshold"]) * (mss)))):
        return prev_state
    else:
        return 0


def check_send_buffer_limitation(config, flow, count, prev_state):
    # In assumption that snd_buf and ob are calculated
    # for every packet during timeseries generation
    curr_pkt = flow.packet_list[count]
    curr_ob = flow.tseries.outstanding_bytes[count]
    mss = flow.src_MSS if (flow.forward_direction == 1) else flow.dst_MSS
    mss -= curr_pkt.options_len

    if ((flow.send_buffer_size - curr_ob[1]) < (
            float(config["packet_based_rca"]["sender_buffer_limitation"]["begin_threshold"]) * mss)):
        return 1
    elif (((flow.send_buffer_size - curr_ob[1]) >= (
            float(config["packet_based_rca"]["sender_buffer_limitation"]["begin_threshold"]) * mss)) and
          ((flow.send_buffer_size - curr_ob[1]) < (
                  float(config["packet_based_rca"]["sender_buffer_limitation"]["end_threshold"]) * mss))):
        return prev_state
    else:
        return 0


def check_receive_buffer_limitation(config, flow, count, prev_state):
    # In assumption that rwnd and ob are calculated
    # for every packet during timeseries generation
    curr_pkt = flow.packet_list[count]
    curr_rwnd = flow.tseries.receiver_advertised_window[count]
    curr_ob = flow.tseries.outstanding_bytes[count]
    mss = flow.src_MSS if (flow.forward_direction == 1) else flow.dst_MSS
    mss -= curr_pkt.options_len

    if ((curr_rwnd[1] - curr_ob[1]) <= (
            float(config["packet_based_rca"]["receiver_buffer_limitation"]["begin_threshold"]) * mss)):
        return 1
    elif (((curr_rwnd[1] - curr_ob[1]) > (
            float(config["packet_based_rca"]["receiver_buffer_limitation"]["begin_threshold"]) * mss)) and \
          ((curr_rwnd[1] - curr_ob[1]) <= (
                  float(config["packet_based_rca"]["receiver_buffer_limitation"]["end_threshold"]) * mss))):
        return prev_state
    else:
        return 0


def check_unshared_bottleneck_limitation(config, flow, packet_number):
    capacity = 0
    n = float(config["packet_based_rca"]["unshared_bottleneck_limitation"]["last_n_sec_throughput"])

    if (flow.bl_capacity == 0) or (flow.bl_capacity == -1):
        return 0

    # Convert capacity from Mbps to bps
    capacity = flow.bl_capacity * 1000000
    if ((1 - (avg_throughput_last_n_sec(flow, packet_number, n) / capacity)) < float(
            config["packet_based_rca"]["unshared_bottleneck_limitation"]["throughput_threshold"])):
        return 1
    return 0


def check_shared_bottleneck_limitation(config, flow, packet_number):
    curr_pkt = flow.packet_list[packet_number]

    n = int(config["packet_based_rca"]["shared_bottleneck_limitation"]["last_n_packets_retransmission"])
    avg_rtt = get_avg_rtt_n_pkts(flow, packet_number, n)
    min_rtt_list = [packet.rtt for packet in list(flow.packet_list[:packet_number]) if
                    ((packet.direction == flow.forward_direction) and (packet.rtt > 0))]
    min_rtt_list.sort()

    if (len(min_rtt_list) == 0):
        return 0

    min_rtt = min_rtt_list[0]
    rtt_score = avg_rtt / min_rtt

    if (float(retransmission_last_n_pkts(flow, packet_number, n)) >= float(
            config["packet_based_rca"]["shared_bottleneck_limitation"]["retransmission_threshold"])) or \
            (rtt_score > float(config["packet_based_rca"]["shared_bottleneck_limitation"]["rtt_threshold"])) or \
            ((curr_pkt.ECN == 1) or (has_flag(curr_pkt.flags, ECE) == 1) or (has_flag(curr_pkt.flags, CWR) == 1)):
        return 1
    return 0


def check_tcp_cc_limitation(config, flow, count):
    mss = flow.src_MSS if (flow.forward_direction == 1) else flow.dst_MSS
    n = int(config["packet_based_rca"]["tcp_cc_limitation"]["last_n_packet_window"])
    if (count - n < 0):
        pkt_list = flow.packet_list[:count]
        i = 0
    else:
        pkt_list = flow.packet_list[count - n:count]
        i = count - n

    for packet in list(pkt_list):
        curr_ob = flow.tseries.outstanding_bytes[i]
        curr_rwnd = flow.tseries.receiver_advertised_window[i]

        # TODO: Add check for packet loss
        if (((curr_rwnd[1] - curr_ob[1]) > 2 * mss) and ((flow.send_buffer_size - curr_ob[1]) > 2 * mss)) and \
                (is_packet_retransmitted(packet) == 0):
            i += 1
            continue
        else:
            return 1
    return 0


######################################################################################

def get_flow_periods(config, flow):
    packet_cnt = 0
    prev_ts = 0
    prev_sr_state = 0
    prev_sb_state = 0
    prev_rb_state = 0
    ss_temp_list = []

    for period in list(flow.siekkinen_data):
        if (period.period_type == IM_ALP):
            add_ss_limitation(flow, period, ss_temp_list)

    for packet in list(flow.packet_list):
        if (packet.direction == flow.forward_direction):
            # Perform all limitation checks
            add_limitation_to_list(flow, packet, SS, check_slow_sender_limitation(config, flow, packet_cnt), packet_cnt)

            prev_sr_state = check_slow_receiver_limitation(config, flow, packet_cnt, prev_sr_state)
            add_limitation_to_list(flow, packet, SR, prev_sr_state, packet_cnt)

            prev_sb_state = check_send_buffer_limitation(config, flow, packet_cnt, prev_sb_state)
            add_limitation_to_list(flow, packet, SB, prev_sb_state, packet_cnt)

            prev_rb_state = check_receive_buffer_limitation(config, flow, packet_cnt, prev_rb_state)
            add_limitation_to_list(flow, packet, RB, prev_rb_state, packet_cnt)

            add_limitation_to_list(flow, packet, UBL, check_unshared_bottleneck_limitation(config, flow, packet_cnt),
                                   packet_cnt)
            add_limitation_to_list(flow, packet, SBL, check_shared_bottleneck_limitation(config, flow, packet_cnt),
                                   packet_cnt)
            add_limitation_to_list(flow, packet, CA, check_tcp_cc_limitation(config, flow, packet_cnt), packet_cnt)
        packet_cnt += 1

    insert_limitations(flow, flow.limitations.slow_sender, ss_temp_list)

    sort_limitations(flow)


def plot_output(config, output, flow, flow_cnt, outdir):
    # Declaring a figure "gnt"
    fig, gnt = plt.subplots(figsize=(15, 5))

    # Find initial time value to get relative time
    first_packet = flow.packet_list[0]
    last_packet = flow.packet_list[-1]
    start_time = first_packet.timestamp
    end_time = last_packet.timestamp

    # Setting Y-axis limits
    gnt.set_ylim(0, 14)

    # Setting X-axis limits
    gnt.set_xlim(0, end_time - start_time)

    # Setting labels for x-axis and y-axis
    gnt.set_xlabel('Flow duration in seconds')
    gnt.set_ylabel('Limitations')

    # Setting ticks on y-axis
    gnt.set_yticks([1, 3, 5, 7, 9, 11, 13])

    # Labelling tickes of y-axis
    gnt.set_yticklabels(
        ['Slow Sender', 'Slow Receiver', 'Send Buffer', 'Receive Buffer', 'Unshared Bottleneck', 'Shared Bottleneck',
         'Congestion Avoidance'])

    # Setting graph attribute
    gnt.grid(True)

    o_list = []
    height = 0
    color = 'tab:white'
    for entry in output:
        if (entry.period_type == SS):
            color = 'tab:blue'
            height = 0.75
        elif (entry.period_type == SR):
            color = 'tab:red'
            height = 2.75
        elif (entry.period_type == SB):
            color = 'tab:green'
            height = 4.75
        elif (entry.period_type == RB):
            color = 'tab:orange'
            height = 6.75
        elif (entry.period_type == UBL):
            color = 'tab:pink'
            height = 8.75
        elif (entry.period_type == SBL):
            color = 'tab:purple'
            height = 10.75
        elif (entry.period_type == CA):
            color = 'tab:brown'
            height = 12.75
        new_start = entry.start
        if (entry.start >= start_time):
            new_start = entry.start - start_time
        else:
            entry.start = start_time
        if (entry.end == -1):
            entry.end = end_time
        duration = entry.end - entry.start
        l_entry = (new_start, duration, color, height)
        o_list.append(l_entry)

    # Declaring multiple bars in at same level and same width
    for entry in o_list:
        range_bar = [(entry[0], entry[1])]
        gnt.broken_barh(range_bar, (entry[3], 0.5), facecolors=(entry[2]))

    file_name = "final_limitations_flow_" + str(flow_cnt) + ".png"
    graph_name = os.path.join(outdir, file_name)
    plt.savefig(graph_name)


def get_duration(entry, end):
    if (entry.duration == -1):
        if (entry.end == -1):
            return (end - entry.start)
        else:
            return entry.end - entry.start
    return entry.duration


def plot_limitation(config, flow, flow_cnt, outdir):
    # Declaring a figure "gnt"
    fig, gnt = plt.subplots()
    pdf_height = 25.0 * float(1) / 10
    fig.set_size_inches(20, pdf_height)

    # Find initial time value to get relative time
    first_packet = flow.packet_list[0]
    last_packet = flow.packet_list[-1]
    start_time = first_packet.timestamp
    end_time = last_packet.timestamp

    # Setting Y-axis limits
    gnt.set_ylim(0, 50)

    # Setting X-axis limits
    gnt.set_xlim(0, end_time - start_time)

    # Setting labels for x-axis and y-axis
    gnt.set_xlabel('Flow duration in seconds')
    gnt.set_ylabel('Limitations')

    # Setting ticks on y-axis
    gnt.set_yticks([11, 16, 21, 26, 31, 36, 41])

    # Labelling tickes of y-axis
    gnt.set_yticklabels(
        ['Slow Sender', 'Slow Receiver', 'Send Buffer', 'Receive Buffer', 'Unshared Bottleneck', 'Shared Bottleneck',
         'TCP CC'])

    # Setting graph attribute
    gnt.grid(True)

    ss_list = []
    sr_list = []
    sb_list = []
    rb_list = []
    ubl_list = []
    sbl_list = []
    ca_list = []

    for entry in flow.limitations.slow_sender:
        entry.duration = get_duration(entry, end_time)
        ss_entry = (entry.start - start_time, entry.duration)
        ss_list.append(ss_entry)
    for entry in flow.limitations.slow_receiver:
        entry.duration = get_duration(entry, end_time)
        sr_entry = (entry.start - start_time, entry.duration)
        sr_list.append(sr_entry)
    for entry in flow.limitations.sender_buffer:
        entry.duration = get_duration(entry, end_time)
        sb_entry = (entry.start - start_time, entry.duration)
        sb_list.append(sb_entry)
    for entry in flow.limitations.receiver_buffer:
        entry.duration = get_duration(entry, end_time)
        rb_entry = (entry.start - start_time, entry.duration)
        rb_list.append(rb_entry)
    for entry in flow.limitations.unshared_bottleneck:
        entry.duration = get_duration(entry, end_time)
        ubl_entry = (entry.start - start_time, entry.duration)
        ubl_list.append(ubl_entry)
    for entry in flow.limitations.shared_bottleneck:
        entry.duration = get_duration(entry, end_time)
        sbl_entry = (entry.start - start_time, entry.duration)
        sbl_list.append(sbl_entry)
    for entry in flow.limitations.transport_layer:
        entry.duration = get_duration(entry, end_time)
        ca_entry = (entry.start - start_time, entry.duration)
        ca_list.append(ca_entry)

    # Declaring multiple bars in at same level and same width
    gnt.broken_barh(ss_list, (10, 2), facecolors=('tab:blue'))
    gnt.broken_barh(sr_list, (15, 2), facecolors=('tab:red'))
    gnt.broken_barh(sb_list, (20, 2), facecolors=('tab:green'))
    gnt.broken_barh(rb_list, (25, 2), facecolors=('tab:orange'))
    gnt.broken_barh(ubl_list, (30, 2), facecolors=('tab:pink'))
    gnt.broken_barh(sbl_list, (35, 2), facecolors=('tab:purple'))
    gnt.broken_barh(ca_list, (40, 2), facecolors=('tab:brown'))

    flow_file = "Flow_" + str(flow_cnt)
    file_name = "all_limitations.pdf"
    graph_name = os.path.join(outdir, flow_file, file_name)
    plt.savefig(graph_name)


def sort_periods(limitations_list):
    new_list = sorted(limitations_list, key=lambda im_period: im_period.start_pkt_nr)
    return new_list


def sort_limitations(flow):
    flow.limitations.slow_sender = sort_periods(flow.limitations.slow_sender)
    flow.limitations.slow_receiver = sort_periods(flow.limitations.slow_receiver)
    flow.limitations.sender_buffer = sort_periods(flow.limitations.sender_buffer)
    flow.limitations.receiver_buffer = sort_periods(flow.limitations.receiver_buffer)
    flow.limitations.unshared_bottleneck = sort_periods(flow.limitations.unshared_bottleneck)
    flow.limitations.shared_bottleneck = sort_periods(flow.limitations.shared_bottleneck)
    flow.limitations.transport_layer = sort_periods(flow.limitations.transport_layer)


@dataclass
class missing_period:
    start: int = -1
    end: int = -1
    start_time: float = -1
    end_time: float = -1

    def __init__(self, start, end, start_time, end_time):
        self.start = start
        self.end = end
        self.start_time = start_time
        self.end_time = end_time


def get_missing_periods(flow, output):
    missing_periods = []
    start_pkt_nr = 0
    end_pkt_nr = flow.tx_pkt_count + flow.rx_pkt_count - 1
    last_end = -1
    last_time = 0
    first_packet = flow.packet_list[0]
    last_packet = flow.packet_list[-1]
    start = first_packet.timestamp
    end = last_packet.timestamp

    entry_cnt = 0
    for entry in list(output):
        if entry.end_pkt_nr == -1:
            entry.end_pkt_nr = end_pkt_nr
        if entry.end == -1:
            entry.end = end
        if (entry_cnt == 0):
            if (entry.start_pkt_nr > 1):
                new_period = missing_period(0, entry.start_pkt_nr - 1, start, entry.start)
                missing_periods.append(new_period)
            elif (entry.start_pkt_nr == 1):
                new_period = missing_period(0, entry.start_pkt_nr, start, entry.start)
                missing_periods.append(new_period)
        elif (last_end + 1 != entry.start_pkt_nr):
            new_period = missing_period(last_end + 1, entry.start_pkt_nr - 1, last_time, entry.start)
            missing_periods.append(new_period)
        entry_cnt += 1
        last_end = entry.end_pkt_nr
        last_time = entry.end

    if (last_end != end_pkt_nr):
        new_period = missing_period(last_end + 1, end_pkt_nr, last_time, end)
        missing_periods.append(new_period)

    return missing_periods


def insert_limitations(flow, output, input_list):
    missing_periods = []
    last_packet = flow.packet_list[-1]
    end_pkt_num = flow.tx_pkt_count + flow.rx_pkt_count - 1
    end_pkt_time = last_packet.timestamp
    if len(output) == 0:
        return input_list

    missing_periods = get_missing_periods(flow, output)
    if len(missing_periods) == 0:
        return output

    new_list = []
    for ientry in list(input_list):
        if ientry.end_pkt_nr == -1:
            ientry.end_pkt_nr = end_pkt_num
        if ientry.end == -1:
            ientry.end = end_pkt_time

        for entry in list(missing_periods):
            if (entry.start < ientry.start_pkt_nr):
                if (entry.end < ientry.start_pkt_nr):
                    continue
                else:
                    if (entry.end >= ientry.end_pkt_nr):
                        new_entry = im_period(ientry.start, ientry.end, ientry.duration, ientry.period_type,
                                              ientry.pkt_count, ientry.byte_count)
                        new_entry.root_cause = ientry.period_type
                        new_entry.start_pkt_nr = ientry.start_pkt_nr
                        new_entry.end_pkt_nr = ientry.end_pkt_nr
                        new_list.append(new_entry)
                    else:
                        new_entry = im_period(ientry.start, ientry.end, ientry.duration, ientry.period_type,
                                              ientry.pkt_count, ientry.byte_count)
                        new_entry.root_cause = ientry.period_type
                        new_entry.start_pkt_nr = ientry.start_pkt_nr
                        new_entry.end_pkt_nr = entry.end
                        new_entry.start = ientry.start
                        new_entry.end = entry.end_time
                        new_entry.duration = new_entry.end - new_entry.start
                        new_entry.pkt_count = new_entry.end_pkt_nr - new_entry.start_pkt_nr
                        new_list.append(new_entry)
            elif (entry.start == ientry.start_pkt_nr):
                if (entry.end >= ientry.end_pkt_nr):
                    new_entry = im_period(ientry.start, ientry.end, ientry.duration, ientry.period_type,
                                          ientry.pkt_count, ientry.byte_count)
                    new_entry.root_cause = ientry.period_type
                    new_entry.start_pkt_nr = ientry.start_pkt_nr
                    new_entry.end_pkt_nr = ientry.end_pkt_nr
                    new_list.append(new_entry)
                else:
                    new_entry = im_period(ientry.start, ientry.end, ientry.duration, ientry.period_type,
                                          ientry.pkt_count, ientry.byte_count)
                    new_entry.root_cause = ientry.period_type
                    new_entry.start_pkt_nr = entry.start
                    new_entry.end_pkt_nr = entry.end
                    new_entry.start = entry.start_time
                    new_entry.end = entry.end_time
                    new_entry.duration = new_entry.end - new_entry.start
                    new_entry.pkt_count = new_entry.end_pkt_nr - new_entry.start_pkt_nr
                    new_list.append(new_entry)
            else:
                if (entry.start >= ientry.end_pkt_nr):
                    continue
                else:
                    if (ientry.end_pkt_nr <= entry.end):
                        new_entry = im_period(ientry.start, ientry.end, ientry.duration, ientry.period_type,
                                              ientry.pkt_count, ientry.byte_count)
                        new_entry.root_cause = ientry.period_type
                        new_entry.start_pkt_nr = entry.start
                        new_entry.end_pkt_nr = ientry.end_pkt_nr
                        new_entry.start = entry.start_time
                        new_entry.end = ientry.end
                        new_entry.duration = new_entry.end - new_entry.start
                        new_entry.pkt_count = new_entry.end_pkt_nr - new_entry.start_pkt_nr
                        new_list.append(new_entry)
                    else:
                        new_entry = im_period(ientry.start, ientry.end, ientry.duration, ientry.period_type,
                                              ientry.pkt_count, ientry.byte_count)
                        new_entry.root_cause = ientry.period_type
                        new_entry.start_pkt_nr = entry.start
                        new_entry.end_pkt_nr = entry.end
                        new_entry.start = entry.start_time
                        new_entry.end = entry.end_time
                        new_entry.duration = new_entry.end - new_entry.start
                        new_entry.pkt_count = new_entry.end_pkt_nr - new_entry.start_pkt_nr
                        new_list.append(new_entry)

    for entry in list(new_list):
        output.append(entry)

    new_output = sorted(output, key=lambda im_period: im_period.start_pkt_nr)

    return new_output


def find_limitations(config, flow, flow_count, outdir):
    output = []

    output = insert_limitations(flow, output, flow.limitations.slow_receiver)
    output = insert_limitations(flow, output, flow.limitations.slow_sender)
    output = insert_limitations(flow, output, flow.limitations.unshared_bottleneck)
    output = insert_limitations(flow, output, flow.limitations.shared_bottleneck)
    output = insert_limitations(flow, output, flow.limitations.receiver_buffer)
    output = insert_limitations(flow, output, flow.limitations.sender_buffer)
    output = insert_limitations(flow, output, flow.limitations.transport_layer)

    missing_periods = get_missing_periods(flow, output)
    for entry in missing_periods:
        new_entry = im_period(entry.start_time, entry.end_time, entry.end_time - entry.start_time, -1, -1, -1)
        new_entry.root_cause = UK
        new_entry.start_pkt_nr = entry.start
        new_entry.end_pkt_nr = entry.end
        new_entry.duration = new_entry.end - new_entry.start
        new_entry.pkt_count = new_entry.end_pkt_nr - new_entry.start_pkt_nr
        output.append(new_entry)

    new_output = sorted(output, key=lambda im_period: im_period.start_pkt_nr)

    for entry in new_output:
        flow.limitation_periods.append(entry)

    last_packet = flow.packet_list[-1]
    last_time = last_packet.timestamp
    for entry in flow.limitation_periods:
        if (entry.duration == -1):
            entry.end = last_time
            entry.duration = entry.end - entry.start

    # plot_output(config, output, flow, flow_count, outdir)


def perform_custom_rca(config, flows, outdir):
    flow_count = 1
    for flow in flows:
        get_flow_periods(config, flow)
        find_limitations(config, flow, flow_count, outdir)
        #plot_limitation(config, flow, flow_count, outdir)
        flow_count += 1

