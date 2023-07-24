# Siekkinen approach implementation file
#!/usr/bin/python

import numpy as np
import collections
import matplotlib.pyplot as plt

try:
    from collections import OrderedDict
except ImportError:
    OrderedDict = dict

from time_series_metrics.helper.rca import *
from time_series_metrics.helper.process_pcap import *


def is_MSS_sized(mss, size):
    if size >= mss:
        return 1 
    return 0


def get_first_data_pkt_len(flow):
    for packet in list(flow.packet_list):
        if (packet.direction == flow.forward_direction) and \
                (packet.payload_len > 0):
            return packet.payload_len
    return 0


def get_last_n_MSS_sized(n, mss, pkt_len_list):
    if not pkt_len_list:
        return 0

    count = 0
    mss_count = 0

    for item in pkt_len_list:
        count += 1
        mss_count += is_MSS_sized(mss, item)
        if (count == n):
            return mss_count
    return mss_count


def add_len_to_list(size, pkt_len_list):
    pkt_len_list.insert(0, size)

    if (len(pkt_len_list) > 10):
        pkt_len_list.pop()


def isolate(config, flow):
    mss = flow.src_MSS if (flow.forward_direction == 0) else flow.dst_MSS
    is_active = 0
    pkt_count = 0
    byte_count = 0
    start = 0
    payload_sz = 0
    p0_mss = get_first_data_pkt_len(flow)
    pkt_cnt = 0
    start_nr = 0
    data_pkt_len_list = []

    for packet in list(flow.packet_list):
        if (start == 0):
            start = packet.timestamp
            start_nr = pkt_cnt
            prev_timestamp = packet.timestamp

        if (is_active == 1):
            if (packet.direction == flow.forward_direction) and \
                    (packet.payload_len > 0):
                payload_sz = packet.payload_len + packet.options_len
                pkt_count += 1
                byte_count += payload_sz
                add_len_to_list(payload_sz, data_pkt_len_list)

                if ((len(data_pkt_len_list) == 10) and \
                    (get_last_n_MSS_sized(10, mss, data_pkt_len_list) <= config["Siekkinen"]["Isolate_threshold"])) or \
                        ((is_MSS_sized(mss, p0_mss) == 0) and \
                         (packet.timestamp - prev_timestamp) > (packet.rtt / 2) and \
                         (packet.is_retransmission == 0) and \
                         (packet.is_fast_retransmission == 0) and \
                         (packet.is_spurious_retransmission == 0)):
                    if (pkt_count >= config["Siekkinen"]["btp_pkt_cnt_threshold"]):
                        # Store current period as IM_BTP
                        im_entry = im_period(start, packet.timestamp, (packet.timestamp - start), IM_BTP, pkt_count,
                                             byte_count)
                        im_entry.start_pkt_nr = start_nr
                        im_entry.end_pkt_nr = pkt_cnt - 1
                    else:
                        # Store current period as IM_STP
                        im_entry = im_period(start, packet.timestamp, (packet.timestamp - start), IM_STP, pkt_count,
                                             byte_count)
                        im_entry.start_pkt_nr = start_nr
                        im_entry.end_pkt_nr = pkt_cnt - 1
                    flow.isolate_periods.append(im_entry)
                    is_active = 0
                    pkt_count = 0
                    byte_count = 0
                    start = packet.timestamp
                    start_nr = pkt_cnt
                p0_mss = payload_sz
                prev_timestamp = packet.timestamp
        else:
            pkt_count += 1
            payload_sz = packet.payload_len + packet.options_len
            byte_count += payload_sz
            if (packet.direction == flow.forward_direction) and \
                    (packet.payload_len > 0):
                add_len_to_list(payload_sz, data_pkt_len_list)
                prev_timestamp = packet.timestamp

            n = get_last_n_MSS_sized(3, mss, data_pkt_len_list)

            if n == 3:
                # Store current IM_ALP
                im_entry = im_period(start, packet.timestamp, (packet.timestamp - start), IM_ALP, pkt_count, byte_count)
                im_entry.start_pkt_nr = start_nr
                im_entry.end_pkt_nr = pkt_cnt - 1
                flow.isolate_periods.append(im_entry)
                is_active = 1
                start = packet.timestamp
                start_nr = pkt_cnt
                pkt_count = 0
                byte_count = 0
        pkt_cnt += 1

    prev_timestamp = flow.packet_list[-1].timestamp
    if (start != prev_timestamp):
        if (len(data_pkt_len_list) == 10) and \
                (get_last_n_MSS_sized(10, mss, data_pkt_len_list) > config["Siekkinen"]["Isolate_threshold"]):
            if (pkt_count >= config["Siekkinen"]["btp_pkt_cnt_threshold"]):
                # Store current period as IM_BTP
                im_entry = im_period(start, prev_timestamp, (packet.timestamp - start), IM_BTP, pkt_count, byte_count)
                im_entry.start_pkt_nr = start_nr
                im_entry.end_pkt_nr = pkt_cnt - 1
            else:
                # Store current period as IM_STP
                im_entry = im_period(start, prev_timestamp, (packet.timestamp - start), IM_STP, pkt_count, byte_count)
                im_entry.start_pkt_nr = start_nr
                im_entry.end_pkt_nr = pkt_cnt - 1
        else:
            im_entry = im_period(start, prev_timestamp, (packet.timestamp - start), IM_ALP, pkt_count, byte_count)
            im_entry.start_pkt_nr = start_nr
            im_entry.end_pkt_nr = pkt_cnt - 1
        flow.isolate_periods.append(im_entry)


def merge_periods(p1, p2):
    new_period = im_period(p1.start, p2.end, (p1.duration + p2.duration), -1, (p1.pkt_count + p2.pkt_count),
                           (p1.byte_count + p2.byte_count))
    if (p1.start_pkt_nr != -1):
        new_period.start_pkt_nr = p1.start_pkt_nr
    else:
        new_period.start_pkt_nr = p2.start_pkt_nr
    new_period.end_pkt_nr = p2.end_pkt_nr
    return new_period


def merge(config, flow):
    p_merge = im_period(0, 0, 0, -1, 0, 0)
    prev = -1
    s_new = []
    i = 0
    sum_bytes = 0
    sum_duration = 0
    flow.siekkinen_data = flow.isolate_periods
    while True:
        for period in flow.siekkinen_data:
            if (period.period_type == IM_STP) or (period.period_type == IM_BTP):
                sum_bytes += period.byte_count
                sum_duration += period.duration * period.n
                tput_transfer = sum_bytes / sum_duration
                tput_merged = (p_merge.byte_count + period.byte_count) / (p_merge.duration + period.duration)

                if (tput_merged / tput_transfer) >= config["Siekkinen"]["drop"]:
                    # Merger Allowed
                    p_merge = merge_periods(p_merge, period)
                    p_merge.n = (tput_merged / tput_transfer)
                else:
                    # Merger not Allowed
                    if p_merge.pkt_count >= config["Siekkinen"]["btp_pkt_cnt_threshold"]:
                        p_merge.period_type = IM_BTP
                    else:
                        p_merge.period_type = IM_STP
                    if p_merge not in s_new:
                        s_new.append(p_merge)
                    if (prev not in s_new) and (prev != -1):
                        s_new.append(prev)
                p_merge = period
                sum_bytes = period.byte_count
                sum_duration = period.duration * period.n
                prev = period
            elif (i != 0) and (i != len(flow.isolate_periods) - 1) and (period.period_type == IM_ALP):
                # Merge with the interleaving IM_ALP
                p_merge = merge_periods(p_merge, period)
            i += 1
        if (flow.siekkinen_data == s_new) or (not s_new):
            break
        flow.siekkinen_data = s_new


def get_disp_score(config, flow, period):
    disp_score = 0
    avg_thrput = 0
    duration = period.end - period.start

    if (flow.bl_capacity == 0) or (flow.bl_capacity == -1):
        return 0, 0

    # Convert capacity from Mbps to bps
    capacity = flow.bl_capacity * 1000000
    if (duration > 0) and (capacity > 0):
        avg_thrput = float((period.byte_count * 8 / duration))
        disp_score = (1 - (avg_thrput / capacity))

    return disp_score, (avg_thrput / (10 ** 6))


def get_retr_score(config, flow, period):
    retr_score = 0
    retr_count = 0
    total_packets = 0

    for packet in flow.packet_list:
        if (packet.direction == flow.forward_direction):
            # Check if the packet is within the time window of the period
            if (packet.timestamp >= period.start) or (packet.timestamp < period.end):
                if (packet.is_retransmission == 1) or \
                        (packet.is_fast_retransmission == 1) or \
                        (packet.is_spurious_retransmission == 1):
                    retr_count += 1
                total_packets += 1

    # Calculate retransmission rate for the time period until previous timestamp
    if (total_packets > 0):
        retr_score = retr_count / total_packets
    return retr_score


def get_rwnd_score(config, flow, period):
    rscore_sum = 0
    rscore_cnt = 0
    rwnd_score = 0
    lb = config["Siekkinen"]["rwnd_score_lb"]
    mss = flow.src_MSS if (flow.forward_direction == 1) else flow.dst_MSS
    start_time = period.start
    ob_ts = []
    rw_ts = []

    # Assuming ob_tuple and rwnd_tuple are generated for every packet in flow including both directions
    for (ob_tuple, rwnd_tuple) in zip(flow.tseries.outstanding_bytes, flow.tseries.receiver_advertised_window):
        if (ob_tuple[0] == rwnd_tuple[0]) and \
                ((ob_tuple[0] >= period.start) or \
                 (ob_tuple[0] < period.end)):
            if ((start_time - ob_tuple[0]) < flow.min_rtt):
                ob_ts.append(ob_tuple[1])
                rw_ts.append(rwnd_tuple[1])
            else:
                start_time = ob_tuple[0]

    for (ob, rw) in zip(ob_ts, rw_ts):
        rscore = 1 if ((rw - ob) < lb * mss) else 0
        rscore_sum += rscore
        rscore_cnt += 1

    if (rscore_cnt > 0):
        rwnd_score = (rscore_sum / rscore_cnt)

    return rwnd_score


def get_bscore(config, flow, period):
    rwnd_count = 0
    prev_time = 0
    sum_rwnd = 0
    sum_iat = 0
    bscore = 0
    iats = []
    iat = 0

    mss = flow.src_MSS if (flow.forward_direction == 1) else flow.dst_MSS
    for packet in list(flow.packet_list):
        if (packet.timestamp >= period.start) or \
                (packet.timestamp < period.end):
            if (packet.direction == flow.forward_direction) and \
                    (packet.payload_len > 0):
                if (prev_time == 0):
                    prev_time = packet.timestamp
                iat = packet.timestamp - prev_time

                sum_iat += iat
                iats.append(iat)
                prev_time = packet.timestamp
            else:
                sum_rwnd += packet.rwnd
                rwnd_count += 1

    if (rwnd_count > 0) and (len(iats) > 0) and (mss > 0):
        avg_rwnd = ((sum_rwnd / rwnd_count) / mss)
        avg_iat = sum_iat / len(iats)
        p = float(100 * (1 - (1 / avg_rwnd)))
        iat_np = np.array(iats)
        iat_p = np.percentile(iat_np, p)
        b_score = (iat_p / (avg_iat * avg_rwnd))
    return b_score


def analyse_root_cause(config, flow, periods_list):
    for period in periods_list:
        if (period.period_type == IM_ALP):
            period.root_cause = ALP
            continue

        s_score = siekkinen_scores()
        disp_score, avg_throughput = get_disp_score(config, flow, period)
        s_score.avg_throughput = avg_throughput
        s_score.disp_score = disp_score
        s_score.disp_score_threshold = float(config["Siekkinen"]["th_disp"])
        if (disp_score < float(config["Siekkinen"]["th_disp"])):
            # Unshared Bottleneck limitation
            period.root_cause = UBL
        else:
            retr_score = get_retr_score(config, flow, period)
            s_score.retr_score = retr_score
            s_score.retr_score_threshold = float(config["Siekkinen"]["th_retr"])
            if (retr_score > float(config["Siekkinen"]["th_retr"])):
                # Shared Bottleneck limitation
                period.root_cause = SBL
            else:
                rwnd_score = get_rwnd_score(config, flow, period)
                s_score.rwnd_score = rwnd_score
                s_score.rwnd_score_threshold = float(config["Siekkinen"]["th_rwnd"])
                if (rwnd_score > float(config["Siekkinen"]["th_rwnd"])):
                    b_score = get_bscore(config, flow, period)
                    s_score.b_score = b_score
                    s_score.b_score_threshold = float(config["Siekkinen"]["th_bscore"])
                    if (b_score > float(config["Siekkinen"]["th_bscore"])):
                        # Receive Buffer limitation
                        period.root_cause = RB
                    else:
                        # Shared Bottleneck limitation
                        period.root_cause = SBL
                else:
                    if (rwnd_score == 0) and (retr_score == 0):
                        # TCP CC/CA limitation
                        period.root_cause = CA
                    else:
                        # Mixed/Unknown limitation
                        period.root_cause = UK
        period.deciding_metrics.append(s_score)


def get_color(rca):
    if (rca == ALP):
        return 'tab:blue', 'ALP', 0.75
    elif (rca == UBL):
        return 'tab:pink', 'UBL', 2.75
    elif (rca == SBL):
        return 'tab:grey', 'SBL', 4.75
    elif (rca == RB):
        return 'tab:orange', 'RB', 6.75
    elif (rca == CA):
        return 'tab:brown', 'CA', 8.75
    else:
        return 'tab:purple', 'UK', 10.75


def plot_rca(flow, outdir, flow_cnt, fixed):
    # Declaring a figure "gnt"
    fig, gnt = plt.subplots(figsize=(15, 5))

    # Find initial time value to get relative time
    first_packet = flow.packet_list[0]
    last_packet = flow.packet_list[-1]
    start_time = first_packet.timestamp
    end_time = last_packet.timestamp

    # Setting Y-axis limits
    gnt.set_ylim(0, 12)

    # Setting X-axis limits
    gnt.set_xlim(0, end_time - start_time)

    # Setting labels for x-axis and y-axis
    gnt.set_xlabel('Flow duration in seconds')
    gnt.set_ylabel('Siekkinen Limitations')

    # Setting ticks on y-axis
    gnt.set_yticks([1, 3, 5, 7, 9, 11])

    # Labelling tickes of y-axis
    gnt.set_yticklabels(
        ['ALP', 'Unshared bottleneck', 'Shared bottleneck', 'Receive buffer', 'Congestion Avoidance', 'Unknown'])

    # Setting graph attribute
    gnt.grid(True)

    olist = []
    if fixed == 1:
        file_name = "siekkinen_fixed_flow_" + str(flow_cnt) + ".png"
        olist = flow.fixed_periods
    else:
        file_name = "siekkinen_flow_" + str(flow_cnt) + ".png"
        olist = flow.siekkinen_data

    for entry in olist:
        temp_list = []
        if (entry.duration == -1):
            if (entry.end == -1):
                entry.duration = end_time - entry.start
            else:
                entry.duration - entry.end - entry.start
        new_entry = (entry.start - start_time, entry.duration)
        temp_list.append(new_entry)
        color, label, height = get_color(entry.root_cause)
        gnt.broken_barh(temp_list, (height, 0.5), color=color, label=label)

    handles, labels = plt.gca().get_legend_handles_labels()
    by_label = OrderedDict(zip(labels, handles))
    plt.legend(by_label.values(), by_label.keys())

    graph_name = os.path.join(outdir, file_name)
    plt.savefig(graph_name)


def run_IM_algorithm(config, flows):
    for flow in flows:
        isolate(config, flow)
        merge(config, flow)


def perform_siekkinen_rca(config, flows, outdir):
    flow_cnt = 1
    for flow in flows:
        analyse_root_cause(config, flow, flow.siekkinen_data)
        # plot_rca(flow, outdir, flow_cnt, 0)
        flow_cnt += 1


def get_fixed_periods(config, flow):
    fixed_periods = []
    fixed_limit = float(config["Siekkinen"]["fixed_interval"])
    for period in flow.siekkinen_data:
        if (period.period_type == IM_ALP):
            # Store current IM_ALP
            im_entry = im_period(period.start, period.end, period.end - period.start, IM_ALP, period.pkt_count,
                                 period.byte_count)
            im_entry.start_pkt_nr = period.start_pkt_nr
            im_entry.end_pkt_nr = period.end_pkt_nr
            im_entry.root_cause = ALP
            fixed_periods.append(im_entry)

        elif (period.period_type == IM_BTP) or (period.period_type == IM_STP):
            if (period.end_pkt_nr <= period.start_pkt_nr):
                continue
            pkt_list = flow.packet_list[period.start_pkt_nr:period.end_pkt_nr]
            prev_timestamp = pkt_list[0].timestamp
            start = period.start_pkt_nr
            end = period.end_pkt_nr
            start_time = pkt_list[0].timestamp
            end_time = pkt_list[-1].timestamp
            pkt_cnt = 0
            byte_count = 0
            pkt_num = period.start_pkt_nr

            for pkt in pkt_list:
                if (pkt.timestamp - start_time) < fixed_limit:
                    pkt_cnt += 1
                    byte_count += pkt.payload_len + pkt.options_len
                else:
                    # Store fixed period
                    im_entry = im_period(start_time, pkt.timestamp, pkt.timestamp - start_time, IM_STP, pkt_cnt,
                                         byte_count)
                    im_entry.start_pkt_nr = start
                    im_entry.end_pkt_nr = pkt_num
                    fixed_periods.append(im_entry)

                    start_time = pkt.timestamp
                    start = pkt_num
                    pkt_cnt = 0
                    byte_count = 0

                pkt_num += 1

            if (start_time != end_time):
                # Store fixed period
                im_entry = im_period(start_time, end_time, (end_time - start_time), IM_STP, pkt_cnt, byte_count)
                im_entry.start_pkt_nr = start
                im_entry.end_pkt_nr = end
                fixed_periods.append(im_entry)
        else:
            print("Invalid IM period type")

    return fixed_periods


def perform_fixed_siekkinen_rca(config, flows, outdir):
    flow_cnt = 1
    for flow in flows:
        flow.fixed_periods = get_fixed_periods(config, flow)
        analyse_root_cause(config, flow, flow.fixed_periods)
        # plot_rca(flow, outdir, flow_cnt, 1)
        flow_cnt += 1

