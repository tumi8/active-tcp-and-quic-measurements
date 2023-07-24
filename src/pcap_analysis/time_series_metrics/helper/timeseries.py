# Process Pcap file
#!/usr/bin/python

import collections
import numpy as np

from time_series_metrics.helper.process_pcap import *
from time_series_metrics.helper.tcp_helper import *
from time_series_metrics.helper.utils import *

MAX_SEQACK_NUMBER = 4294967295


# Function to calculate running RTT
# estimates for both directions
def get_running_rtt_estimates(flow):
    if (flow.timestamp_option_available == 1):
        get_rtt_from_timestamp_option(flow)
    # We do not consider flows without timestamp option
    # else:
    #    get_rtt_fallback(flow)


def get_rtt_fallback(flow):
    # Fallback method
    count = 0

    for packet in list(flow.packet_list):
        count += 1
        if (packet.direction != flow.forward_direction):
            continue
        # Update RTT values whenever ACK is received
        if has_flag(packet.flags, ACK):
            # Find corresponding packet that is acked
            search_list = flow.packet_list[:count]
            for pkt in reversed(search_list):
                # Only look in the reverse direction packets
                if pkt.direction != packet.direction:
                    # Case to handle SYN packets
                    if pkt.payload_len == 0:
                        next_ack = packet.ack_nr - 1
                    else:
                        next_ack = packet.ack_nr
                    # Corresponding packet with seq_nr found
                    if (pkt.seq_nr + pkt.payload_len) == next_ack:
                        # Update timestamp and break from search
                        packet.rtt = packet.timestamp - pkt.timestamp
                        break


def get_rtt_from_timestamp_option(flow):
    timestamp_tracker = []
    prev_rtt = 0
    count = 0

    for packet in list(flow.packet_list):
        count += 1
        # For every packet from sender (s1,-)
        if (packet.direction == flow.forward_direction):
            packet.rtt = prev_rtt
            # Only calculate RTT for data packets
            if (packet.payload_len <= 0):
                continue
            # Check if we have multiple packets with same timestamp
            # Only consider first packet and ignore the following packets
            if (packet.TSval in timestamp_tracker):
                continue
            timestamp_tracker.append(packet.TSval)
            ack_count = count
            # Find corresponding ack packet (r1,s1)
            for pkt_ack in list(flow.packet_list[count:]):
                ack_count += 1
                # Consider only ACK segments
                if (pkt_ack.direction == flow.forward_direction) or (has_flag(pkt_ack.flags, ACK) == 0):
                    continue
                # Match s1
                if (pkt_ack.TSecr == packet.TSval):
                    # Find respective echo packet for the ack packet (s2,r1)
                    for pkt_echo in list(flow.packet_list[ack_count:]):

                        # Consider only ACK segments
                        if (pkt_echo.direction != flow.forward_direction):
                            continue
                        # Match r1
                        if (pkt_echo.TSecr == pkt_ack.TSval):
                            packet.rtt = pkt_echo.timestamp - packet.timestamp
                            if (flow.min_rtt == 0):
                                flow.min_rtt = packet.rtt
                            elif (packet.rtt > 0) and (flow.min_rtt > 0):
                                flow.min_rtt = min(packet.rtt, flow.min_rtt)
                            prev_rtt = packet.rtt
                            break
                    break
    del (timestamp_tracker)


def get_sender_buffer_size(config, flow):
    # Get list of outstanding bytes
    send_buffer_list = [item[1] for item in flow.tseries.outstanding_bytes]
    # Sort the list
    send_buffer_list.sort(reverse=True)

    # Get quartiles
    first_quartile = np.percentile(send_buffer_list, [25])
    third_quartile = np.percentile(send_buffer_list, [75])

    send_buffer_list = [item for item in send_buffer_list if
                        ((item >= first_quartile) and (item <= third_quartile).all())]
    send_buffer_list.sort(reverse=True)

    # Get the number of occurences of every value
    send_buffers = collections.Counter(send_buffer_list)
    send_buff_list = np.array(send_buffer_list)

    # Find the maximum send buffer size
    flow.max_send_buffer_size = send_buffer_list[0]
    # Find the maximum send buffer size that occurred atleast thrice
    for key, value in send_buffers.items():
        if value > 3:
            # Get the first highest occurring outstanding bytes value
            flow.send_buffer_size = key
            break


########################## Generic Timeseries generating functions ####################

# Generic method - Packet by packet granularity

def generate_ts_rtt_generic(config, flow):
    pkt_count = 0
    rtt_sum = 0.0

    for packet in list(flow.packet_list):
        if (packet.direction == flow.forward_direction):
            pkt_count += 1
            rtt_sum += float(packet.rtt)
        rtt_tuple = packet.timestamp, (packet.rtt * 1000)
        flow.tseries.rtt.append(rtt_tuple)
    if (pkt_count > 0):
        flow.avg_rtt = rtt_sum / pkt_count


def generate_ts_outstanding_bytes_generic(config, flow):
    next_seq_nr = 0
    max_next_seq_nr = 0
    max_ack_nr = 0
    ob_count = 0

    for packet in list(flow.packet_list):
        if (packet.direction == flow.forward_direction):
            # Compute outstanding bytes
            if (packet.tcp_seq_info.max_next_seq_nr > 0) and (packet.tcp_seq_info.last_seen_ack_nr > 0):
                if (packet.tcp_seq_info.max_next_seq_nr < packet.tcp_seq_info.last_seen_ack_nr):
                    if ((packet.tcp_seq_info.last_seen_ack_nr - packet.tcp_seq_info.max_next_seq_nr) > (2 ** 30)):
                        packet.tcp_seq_info.max_next_seq_nr += (2 ** 32)
                if packet.tcp_seq_info.max_next_seq_nr >= packet.tcp_seq_info.last_seen_ack_nr:
                    ob_count = (packet.tcp_seq_info.max_next_seq_nr - packet.tcp_seq_info.last_seen_ack_nr)
                else:
                    ob_count = (packet.tcp_seq_info.max_next_seq_nr - (packet.tcp_seq_info.last_seen_ack_nr - 1))
        ob_tuple = (packet.timestamp, ob_count)
        flow.tseries.outstanding_bytes.append(ob_tuple)


def generate_ts_sender_buffer_generic(config, flow):
    send_buffer = 0

    for item in list(flow.tseries.outstanding_bytes):
        send_buffer = max(send_buffer, item[1])
        sb_tuple = (item[0], send_buffer)
        flow.send_buffer_size = send_buffer
        flow.tseries.sender_buffer.append(sb_tuple)


def generate_ts_retransmission_generic(config, flow):
    retr_count = 0
    retr_tuple = 0
    total_packets = 0
    retransmission_rate = 0

    for packet in list(flow.packet_list):
        if (packet.direction != flow.forward_direction):
            continue

        next_seq_nr = packet.tcp_seq_info.prev_max_next_seq_nr

        if ((packet.payload_len > 0) or \
            (has_flag(packet.flags, SYN) == 1) or \
            (has_flag(packet.flags, FIN) == 1)) == 0:
            continue

        if (packet.seq_nr < next_seq_nr):
            if (next_seq_nr - packet.seq_nr) > (2 ** 30):
                packet.seq_nr += (2 ** 32)
        seq_not_advanced = (next_seq_nr > 0) and (packet.seq_nr < next_seq_nr)

        # Check if packet is keep_alive
        packet.is_keep_alive = is_keep_alive(packet, next_seq_nr)
        if (packet.is_keep_alive == 1):
            continue

        if (packet.payload_len > 1) and (next_seq_nr - 1 == packet.seq_nr):
            seq_not_advanced = 0

        # Check if the packet is a spurious retransmission packet
        packet.is_spurious_retransmission = is_spurious_retransmission(packet)
        if (packet.is_spurious_retransmission == 1):
            continue

        # Check if the packet is a fast retransmission packet
        packet.is_fast_retransmission = is_fast_retransmission(packet, seq_not_advanced)
        if (packet.is_fast_retransmission == 1):
            continue

        # Check if the packet is out-of-order
        packet.is_out_of_order = is_out_of_order(packet, seq_not_advanced)
        if (packet.is_out_of_order == 1):
            continue

        # Check if the packet is a retransmission packet
        if (seq_not_advanced == 1):
            packet.is_retransmission = 1
            continue

    # Update total retransmission count of flow
    flow.retransmission_count = retr_count

    prev_timestamp = flow.packet_list[0].timestamp
    start_timestamp = flow.packet_list[0].timestamp
    for packet in list(flow.packet_list):
        if (packet.direction == flow.forward_direction):
            # Check if we exhausted the time window specified in config
            if float(packet.timestamp - start_timestamp) <= float(config["timeseries"]["retransmission_interval"]):
                if (packet.is_retransmission == 1) or \
                        (packet.is_fast_retransmission == 1) or \
                        (packet.is_spurious_retransmission == 1):
                    retr_count += 1
                total_packets += 1
            else:
                # Calculate retransmission rate for the time period until previous timestamp
                if (total_packets > 0):
                    retransmission_rate = retr_count / total_packets
                # Start new time period with current timestamp
                start_timestamp = packet.timestamp
                retr_count = 0
        # Add an entry in the timeseries
        retr_tuple = prev_timestamp, retransmission_rate
        flow.tseries.retransmission.append(retr_tuple)
        # Update the previous timestamp value
        prev_timestamp = packet.timestamp

    # We might not have exhausted the time window,
    # But the flow would have ended
    if (prev_timestamp != start_timestamp):
        if (total_packets > 0):
            retransmission_rate = retr_count / total_packets
            retr_tuple = prev_timestamp, retransmission_rate
            flow.tseries.retransmission.append(retr_tuple)

    # Update total retransmission count of flow
    flow.retransmission_count = retr_count


def generate_ts_rwnd_generic(config, flow):
    rwnd = 0
    for packet in list(flow.packet_list):
        if (packet.direction != flow.forward_direction):
            rwnd = packet.rwnd
        rwnd_tuple = packet.timestamp, rwnd
        flow.tseries.receiver_advertised_window.append(rwnd_tuple)


def generate_ts_throughput_generic(config, flow):
    throughput = 0
    bytes_sent = 0
    time_consumed = 0
    last_timestamp = [packet.timestamp for packet in flow.packet_list if packet.direction == flow.forward_direction][-1]
    start_timestamp = [packet.timestamp for packet in flow.packet_list if packet.direction == flow.forward_direction][0]
    throughput_tuple = []

    for packet in list(flow.packet_list):
        if (packet.direction == flow.forward_direction):
            # Check if we exhausted the time window specified in config
            if float(packet.timestamp - start_timestamp) <= float(config["timeseries"]["throughput_interval"]):
                bytes_sent += packet.payload_len
            else:
                # Calculate throughput for the time period until previous timestamp
                time_consumed = (packet.timestamp - start_timestamp)
                if (time_consumed > 0):
                    throughput = (bytes_sent * 8) / time_consumed
                # Start new time period with current timestamp
                start_timestamp = packet.timestamp
                bytes_sent = packet.payload_len
        # Add an entry in the timeseries
        throughput_tuple = packet.timestamp, throughput
        flow.tseries.throughput.append(throughput_tuple)
    # We might not have exhausted the time window,
    # But the flow would have ended
    if (last_timestamp != start_timestamp):
        time_consumed = (last_timestamp - start_timestamp)
        if (time_consumed > 0):
            throughput = (bytes_sent * 8) / time_consumed
            throughput_tuple = last_timestamp, throughput
            flow.tseries.throughput.append(throughput_tuple)


def generate_ts_IAT_generic(config, flow):
    forward_prev_time = 0
    reverse_prev_time = 0
    fwd_iat = 0
    rev_iat = 0

    for packet in list(flow.packet_list):
        if (packet.direction != flow.forward_direction):
            if has_flag(packet.flags, ACK):
                if (forward_prev_time > 0):
                    fwd_iat = packet.timestamp - forward_prev_time
                forward_prev_time = packet.timestamp
                iat_tuple = packet.timestamp, fwd_iat
                flow.tseries.IAT_sender.append(iat_tuple)
        else:
            if (packet.payload_len > 0):
                if (reverse_prev_time > 0):
                    rev_iat = packet.timestamp - reverse_prev_time
                reverse_prev_time = packet.timestamp
                iat_tuple = packet.timestamp, rev_iat
                flow.tseries.IAT_receiver.append(iat_tuple)


def generate_ts_rwnd_utilisation_generic(config, flow):
    count = 0
    next_seq_nr = 0
    max_next_seq_nr = 0
    allowed_next_seq_nr = 0
    rwnd_utilisation = 0
    max_allowed_next_seq_nr = 0

    for packet in list(flow.packet_list):
        # Get max seen ack and seq nr
        if (packet.direction == flow.forward_direction) and (packet.payload_len > 0):
            next_seq_nr = packet.payload_len + packet.seq_nr
            max_next_seq_nr = max(max_next_seq_nr, next_seq_nr)
        elif (packet.direction != flow.forward_direction) and (has_flag(packet.flags, ACK) == 1):
            allowed_next_seq_nr = packet.ack_nr + packet.rwnd
            max_allowed_next_seq_nr = max(max_allowed_next_seq_nr, allowed_next_seq_nr)

        # Compute rwnd utilisation
        if (max_allowed_next_seq_nr > max_next_seq_nr):
            rwnd_utilisation = max_allowed_next_seq_nr - max_next_seq_nr
        rwnd_utilisation_tuple = (packet.timestamp, rwnd_utilisation)
        flow.tseries.receive_buffer_utilisation.append(rwnd_utilisation_tuple)


def generate_ts_rwnd_full_generic(config, flow):
    rwnd = 0

    for packet in list(flow.packet_list):
        rwnd_full = 0
        if (packet.direction == flow.forward_direction):
            if (packet.payload_len > 0) and \
                    (packet.tcp_seq_info.next_seq_nr == rwnd) and \
                    (has_flag(packet.flags, SYN) == 0) and \
                    (has_flag(packet.flags, FIN) == 0) and \
                    (has_flag(packet.flags, RST) == 0):
                rwnd_full = 1
        else:
            rwnd = packet.rwnd
        rwnd_full_tuple = (packet.timestamp, rwnd_full)
        flow.tseries.receive_buffer_full.append(rwnd_full_tuple)


#####################################################################################

# Function to call all timeseries generating functions
# TODO: Register callback to handle multiple granularities
def generate_all_timeseries(config, flows):
    for flow in flows:
        generate_ts_rtt_generic(config, flow)
        generate_ts_outstanding_bytes_generic(config, flow)
        generate_ts_sender_buffer_generic(config, flow)
        generate_ts_rwnd_generic(config, flow)
        generate_ts_IAT_generic(config, flow)
        generate_ts_rwnd_utilisation_generic(config, flow)
        generate_ts_rwnd_full_generic(config, flow)
        generate_ts_retransmission_generic(config, flow)
        generate_ts_throughput_generic(config, flow)

        get_sender_buffer_size(config, flow)


def export_data_as_csv(data_series, name, flow_dir):
    # Construct csv file name
    file_name = str(flow_dir) + "/" + str(name) + "_timeseries.csv"
    # Save as csv with nanosecond level precision (10^9)
    np.savetxt(file_name, data_series, delimiter=", ", fmt="%0.9f")


def export_timeseries_as_csv(config, flows, output_dir):
    count = 0
    for flow in flows:
        count += 1
        flow_dir = get_output_dir_name(count, output_dir)

        export_data_as_csv(flow.tseries.rtt, "RTT", flow_dir)
        export_data_as_csv(flow.tseries.outstanding_bytes, "Outstanding_Bytes", flow_dir)
        export_data_as_csv(flow.tseries.sender_buffer, "Sender_Buffer", flow_dir)
        export_data_as_csv(flow.tseries.retransmission, "Retransmission", flow_dir)
        export_data_as_csv(flow.tseries.receiver_advertised_window, "Receiver_Advertised_Window", flow_dir)
        export_data_as_csv(flow.tseries.throughput, "Throughput", flow_dir)
        export_data_as_csv(flow.tseries.IAT_sender, "IAT_Sender", flow_dir)
        export_data_as_csv(flow.tseries.IAT_receiver, "IAT_Receiver", flow_dir)
        export_data_as_csv(flow.tseries.receive_buffer_utilisation, "Receive_Buffer_Utilisation", flow_dir)
        export_data_as_csv(flow.tseries.receive_buffer_full, "Receive_Buffer_Full", flow_dir)


def import_data_from_csv(data_series, name, flow_dir):
    # Construct csv file name
    file_name = str(flow_dir) + "/" + str(name) + "_timeseries.csv"
    # Open csv file
    data = open(file_name)
    time_series = np.loadtxt(data, delimiter=",")
    for entry in time_series:
        data_series.append(entry)


def import_timeseries_from_csv(config, flows, input_directory):
    count = 0

    for flow in flows:
        count += 1
        flow_dir = get_input_dir_name(count, input_directory)

        import_data_from_csv(flow.tseries.rtt, "RTT", flow_dir)
        import_data_from_csv(flow.tseries.outstanding_bytes, "Outstanding_Bytes", flow_dir)
        import_data_from_csv(flow.tseries.sender_buffer, "Sender_Buffer", flow_dir)
        import_data_from_csv(flow.tseries.retransmission, "Retransmission", flow_dir)
        import_data_from_csv(flow.tseries.receiver_advertised_window, "Receiver_Advertised_Window", flow_dir)
        import_data_from_csv(flow.tseries.throughput, "Throughput", flow_dir)
        import_data_from_csv(flow.tseries.IAT_sender, "IAT_Sender", flow_dir)
        import_data_from_csv(flow.tseries.IAT_receiver, "IAT_Receiver", flow_dir)
        import_data_from_csv(flow.tseries.receive_buffer_utilisation, "Receive_Buffer_Utilisation", flow_dir)
        import_data_from_csv(flow.tseries.receive_buffer_full, "Receive_Buffer_Full", flow_dir)

