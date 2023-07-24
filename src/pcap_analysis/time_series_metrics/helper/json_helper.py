# JSON helper functiions file
#!/usr/bin/python

import sys
import json
import os.path


from time_series_metrics.helper.process_pcap import *
from time_series_metrics.helper.rca import *


class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        # 👇️if passed in object is instance of Decimal
        # convert it to a string
        if isinstance(obj, Decimal):
            return str(obj)
        # 👇️otherwise use the default behavior
        return json.JSONEncoder.default(self, obj)

flows_data = {}
def export_flows_as_json(flows, json_file):
    flow_count = 0
    for flow in flows:
        flow_json = {}
        flow_json["src_ip"] = flow.src_ip
        flow_json["dst_ip"] = flow.dst_ip
        flow_json["src_port"] = flow.src_port
        flow_json["dst_port"] = flow.dst_port
        flow_json["src_type"] = flow.src_type
        flow_json["dst_type"] = flow.dst_type
        flow_json["src_end"] = flow.src_end
        flow_json["dst_end"] = flow.dst_end
        flow_json["src_wscale"] = flow.src_wscale
        flow_json["dst_wscale"] = flow.dst_wscale
        flow_json["tx_bytes"] = flow.tx_bytes
        flow_json["rx_bytes"] = flow.rx_bytes
        flow_json["src_MSS"] = flow.src_MSS
        flow_json["dst_MSS"] = flow.dst_MSS
        flow_json["send_buffer_size"] = flow.send_buffer_size
        flow_json["max_send_buffer_size"] = flow.max_send_buffer_size
        flow_json["bl_capacity"] = flow.bl_capacity
        flow_json["flow_duration"] = flow.flow_duration
        flow_json["retransmission_count"] = flow.retransmission_count
        flow_json["time_interval_d1"] = flow.time_interval_d1
        flow_json["time_interval_d2"] = flow.time_interval_d2
        flow_json["start_pkt_num"] = flow.start_pkt_num
        flow_json["end_pkt_num"] = flow.end_pkt_num
        flow_json["rx_pkt_count"] = flow.rx_pkt_count
        flow_json["tx_pkt_count"] = flow.tx_pkt_count
        flow_json["mp_sender_side"] = flow.mp_sender_side
        flow_json["connection_terminated"] = flow.src_end or flow.dst_end
        flow_json["timestamp_option_available"] = flow.timestamp_option_available
        flow_json["forward_direction"] = flow.forward_direction
        flow_json["avg_rtt"] = flow.avg_rtt
        flow_json["min_rtt"] = flow.min_rtt

        pkt_count = 0
        packets = {}
        for pkt in flow.packet_list:
            pkt_json = {}
            pkt_json["direction"] = pkt.direction
            pkt_json["seq_nr"] = pkt.seq_nr
            pkt_json["ack_nr"] = pkt.ack_nr
            pkt_json["flags"] = pkt.flags
            pkt_json["size"] = pkt.size
            pkt_json["rwnd"] = pkt.rwnd
            pkt_json["rtt"] = pkt.rtt
            pkt_json["timestamp"] = pkt.timestamp
            pkt_json["shifted_timestamp"] = pkt.shifted_timestamp
            pkt_json["TSval"] = pkt.TSval
            pkt_json["TSecr"] = pkt.TSecr
            pkt_json["ECN"] = pkt.ECN
            pkt_json["retransmission"] = pkt.is_retransmission
            pkt_json["spurious_retransmission"] = pkt.is_spurious_retransmission
            pkt_json["fast_retransmission"] = pkt.is_fast_retransmission
            pkt_json["keep_alive"] = pkt.is_keep_alive
            pkt_json["dup_ack"] = pkt.is_dup_ack
            pkt_json["out_of_order"] = pkt.is_out_of_order
            pkt_json["payload_len"] = pkt.payload_len
            pkt_json["options_len"] = pkt.options_len
            pkt_json["prev_max_next_seq_nr"] = pkt.tcp_seq_info.prev_max_next_seq_nr
            pkt_json["prev_segment_time"] = pkt.tcp_seq_info.prev_segment_time
            pkt_json["next_seq_nr"] = pkt.tcp_seq_info.next_seq_nr
            pkt_json["max_next_seq_nr"] = pkt.tcp_seq_info.max_next_seq_nr
            pkt_json["last_seen_ack_nr"] = pkt.tcp_seq_info.last_seen_ack_nr
            pkt_json["last_seen_ack_time"] = pkt.tcp_seq_info.last_seen_ack_time
            pkt_json["last_seen_ack_rwnd"] = pkt.tcp_seq_info.last_seen_ack_rwnd
            pkt_json["last_seen_dup_ack_cnt"] = pkt.tcp_seq_info.last_seen_dup_ack_cnt

            # add packet to packet list json
            pkt_count += 1
            pkt_name = "Packet " + str(pkt_count)
            packets[pkt_name] = pkt_json

        flow_json["packet_list"] = packets

        # add flow to json
        flow_count += 1
        flow_name = "Flow " + str(flow_count)
        flows_data[flow_name] = flow_json

    with open(json_file, 'w') as outfile:
        json.dump(flows_data, outfile, cls=DecimalEncoder,  indent=4)

def import_json_as_flows(flows, json_file):
    if not os.path.exists(json_file):
        sys.exit("Input json file does not exist")

    # open json file
    infile = open(json_file, 'r')

    # Read json data
    flows_data = json.load(infile)

    # Import flow information
    for name,flow in flows_data.items():
        src_ip = flow["src_ip"]
        dst_ip = flow["dst_ip"]
        src_port = int(flow["src_port"])
        dst_port = int(flow["dst_port"])
        pkt_num = int(flow["start_pkt_num"])

        # Create new flow
        new_flow = flow_info(src_ip, dst_ip, src_port, dst_port, pkt_num)

        new_flow.src_type = str(flow["src_type"])
        new_flow.dst_type = str(flow["dst_type"])
        new_flow.src_end = int(flow["src_end"])
        new_flow.dst_end = int(flow["dst_end"])
        new_flow.src_wscale = int(flow["src_wscale"])
        new_flow.dst_wscale = int(flow["dst_wscale"])
        new_flow.tx_bytes = int(flow["tx_bytes"])
        new_flow.rx_bytes = int(flow["rx_bytes"])
        new_flow.src_MSS = int(flow["src_MSS"])
        new_flow.dst_MSS = int(flow["dst_MSS"])
        new_flow.rx_pkt_count = int(flow["rx_pkt_count"])
        new_flow.tx_pkt_count = int(flow["tx_pkt_count"])
        new_flow.end_pkt_num = int(flow["end_pkt_num"])
        new_flow.flow_duration = float(flow["flow_duration"])
        new_flow.time_interval_d1 = float(flow["time_interval_d1"])
        new_flow.time_interval_d2 = float(flow["time_interval_d2"])
        new_flow.mp_sender_side = int(flow["mp_sender_side"])
        new_flow.send_buffer_size = float(flow["send_buffer_size"])
        new_flow.max_send_buffer_size = float(flow["max_send_buffer_size"])
        new_flow.bl_capacity = float(flow["bl_capacity"])
        new_flow.retransmission_count = int(flow["retransmission_count"])
        new_flow.timestamp_option_available = int(flow["timestamp_option_available"])
        new_flow.forward_direction = int(flow["forward_direction"])
        new_flow.avg_rtt = float(flow["avg_rtt"])
        new_flow.min_rtt = float(flow["min_rtt"])

        pkt_list = flow["packet_list"]
        # Import packet information
        for pkt_name, pkt in pkt_list.items():
            # Create new packet
            packet = packet_info()

            packet.direction = int(pkt["direction"])
            packet.seq_nr = int(pkt["seq_nr"])
            packet.ack_nr = int(pkt["ack_nr"])
            packet.flags = str(pkt["flags"])
            packet.size = int(pkt["size"])
            packet.rwnd = int(pkt["rwnd"])
            packet.rtt = float(pkt["rtt"])
            packet.timestamp = float(pkt["timestamp"])
            packet.shifted_timestamp = float(pkt["shifted_timestamp"])
            packet.TSval = float(pkt["TSval"])
            packet.TSecr = float(pkt["TSecr"])
            packet.ECN = int(pkt["ECN"])
            packet.is_retransmission = int(pkt["retransmission"])
            packet.is_fast_retransmission = int(pkt["fast_retransmission"])
            packet.is_spurious_retransmission = int(pkt["spurious_retransmission"])
            packet.is_keep_alive = int(pkt["keep_alive"])
            packet.is_dup_ack = int(pkt["dup_ack"])
            packet.is_out_of_order = int(pkt["out_of_order"])
            packet.payload_len = int(pkt["payload_len"])
            packet.options_len = int(pkt["options_len"])
            packet.tcp_seq_info = tcp_sequence_info()
            packet.tcp_seq_info.prev_max_next_seq_nr  = int(pkt["prev_max_next_seq_nr"])
            packet.tcp_seq_info.prev_segment_time = float(pkt["prev_segment_time"])
            packet.tcp_seq_info.next_seq_nr = int(pkt["next_seq_nr"])
            packet.tcp_seq_info.max_next_seq_nr = int(pkt["max_next_seq_nr"])
            packet.tcp_seq_info.last_seen_ack_nr = int(pkt["last_seen_ack_nr"])
            packet.tcp_seq_info.last_seen_ack_time = float(pkt["last_seen_ack_time"])
            packet.tcp_seq_info.last_seen_ack_rwnd = int(pkt["last_seen_ack_rwnd"])
            packet.tcp_seq_info.last_seen_dup_ack_cnt = int(pkt["last_seen_dup_ack_cnt"])

            # Add packet to flow.packet_list
            new_flow.packet_list.append(packet)

        # Add flow to list of flows
        flows.append(new_flow)

    # Close json file
    infile.close()

def get_limitation_name(limitation):
    if limitation == 'slow sender':
        return SS
    elif limitation == 'slow receiver':
        return SR
    elif limitation == 'send buffer':
        return SB
    elif limitation == 'receive buffer':
        return RB
    elif limitation == 'unshared bottleneck':
        return UBL
    elif limitation == 'shared bottleneck':
        return SBL
    elif limitation == 'transport layer':
        return CA
    else:
        return UK

def import_theo_values(theo_data, config, outdir):
    theo_file = os.path.join(outdir, "theoretical_limitations.json")
    if not os.path.exists(theo_file):
        sys.exit("Input theoretically expected limitations file does not exist")

    # open json file
    infile = open(theo_file, 'r')

    # Read json data
    periods = json.load(infile)

    # Import flow information
    for name,period in periods.items():
        start      = float(period["start"])
        end        = float(period["end"])
        limitation = get_limitation_name(str(period['limitation']))
        new_period = theo_period(start, end, limitation)

        new_period.throughput  = float(period['throughput'])
        new_period.metrics.mss         = float(period['mss'])
        new_period.metrics.rtt         = float(period['rtt'])
        new_period.metrics.bandwidth   = float(period['bandwidth'])
        new_period.metrics.loss        = float(period['loss'])
        new_period.metrics.latency     = float(period['latency'])
        new_period.metrics.buffer_size = float(period['buffer_size'])
        new_period.metrics.cpu_share   = float(period['cpu_share'])
        new_period.metrics.delay       = float(period['delay'])

        theo_data.append(new_period)


