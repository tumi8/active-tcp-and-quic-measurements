# Process Pcap file
#!/usr/bin/python

from dataclasses import dataclass, field
from scapy.all import *

from time_series_metrics.helper.rca import *
from time_series_metrics.helper.timeseries import *
from time_series_metrics.helper.tcp_helper import *

@dataclass
class packet_info:
    tcp_seq_info: tcp_sequence_info
    direction: int = 0
    seq_nr: int = 0
    ack_nr: int = 0 
    flags: str = ""
    size: int = 0
    rwnd: int = 0
    rtt: float = 0
    timestamp: float = 0
    shifted_timestamp: float = 0
    TSval: float = 0
    TSecr: float = 0
    ECN: int = 0
    is_retransmission: bool = 0
    is_fast_retransmission: bool = 0
    is_spurious_retransmission: bool = 0
    is_keep_alive: bool = 0
    is_dup_ack: bool = 0
    is_out_of_order: bool = 0
    payload_len: int = 0
    options_len: int = 0

    # Constructor
    def __init__(self):
        return

    # Add packet information
    def add_info(self, config, flow, packet):
        ip = packet[IP] if packet.haslayer(IP) == 1 else packet[IPv6]
        tcp = packet[TCP]
        self.direction = get_direction(flow, ip, tcp)
        self.seq_nr = tcp.seq
        self.ack_nr = tcp.ack
        self.flags = str(tcp.flags)
        self.size = len(packet)
        self.rwnd = get_scaled_window(flow, self.direction, tcp.window)
        self.timestamp = packet.time
        self.ECN = get_ip_ECN(ip)
        self.payload_len = ip.len - ((ip.ihl + tcp.dataofs) * 4) if packet.haslayer(IP) == 1 else ip.plen
        self.options_len = (tcp.dataofs - 5) * 4
        self.tcp_seq_info = tcp_sequence_info()


@dataclass
class timeseries:
    rtt: list[float]
    sender_buffer: list[float]
    outstanding_bytes: list[float]
    IAT_sender: list[float]
    IAT_receiver: list[float]
    throughput: list[float]
    retransmission: list[int]
    receiver_advertised_window: list[float]
    receive_buffer_utilisation: list[float]
    receive_buffer_full: list[float]

    # Constructor
    def __init__(self):
        self.rtt = []
        self.sender_buffer = []
        self.outstanding_bytes = []
        self.IAT_sender = []
        self.IAT_receiver = []
        self.throughput = []
        self.retransmission = []
        self.receiver_advertised_window = []
        self.receive_buffer_utilisation = []
        self.receive_buffer_full = []


@dataclass
class flow_info:
    tseries: timeseries
    packet_list: list[packet_info]
    isolate_periods: list[im_period]
    fixed_periods: list[im_period]
    limitation_periods: list[im_period]
    siekkinen_data: list[im_period]
    limitations: list[limitation_period]
    src_ip: str = ""
    dst_ip: str = ""
    src_type: str = ""  # Type: sender or receiver
    dst_type: str = ""
    src_port: int = 0
    dst_port: int = 0
    src_end: bool = 0
    dst_end: bool = 0
    src_wscale: int = 0
    dst_wscale: int = 0
    tx_bytes: int = 0
    rx_bytes: int = 0
    src_MSS: int = 0
    dst_MSS: int = 0
    rx_pkt_count: int = 0
    tx_pkt_count: int = 0
    start_pkt_num: int = 0
    end_pkt_num: int = 0
    flow_duration: float = 0
    time_interval_d1: float = 0  # To calculate measurement position
    time_interval_d2: float = 0
    mp_sender_side: bool = 0
    send_buffer_size: float = 0  # Based on frequency of occurrence
    max_send_buffer_size: float = 0
    bl_capacity: float = 0
    retransmission_count: int = 0
    timestamp_option_available: bool = 0
    forward_direction: bool = 0
    avg_rtt: float = 0
    min_rtt: float = 0

    # Constructor
    def __init__(self, src_ip, dst_ip, src_port, dst_port, pkt_num):
        self.src_ip = str(src_ip)
        self.dst_ip = str(dst_ip)
        self.src_port = src_port
        self.dst_port = dst_port
        self.start_pkt_num = pkt_num
        self.tseries = timeseries()
        self.siekkinen_data = []
        self.isolate_periods = []
        self.fixed_periods = []
        self.packet_list = []
        self.limitations = limitation_period()
        self.limitation_periods = []
        return

    # Add a new packet to the flow
    def add_packet(self, config, packet, pkt_num):
        # Create packet
        pkt = packet_info()
        pkt.add_info(config, self, packet)

        conn_end = has_flag(pkt.flags, FIN) or has_flag(pkt.flags, RST)
        if pkt.direction == 1:
            self.rx_bytes += pkt.payload_len
            self.rx_pkt_count += 1
            if (self.dst_end != 1):
                self.dst_end = conn_end
        else:
            self.tx_bytes += pkt.payload_len
            self.tx_pkt_count += 1
            if (self.src_end != 1):
                self.src_end = conn_end

        # Process TCP options
        extract_tcp_options(self, packet, pkt)

        # Add packet to list and increment counter
        self.packet_list.append(pkt)
        self.end_pkt_num = pkt_num
        return


# Function to check if the packet
# belongs to an existing flow
def is_known_flow(ip, tcp, flows):
    for flow in flows:
        if (flow.src_end == 0) and (flow.dst_end == 0) and \
                (get_direction(flow, ip, tcp) != -1):
            flow_found = flow
            return flow_found
    return None


# Function to check if flow exists,
# else add a new flow to the list
# and update necessary information
def add_flow_packet(config, packet, pkt_num, flows):
    # Extract IP and TCP layer
    # Added support for IPv6
    ip = packet[IP] if packet.haslayer(IP) == 1 else packet[IPv6]
    tcp = packet[TCP]

    flow = is_known_flow(ip, tcp, flows)
    if flow is None:
        if has_flag(tcp.flags, SYN) == 1 and has_flag(tcp.flags, ACK) == 0:
            flow = flow_info(ip.src, ip.dst, tcp.sport, tcp.dport, pkt_num)
            flows.append(flow)
        else:
            return

    flow.add_packet(config, packet, pkt_num)


# Main pcap processing function
def process_pcap(pcap_file, config, flows):
    # Read all packets from the pcap
    packets = PcapReader(pcap_file)
    total_pkt_count = 0

    # Iterate through every packet
    for packet in packets:
        total_pkt_count += 1
        # Check if packet has IP and TCP layers
        if (packet.haslayer(IP) == 1 or packet.haslayer(IPv6) == 1) and packet.haslayer(TCP) == 1:
            # Add flow and packet to the list
            add_flow_packet(config, packet, total_pkt_count, flows)


# Update and cleanup flows list
def update_flows(config, flows):
    for flow in list(flows):
        # Remove flows without initial handshake
        if (has_tcp_handshake(flow) == 0):
            flows.remove(flow)
            continue

        # Remove flows that do not support timestamp option
        if (flow.timestamp_option_available == 0):
            flows.remove(flow)
            continue

        # Determine Sender and Receiver
        if (flow.tx_bytes > flow.rx_bytes):
            flow.src_type = "Sender"
            flow.dst_type = "Receiver"
            flow.forward_direction = 0
        else:
            flow.dst_type = "Sender"
            flow.src_type = "Receiver"
            flow.forward_direction = 1

        # Compute flow duration
        flow.flow_duration = flow.packet_list[-1].timestamp - flow.packet_list[0].timestamp
        # Get initial RTT values
        flow.time_interval_d1, flow.time_interval_d2 = get_mp_time_deltas(flow)

        # Get RTT running estimates
        get_running_rtt_estimates(flow)

        # Compute measurement position
        # Note: To be computed strictly after computing RTT running estimates
        get_measurement_position(config, flow)

        # Ignore flows that are not captured at sender side, if enabled
        if (config["filter"]["only_sender_side"] == 1):
            if (flow.mp_sender_side == 0):
                flows.remove(flow)
                continue

        # Perform TCP sequence analysis
        perform_sequence_analysis(flow)

        # Get Bottleneck capacity
        '''sender_side = get_capacity_measurement_position(config, flow)
        if (sender_side == 1):
            flow.bl_capacity = get_bottleneck_capacity_sender(config, flow)
        else:
            flow.bl_capacity = get_bottleneck_capacity_receiver(config, flow)'''
        #print(sender_side, get_bottleneck_capacity_sender(config, flow), get_bottleneck_capacity_receiver(config, flow))
        flow.bl_capacity = 100

