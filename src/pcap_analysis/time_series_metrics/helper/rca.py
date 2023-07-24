# RCA helper file
#!/usr/bin/python

from dataclasses import dataclass, field

# Limitations
SS = 0  # Slow Sender
SR = 1  # Slow Receiver
SB = 2  # Sender Buffer
RB = 3  # Receiver Buffer
CA = 4  # Congestion control/avoidance
UBL = 5  # Unshared Bottleneck
SBL = 6  # Shared Bottleneck
ALP = 7  # Application Layer Limited
UK = 8  # Mixed/Unknown
 
# Periods of IM algorithm
IM_ALP = 0
IM_STP = 1
IM_BTP = 2

# RCA APPROACHES
SIEKKINEN = 0
SIEKKINEN_FIXED = 1
NEW_APPROACH = 2

DEFAULT_MSS = 1460


@dataclass
class siekkinen_scores:
    avg_throughput: float = -1
    disp_score: float = -1
    disp_score_threshold: float = -1
    retr_score: float = -1
    retr_score_threshold: float = -1
    rwnd_score: float = -1
    rwnd_score_threshold: float = -1
    b_score: float = -1
    b_score_threshold: float = -1

    def __init__(self):
        return


@dataclass
class metrics_data:
    mss: int = DEFAULT_MSS
    rtt: float = 0
    bandwidth: float = 0
    loss: float = 0
    latency: float = 0
    buffer_size: int = 0
    cpu_share: float = 0
    delay: float = 0

    def __init__(self):
        return


@dataclass
class theo_period:
    metrics: metrics_data
    start: float = -1
    end: float = -1
    throughput: float = -1
    limitation: str = UK

    # Constructor
    def __init__(self, start, end, limitation):
        self.start = start
        self.end = end
        self.limitation = limitation
        self.metrics = metrics_data()


@dataclass
class im_period:
    deciding_metrics: list
    start: float = -1
    end: float = -1
    duration: float = 0.0
    byte_count: int = 0
    pkt_count: int = 0
    n: float = 0.0
    period_type: int = 0
    root_cause: int = 0
    start_pkt_nr: int = -1
    end_pkt_nr: int = -1

    def __init__(self, start, end, duration, period_type, pkt_count, byte_count):
        self.start = start
        self.end = end
        self.period_type = period_type
        self.duration = duration
        self.pkt_count = pkt_count
        self.byte_count = byte_count
        self.n = 1
        self.deciding_metrics = []


@dataclass
class limitation_period:
    slow_sender: list[im_period]
    slow_receiver: list[im_period]
    sender_buffer: list[im_period]
    receiver_buffer: list[im_period]
    unshared_bottleneck: list[im_period]
    shared_bottleneck: list[im_period]
    transport_layer: list[im_period]

    # Constructor
    def __init__(self):
        self.slow_sender = []
        self.slow_receiver = []
        self.sender_buffer = []
        self.receiver_buffer = []
        self.unshared_bottleneck = []
        self.shared_bottleneck = []
        self.transport_layer = []


def get_limitation_list(flow, limitation):
    return {
        SS: flow.limitations.slow_sender,
        SR: flow.limitations.slow_receiver,
        SB: flow.limitations.sender_buffer,
        RB: flow.limitations.receiver_buffer,
        UBL: flow.limitations.unshared_bottleneck,
        SBL: flow.limitations.shared_bottleneck,
        CA: flow.limitations.transport_layer,
    }[limitation]


def add_ss_limitation(flow, period, temp_list):
    length = len(temp_list)
    count = -1

    if (length == 0):
        temp_list.append(period)
        return

    for entry in list(temp_list):
        count += 1
        if (entry.start_pkt_nr < period.start_pkt_nr):
            if (entry.end_pkt_nr <= period.end_pkt_nr):
                continue
            else:
                new_entry = entry
                new_entry.end = period.end
                new_entry.end_pkt_nr = period.end_pkt_nr
                new_entry.duration = entry.end - entry.start
                new_entry.pkt_count = entry.end_pkt_nr - entry.start_pkt_nr
                temp_list.remove(entry)
                temp_list.insert(count, new_entry)
                return
        elif (entry.start_pkt_nr == period.start_pkt_nr):
            if (entry.end_pkt_nr < period.end_pkt_nr):
                temp_list.remove(entry)
                temp_list.insert(count, period)
                return
            else:
                return
        elif (entry.start_pkt_nr > period.start_pkt_nr):
            if (entry.end_pkt_nr <= period.end_pkt_nr):
                temp_list.remove(entry)
                temp_list.insert(count, period)
                return
            else:
                if (entry.start_pkt_nr <= period.end_pkt_nr):
                    new_entry = entry
                    new_entry.start = period.start
                    new_entry.start_pkt_nr = period.start_pkt_nr
                    new_entry.duration = entry.end - entry.start
                    new_entry.pkt_count = entry.end_pkt_nr - entry.start_pkt_nr
                    temp_list.remove(entry)
                    temp_list.insert(count, new_entry)
                    return
                else:
                    temp_list.append(period)
                    return
    temp_list.append(period)


def add_limitation_to_list(flow, packet, limitation, is_exist, pkt_num):
    limitation_list = get_limitation_list(flow, limitation)
    if (len(limitation_list) == 0):
        if (is_exist == 1):
            # Record new period
            new_period = im_period(packet.timestamp, -1, -1, limitation, 1, packet.payload_len + packet.options_len)
            new_period.start_pkt_nr = pkt_num
            new_period.root_cause = limitation
            limitation_list.append(new_period)
    else:
        period = limitation_list[-1]
        if (is_exist == 1):
            if (period.start != -1) and (period.end != -1):
                if (period.end_pkt_nr == pkt_num - 1):
                    # Update metrics
                    period.end_pkt_nr = pkt_num
                    period.pkt_count += 1
                    if (packet.payload_len > 0):
                        period.byte_count += packet.payload_len + packet.options_len
                else:
                    # Record new period
                    new_period = im_period(packet.timestamp, -1, -1, limitation, 1,
                                           packet.payload_len + packet.options_len)
                    new_period.start_pkt_nr = pkt_num
                    new_period.root_cause = limitation
                    limitation_list.append(new_period)
            elif (period.start != -1) and (period.end == -1):
                # Update metrics
                period.end_pkt_nr = pkt_num
                period.pkt_count += 1
                if (packet.payload_len > 0):
                    period.byte_count += packet.payload_len + packet.options_len
        else:
            if (period.start != -1) and (period.end == -1):
                # Record end of period
                period.end = packet.timestamp
                period.duration = period.end - period.start
                period.end_pkt_nr = pkt_num
                # Update metrics
                period.pkt_count += 1
                if (packet.payload_len > 0):
                    period.byte_count += packet.payload_len + packet.options_len

