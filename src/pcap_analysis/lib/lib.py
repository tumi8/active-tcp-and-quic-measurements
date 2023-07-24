import subprocess
import math
import json
import pandas as pd
import numpy as np
from scipy.stats import variation

class IPs:

    """
    consists of ip version, server ip, and client ip, which are determined based on the order of SYN packets 
    """

    # for tcp, df is df_synacks
    # for udp, df is just capture_df for UDP != DNS
    def __init__(self, df: pd.DataFrame, protocol: str, debug: bool): 
        
        if protocol == "tcp":

            if not debug:   
                if df["ip.src"].values[0] != 0:
                    self.ip_version = 4
                    self.server_ip = df["ip.src"].values[0]
                    self.client_ip = df["ip.dst"].values[0]
                else:
                    self.ip_version = 6
                    self.server_ip = df["ipv6.src"].values[0]
                    self.client_ip = df["ipv6.dst"].values[0]

            if debug:   
                if df["ip.dst"].values[0] != 0:
                    self.ip_version = 4
                    self.server_ip = df["ip.dst"].values[0]
                    self.client_ip = df["ip.src"].values[0]
                else:
                    self.ip_version = 6
                    self.server_ip = df["ipv6.dst"].values[0]
                    self.client_ip = df["ipv6.src"].values[0]
        
        if protocol == "quic":

            first_index = df.index.values[0]

            if isinstance(df["ip.dst"].values[0], str):
                self.ip_version = 4
                self.client_ip = df["ip.src"].values[0]
                self.server_ip = df["ip.dst"].values[0]
            else:
                self.ip_version = 6
                self.client_ip = df["ipv6.src"].values[0]
                self.server_ip = df["ipv6.dst"].values[0]

            #print('client:', self.client_ip)
            #print('server:', self.server_ip)

"""
time series data processing
"""

# input is a list of tuples (timestamp, value), returns a dict with {'timetamps':[], 'values':[]}
def generic_ts_to_per_time_ts(timeseries: list, delta: float):

    timestamps = [ts[0] for ts in timeseries]

    first_packet_ts = timestamps[0]
    last_packet_ts = timestamps[-1]

    #print(first_packet_ts, last_packet_ts)

    per_delta_timestamps = []
    per_delta_values = []
    tmp_packet_ts = first_packet_ts
    while tmp_packet_ts <= last_packet_ts:
        per_delta_timestamps.append(tmp_packet_ts)
        values = [ts[1] for ts in timeseries if (ts[0] >= tmp_packet_ts) and (ts[0] <= tmp_packet_ts + delta)]
        #print(values)
        per_delta_values.append(float(np.mean(values)))
        tmp_packet_ts += delta

    return {'timestamps': per_delta_timestamps, 'values': per_delta_values}        

# variation from scipy stats returns coefficient of variation
def get_cov(data: list):
    return variation(data)

"""
KPIs getter
"""

def get_cst(df: pd.DataFrame, ips: IPs):
    if ips.ip_version == 4:
        syn = df[df["ip.src"] == ips.client_ip].iloc[0]["frame.time_epoch"]
        ack = df[df["ip.src"] == ips.client_ip].iloc[1]["frame.time_epoch"]
    else:
        syn = df[df["ipv6.src"] == ips.client_ip].iloc[0]["frame.time_epoch"]
        ack = df[df["ipv6.src"] == ips.client_ip].iloc[1]["frame.time_epoch"]
    cst = np.subtract(ack, syn)
    return cst * 1000


def get_dtt(df: pd.DataFrame, ips: IPs):
    #print(ips.server_ip, ips.client_ip, ips.ip_version)
    #print(df["tcp.len"])
    #print(df["ip.src"])
    #print(df[(df["tcp.len"] != 0) & (df["ip.src"] == ips.server_ip)])
    if ips.ip_version == 4:
        dtt = (
            df[(df["tcp.len"] != 0) & (df["ip.src"] == ips.server_ip)].iloc[-1][
                "frame.time_epoch"
            ]
            - df[(df["tcp.len"] != 0) & (df["ip.src"] == ips.server_ip)].iloc[0][
                "frame.time_epoch"
            ]
        )
    else:
        dtt = (
            df[(df["tcp.len"] != 0) & (df["ipv6.src"] == ips.server_ip)].iloc[-1][
                "frame.time_epoch"
            ]
            - df[(df["tcp.len"] != 0) & (df["ipv6.src"] == ips.server_ip)].iloc[0][
                "frame.time_epoch"
            ]
        )
    return dtt * 1000

def get_packet_loss(df: pd.DataFrame, ips: IPs):
    r = 0
    if ips.ip_version == 4:
        n = len(df[df["ip.src"] == ips.server_ip])
        for i, segment in df[df["ip.src"] == ips.server_ip].iterrows():
            seg_r = np.minimum(
                1,
                np.nan_to_num(segment["tcp.analysis.retransmission"])
                + np.nan_to_num(segment["tcp.analysis.spurious_retransmission"])
                + np.nan_to_num(segment["tcp.analysis.fast_retransmission"]),
            )
            r += seg_r
    else:
        n = len(df[df["ipv6.src"] == ips.server_ip])
        for i, segment in df[df["ipv6.src"] == ips.server_ip].iterrows():
            seg_r = np.minimum(
                1,
                np.nan_to_num(segment["tcp.analysis.retransmission"])
                + np.nan_to_num(segment["tcp.analysis.spurious_retransmission"])
                + np.nan_to_num(segment["tcp.analysis.fast_retransmission"]),
            )
            r += seg_r
    if r == 0:
        return 0
    else:
        return np.divide(r, n) * 100

"""
NormDiff clalc and DF filtering based on MA Brzoza notebooks
Source: S. Sundaresan, M. Allman, A. Dhamdhere, and K. Claffy, “Tcp congestion signatures,”
"""

def get_rtt_normdiff(df: pd.DataFrame, rtts: list) -> np.float32:

    end_of_slowstart_index = get_end_of_slowstart(df)
    #print(end_of_slowstart_index)
    if end_of_slowstart_index == 0: 
        return None

    slowstart_rtts = rtts[:end_of_slowstart_index]
    filtered_rtts = [rtt for rtt in slowstart_rtts if rtt > 0]

    min_rtt = np.min(filtered_rtts)
    max_rtt = np.max(filtered_rtts)

    # return (min_rtt - max_rtt) / (min_rtt + max_rtt)
    return np.abs(min_rtt - max_rtt) / max_rtt

def get_end_of_slowstart(df: pd.DataFrame):

    try:
        return df.loc[(df['tcp.analysis.retransmission'] == 1) | (
               df['tcp.analysis.spurious_retransmission'] == 1) | (
               df['tcp.analysis.fast_retransmission'] == 1)].index[0] - 1
    except IndexError:
        return len(df.index)

def get_goodput_from_df(df: pd.DataFrame, ips: IPs): 

    recv_bytes_without_retransmissions = 0
    duration = 0 
    
    # remove retransmitted data
    df_org = df
    df = df[(df['tcp.analysis.retransmission'] == 0) & (
            df['tcp.analysis.spurious_retransmission'] == 0) & (
            df['tcp.analysis.fast_retransmission'] == 0)]

    # get received bytes after filtering retransmissions
    if ips.ip_version == 4:
        recv_bytes_without_retransmissions = int(np.sum(df[df["ip.src"] == ips.server_ip]["ip.len"]))
    elif ips.ip_version == 6:
        recv_bytes_without_retransmissions = int(np.sum(df[df["ipv6.src"] == ips.server_ip]["ipv6.plen"]))

    t_min = df_org.iloc[0]["frame.time_epoch"]
    t_max = df_org.iloc[-1]["frame.time_epoch"]

    duration = float(np.subtract(t_max, t_min))

    return recv_bytes_without_retransmissions*8/duration

"""

counting retransmissions

"""

def get_retransmission_count_from_df(df: pd.DataFrame): 
    return len(df[df['tcp.analysis.retransmission'] == 1].index)


def get_fast_retransmission_count_from_df(df: pd.DataFrame): 
    return len(df[df['tcp.analysis.fast_retransmission'] == 1].index)

def get_spurious_retransmission_count_from_df(df: pd.DataFrame): 
    return len(df[df['tcp.analysis.spurious_retransmission'] == 1].index)

"""
File IO
"""
def get_json_data(path):
    with open(path) as f:
        data = json.load(f)
    return data


"""
PCAP
"""

def process_quic_pcap_to_df(path: str):
        
    capture_csv = "{}/capture.csv".format(path)
    capture_pcap = "{}/capture.pcap".format(path)

    print(capture_pcap)

    outfile = open(capture_csv, "w")

    with open("./tshark_quic_cmd.txt", "r") as file:
        tshark_cmd = file.readline().split()
        tshark_cmd[2] = capture_pcap

    proc = subprocess.Popen(
        tshark_cmd,
        stdout=outfile,
    )
    proc.wait()
    outfile.close()

    capture_df = pd.read_csv(capture_csv, delimiter=";").dropna(axis=0, subset=["udp.stream"])

    filtered_capture_df = capture_df[capture_df["_ws.col.Protocol"] != "DNS"]

    return filtered_capture_df

def process_pcap_to_csv(path: str):
    capture_csv = "{}/capture.csv".format(path)
    capture_pcap = "{}/capture.pcap".format(path)

    #print(capture_pcap)

    outfile = open(capture_csv, "w")

    with open("./tshark_cmd.txt", "r") as file:
        tshark_cmd = file.readline().split()
        tshark_cmd[2] = capture_pcap

    proc = subprocess.Popen(
        tshark_cmd,
        stdout=outfile,
    )
    proc.wait()
    outfile.close()

    return capture_csv

def load_pcap_csv(path: str):
    capture_csv = path
    _d = pd.read_csv(capture_csv, delimiter=";").dropna(axis=0, subset=["tcp.stream"])
    _d = _d.loc[
        ~_d["_ws.col.Protocol"].isin(
            [
                "ICMP",
                "ICMPv6",
                "ARP",
                "DNS",
                "SSHv2",
                "SSH",
                "NTP",
                "0x8918",
                "UDP",
                "LLDP",
                "ECHO",
                "RTCP",
                "IAPP",
                "WTP+WSP",
                "TETRA",
                "HiQnet",
                "LLMNR",
                "ENRP",
                "GTPv2",
                "CLDAP",
                "MEMCACHE",
                "MobileIP",
                "Nano",
                "Chargen",
                "IPX",
                "TIME",
                "ADP",
            ]
        )
    ]

    _d = _d.fillna(0).astype(
        {
            "tcp.stream": np.int32,
            "tcp.srcport": np.int32,
            "tcp.dstport": np.int32,
            "tcp.flags.syn": np.int32,
            "tcp.flags.ack": np.int32,
            "tcp.flags.reset": np.int32,
            "tcp.flags.fin": np.int32,
            "ip.len": np.int32,
            "tcp.seq": np.int32,
            "tcp.len": np.int32,
            "tcp.flags": str,
            "tcp.analysis.acks_frame": np.int32,
            "tcp.analysis.initial_rtt": np.float32,
            "tcp.analysis.ack_rtt": np.float32,
            "tcp.options.timestamp.tsecr": np.int64,
            "tcp.options.timestamp.tsval": np.int64,
            "tcp.analysis.retransmission": np.int32,
            "tcp.analysis.spurious_retransmission": np.int32,
            "tcp.analysis.fast_retransmission": np.int32,
            "tcp.analysis.rto": np.int32,
            "tcp.analysis.rto_frame": np.int32,
        }
    )

    return _d

def get_capture_df_filtered_for_synacks(capture_df: pd.DataFrame, debug: bool):
    
    if not debug: 
        df_synacks = capture_df[
            (capture_df["tcp.flags.syn"] == 1)
            & (capture_df["tcp.flags.ack"] == 1)
            # We actually only want 443
            & ((capture_df["tcp.srcport"] == 443))
            #& ((capture_df["tcp.srcport"] == 443) | (capture_df["tcp.srcport"] == 80))
        ]
    if debug: 
        df_synacks = capture_df[
            (capture_df["tcp.flags.syn"] == 1)
            & (capture_df["tcp.flags.ack"] == 1)]
            # We do not know the debug traffic port

    return df_synacks 

def get_capture_df_filtered_for_syns(capture_df: pd.DataFrame, debug: bool):
    
    #print(capture_df['tcp.flags.syn'])

    if not debug: 
        df_syns = capture_df[
            (capture_df["tcp.flags.syn"] == 1)
            & (capture_df["tcp.flags.ack"] == 0)
            # We actually only want 443
            & (capture_df["tcp.dstport"] == 443)
            #& ((capture_df["tcp.srcport"] == 443) | (capture_df["tcp.srcport"] == 80))
        ]
    if debug: 
        print("looool")
        df_syns = capture_df[
            (capture_df["tcp.flags.syn"] == 1)
            & (capture_df["tcp.flags.ack"] == 0)]
            # We do not know the debug traffic port

    return df_syns 
 

def filter_capture_df_for_download_tcp_stream(df: pd.DataFrame, tcp_stream) -> pd.DataFrame:
    return df[(df["tcp.stream"] == tcp_stream)]
