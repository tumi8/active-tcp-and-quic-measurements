import pandas as pd
import numpy as np
import os
import subprocess
import glob
import re


def process_pcap(path: str):
    capture_csv = "{}/capture.csv".format(path)
    capture_pcap = "{}/capture.pcap".format(path)

    outfile = open(capture_csv, "w")

    proc = subprocess.Popen(
        [
            "tshark",
            "-r",
            capture_pcap,
            "-T",
            "fields",
            "-E",
            "separator=;",
            "-E",
            "header=y",
            "-e",
            "_ws.col.No.",
            "-e",
            "frame.time_epoch",
            "-e",
            "_ws.col.Protocol",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "ipv6.src",
            "-e",
            "ipv6.dst",
            "-e",
            "ip.len",
            "-e",
            "tcp.stream",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "tcp.seq",
            "-e",
            "tcp.len",
            "-e",
            "tcp.flags.syn",
            "-e",
            "tcp.flags.cwr",
            "-e",
            "tcp.flags.ecn",
            "-e",
            "tcp.flags.ack",
            "-e",
            "tcp.flags.reset",
            "-e",
            "tcp.flags.fin",
            "-e",
            "tcp.flags",
            "-e",
            "tcp.analysis.acks_frame",
            "-e",
            "tcp.analysis.initial_rtt",
            "-e",
            "tcp.analysis.ack_rtt",
            "-e",
            "tcp.options.wscale.shift",
            "-e",
            "tcp.options.tfo.cookie",
            "-e",
            "tcp.options.tfo.request",
            "-e",
            "tcp.options.sack.count",
            "-e",
            "tcp.options.sack_perm",
            "-e",
            "tcp.options.timestamp.tsecr",
            "-e",
            "tcp.options.timestamp.tsval",
            "-e",
            "tcp.analysis.retransmission",
            "-e",
            "tcp.analysis.spurious_retransmission",
            "-e",
            "tcp.analysis.fast_retransmission",
            "-e",
            "tcp.analysis.rto",
            "-e",
            "tcp.analysis.rto_frame",
        ],
        stdout=outfile,
    )
    proc.wait()
    outfile.close()


def load_pcap(path: str):
    capture_csv = "{}/capture.csv".format(path)
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
            "tcp.options.timestamp.tsecr": np.longlong,
            "tcp.options.timestamp.tsval": np.longlong,
            "tcp.analysis.retransmission": np.int32,
            "tcp.analysis.spurious_retransmission": np.int32,
            "tcp.analysis.fast_retransmission": np.int32,
            "tcp.analysis.rto": np.int32,
            "tcp.analysis.rto_frame": np.int32,
        }
    )

    return _d


def filter_ips(df: pd.DataFrame, server_ip: str, client_ip: str) -> pd.DataFrame:
    return df[
        ((df["ip.src"] == server_ip) & (df["ip.dst"] == client_ip))
        | ((df["ip.dst"] == server_ip) & (df["ip.src"] == client_ip))
    ]


def get_throughput(df: pd.DataFrame, server_ip: str, client_ip: str):
    # df = filter_ips(df,server_ip,client_ip)
    len_sum = np.sum(df[df["ip.src"] == server_ip]["ip.len"])
    t_min = df.iloc[0]["frame.time_epoch"]
    t_max = df.iloc[-1]["frame.time_epoch"]
    throughput = np.divide(len_sum, np.subtract(t_max, t_min))
    return throughput


def get_cst(df: pd.DataFrame, server_ip: str, client_ip: str):
    # df = filter_ips(df, server_ip, client_ip)
    syn = df[df["ip.src"] == client_ip].iloc[0]["frame.time_epoch"]
    ack = df[df["ip.src"] == client_ip].iloc[1]["frame.time_epoch"]
    cst = np.subtract(ack, syn)
    return cst * 1000


def get_rtt_list_ts(df: pd.DataFrame, server_ip: str, client_ip: str):

    rtts = []

    for client_segment in df[
        (df["ip.src"] == client_ip)
        & (df["tcp.flags.ack"] == 1)
        & (df["tcp.flags.syn"] == 0)
    ].iterrows():
        try:
            client_segment = client_segment[1]

            server_segment = df[
                (df["ip.src"] == server_ip)
                & (df["_ws.col.No."] < client_segment["_ws.col.No."])
            ].iloc[-1]

            rtt = np.longlong(client_segment["tcp.options.timestamp.tsval"]) - np.longlong(
                server_segment["tcp.options.timestamp.tsecr"]
            )
            if rtt > 0:
                rtts.append(rtt)
        except IndexError:
            pass

    return rtts


def get_mean_ack_rtt_ts(df: pd.DataFrame, server_ip: str, client_ip: str):
    rtts = get_rtt_list_ts(df, server_ip, client_ip)
    return np.mean(rtts)


def get_packet_loss(df: pd.DataFrame, server_ip: str, client_ip: str):
    r = 0
    n = len(df[df["ip.src"] == server_ip])
    for i, segment in df[df["ip.src"] == server_ip].iterrows():
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


def get_dtt(df: pd.DataFrame, server_ip: str, client_ip: str):
    dtt = (
        df[(df["tcp.len"] != 0) & (df["ip.src"] == server_ip)].iloc[-1][
            "frame.time_epoch"
        ]
        - df[(df["tcp.len"] != 0) & (df["ip.src"] == server_ip)].iloc[0][
            "frame.time_epoch"
        ]
    )

    return dtt


def get_server_tcp_option_info(df: pd.DataFrame):
    df_syns = df[
        (df["tcp.flags.syn"] == 1)
        & (df["tcp.flags.ack"] == 1)
        & ((df["tcp.srcport"] == 443) | (df["tcp.srcport"] == 80))
    ]
    num_syn = len(df_syns)

    if num_syn == 0:
        return {
        "ECN": None,
        "SACK": None,
        "TFO": None,
        "WS": None,
        "IP": None,
        "PORT": None,
        "Num_SYN": 0,
        "TCP_Stream": None,
        "Client_IP": None,
        "Client_port": None
    }
    elif num_syn > 1:
        max_count = max_index = 0
        df_syns = df_syns.reset_index()
        for index, row in df_syns.iterrows():
            tcp_stream = row["tcp.stream"]
            if len(df[df["tcp.stream"] == tcp_stream]) > max_count:
                max_count = len(df[df["tcp.stream"] == tcp_stream])
                max_index = index
    elif num_syn == 1:
        max_index = 0

    ecn_value = df_syns["tcp.flags.ecn"].values[max_index]
    ws_value = df_syns["tcp.options.wscale.shift"].values[max_index]
    sack_value = df_syns["tcp.options.sack_perm"].values[max_index]
    tfo_value = df_syns["tcp.options.tfo.cookie"].values[max_index]
    ip_addr = (
        df_syns["ip.src"].values[max_index]
        if df_syns["ip.src"].values[max_index] != 0
        else df_syns["ipv6.src"].values[max_index]
    )
    tcp_stream = df_syns["tcp.stream"].values[max_index]
    port = df_syns["tcp.srcport"].values[max_index]
    client_ip = (
        df_syns["ip.dst"].values[max_index]
        if df_syns["ip.dst"].values[max_index] != 0
        else df_syns["ipv6.dst"].values[max_index]
    )
    client_port = df_syns["tcp.dstport"].values[max_index]
    ecn = sack = tfo = False
    if ecn_value == 1:
        ecn = True
    if sack_value == 402:
        sack = True
    if type(tfo_value) == str:
        tfo = True
    ws = int(ws_value)

    tcp_options = {
        "ECN": ecn,
        "SACK": sack,
        "TFO": tfo,
        "WS": ws,
        "IP": ip_addr,
        "PORT": int(port),
        "Num_SYN": num_syn,
        "TCP_Stream": int(tcp_stream),
        "Client_IP": client_ip,
        "Client_port": int(client_port),
    }
    return tcp_options


def main(path: str, server_ip: str, client_ip: str):

    process_pcap(path)
    df = load_pcap(path)
    if server_ip is None:
        df_syn = df[(df["tcp.flags.syn"] == 1) & (df["tcp.flags.ack"] == 1)]
        server_ip = df_syn["ip.src"].values[0]
        client_ip = df_syn["ip.dst"].values[0]
    df = filter_ips(df, server_ip, client_ip)
    throughput = get_throughput(df, server_ip, client_ip)
    cst = get_cst(df, server_ip, client_ip)
    mean_ack_rtt = get_mean_ack_rtt_ts(df, server_ip, client_ip)
    retransmission_rate = get_packet_loss(df, server_ip, client_ip)
    dtt = get_dtt(df, server_ip, client_ip)
    kpis = {
        "throughput": throughput,
        "cst": cst,
        "mean_ack_rtt": mean_ack_rtt,
        "retransmission_rate": retransmission_rate,
        "dtt": dtt,
    }
    kpis["tcp_options"] = get_server_tcp_option_info(df)
    return kpis


def get_server_tcp_option(path: str):
    if not os.path.exists("{}/capture.pcap".format(path)):
        return {"Num_SYN": 0}
    process_pcap(path)
    df = load_pcap(path)
    return get_server_tcp_option_info(df)

