import pandas as pd
import numpy as np

from lib.capture import IPs

class FlowBytes: 

    def __init__(self, capture_df: pd.DataFrame, ips: IPs) -> None:

        self.total_bytes = 0
        self.tx_bytes = 0
        self.rx_bytes = 0

        if ips.ip_version == 4:
            self.tx_bytes = int(np.sum(capture_df[capture_df["ip.src"] == ips.client_ip]["ip.len"]))
            self.rx_bytes = int(np.sum(capture_df[capture_df["ip.src"] == ips.server_ip]["ip.len"]))
        elif ips.ip_version == 6:
            self.tx_bytes = int(np.sum(capture_df[capture_df["ipv6.src"] == ips.client_ip]["ipv6.plen"]))
            self.rx_bytes = int(np.sum(capture_df[capture_df["ipv6.src"] == ips.server_ip]["ipv6.plen"]))
        
        self.total_bytes = self.tx_bytes + self.rx_bytes

class FlowDuration: 

    def __init__(self, capture_df: pd.DataFrame) -> None:
        
        self.duration = 0 

        t_min = capture_df.iloc[0]["frame.time_epoch"]
        t_max = capture_df.iloc[-1]["frame.time_epoch"]

        self.duration = float(np.subtract(t_max, t_min))

class FlowPackets: 

    def __init__(self, capture_df: pd.DataFrame, ips: IPs) -> None:

        self.total_packets = 0
        self.tx_packets = 0
        self.rx_packets = 0

        if ips.ip_version == 4: 
            self.tx_packets = len(capture_df[capture_df["ip.src"] == ips.client_ip])
            self.rx_packets = len(capture_df[capture_df["ip.src"] == ips.server_ip])
        elif ips.ip_version == 6:
            self.tx_packets = len(capture_df[capture_df["ipv6.src"] == ips.client_ip])
            self.rx_packets = len(capture_df[capture_df["ipv6.src"] == ips.server_ip])

        self.total_packets = self.tx_packets + self.rx_packets
        

class TCPFlowCharacteristics:

    def __init__(self, capture_df: pd.DataFrame, ips: IPs) -> None:

        self.flowbytes = FlowBytes(capture_df, ips)
        self.flowduration = FlowDuration(capture_df)
        self.flowpackets = FlowPackets(capture_df, ips)
        self.flowrate = self.flowbytes.rx_bytes*8/self.flowduration.duration
