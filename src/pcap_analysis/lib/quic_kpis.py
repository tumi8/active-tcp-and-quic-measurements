import os 
import json
import pandas as pd
import numpy as np
from lib.lib import IPs, process_quic_pcap_to_df


def check_aioquic_success(capture_path: str): 

    success =  False 

    try: 
        if os.path.exists("{}/header.info".format(capture_path)):
            success = True
    except Exception as e:
        print(e)
        
    return success


def check_quiche_success(capture_path: str): 

    success =  False 

    try: 
        with open(capture_path+"/dump.json", "r") as dump: 
            data = json.load(dump)
        
        if data['entries'][0]['response']['headers'][0]['value'] == '200': 
            success = True
    except Exception as e:
        print(e)
    
    return success


class QUICFlowBytes: 

    def __init__(self, capture_df: pd.DataFrame, ips: IPs) -> None:

        self.total_bytes = 0
        self.tx_bytes = 0
        self.rx_bytes = 0

        if not(capture_df is None):
            if ips.ip_version == 4:
                self.tx_bytes = int(np.sum(capture_df[capture_df["ip.src"] == ips.client_ip]["ip.len"]))
                self.rx_bytes = int(np.sum(capture_df[capture_df["ip.src"] == ips.server_ip]["ip.len"]))
            elif ips.ip_version == 6:
                self.tx_bytes = int(np.sum(capture_df[capture_df["ipv6.src"] == ips.client_ip]["ipv6.plen"]))
                self.rx_bytes = int(np.sum(capture_df[capture_df["ipv6.src"] == ips.server_ip]["ipv6.plen"]))
        
        self.total_bytes = self.tx_bytes + self.rx_bytes

class QUICFlowDuration: 

    def __init__(self, capture_df: pd.DataFrame) -> None:
        
        self.duration = 0 

        if not(capture_df is None):
            t_min = capture_df.iloc[0]["frame.time_epoch"]
            t_max = capture_df.iloc[-1]["frame.time_epoch"]
            self.duration = float(np.subtract(t_max, t_min))

class QUICFlowPackets: 
        
    def __init__(self, capture_df: pd.DataFrame, ips: IPs) -> None:
        
        self.total_packets = 0
        self.tx_packets = 0
        self.rx_packets = 0

        if not(capture_df is None):
            if ips.ip_version == 4: 
                self.tx_packets = len(capture_df[capture_df["ip.src"] == ips.client_ip])
                self.rx_packets = len(capture_df[capture_df["ip.src"] == ips.server_ip])
            elif ips.ip_version == 6:
                self.tx_packets = len(capture_df[capture_df["ipv6.src"] == ips.client_ip])
                self.rx_packets = len(capture_df[capture_df["ipv6.src"] == ips.server_ip])

        self.total_packets = self.tx_packets + self.rx_packets


class QUICRESULT:

    def __init__(self, quic_path: str, quic_run_id: str, quic_client: str) -> None:
        
        self.quic_client = quic_client
        self.capture_path = ""
        self.flowbytes = QUICFlowBytes(None, None)
        self.flowduration = QUICFlowDuration(None)
        self.flowpackets = QUICFlowPackets(None, None)
        self.flowrate = 0

        if self.quic_client == "aioquic":
            self.capture_path = quic_path + "/" + quic_run_id + "_" + self.quic_client  
            self.quic_dl_successful = check_aioquic_success(self.capture_path)

            if self.quic_dl_successful: 
                # capture df already filtered for UDP != DNS
                capture_df = process_quic_pcap_to_df(self.capture_path)
                ips = IPs(capture_df, "quic", False)

                self.flowbytes = QUICFlowBytes(capture_df, ips)
                self.flowduration = QUICFlowDuration(capture_df)
                self.flowpackets = QUICFlowPackets(capture_df, ips)
                self.flowrate = self.flowbytes.total_bytes*8/self.flowduration.duration

        if self.quic_client == "quiche": 
            self.capture_path = quic_path + "/" + quic_run_id + "_" + self.quic_client  
            self.quic_dl_successful = check_quiche_success(self.capture_path)

            if self.quic_dl_successful: 
                # capture df already filtered for UDP != DNS
                capture_df = process_quic_pcap_to_df(self.capture_path)
                ips = IPs(capture_df, "quic", False)

                self.flowbytes = QUICFlowBytes(capture_df, ips)
                self.flowduration = QUICFlowDuration(capture_df)
                self.flowpackets = QUICFlowPackets(capture_df, ips)
                self.flowrate = self.flowbytes.total_bytes*8/self.flowduration.duration

        
class QUICRESULTs: 

    def __init__(self, quic_path: str):
                
        paths = []

        # we do not know the run id (i.e. timestamp) of the quic downloads
        for root, dirs, files in os.walk(quic_path, topdown=True):
            for name in dirs:
                paths.append(os.path.join(root, name))
            break

        self.quic_run_id = paths[0].split('/')[-1].split('_')[0]
        self.aioquic_result = QUICRESULT(quic_path, self.quic_run_id, "aioquic") 
        self.quiche_result = QUICRESULT(quic_path, self.quic_run_id, "quiche") 


