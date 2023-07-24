import pandas as pd
import numpy as np

from lib.lib import generic_ts_to_per_time_ts, get_packet_loss, get_cst, get_dtt, get_cov, get_rtt_normdiff, get_retransmission_count_from_df, get_goodput_from_df, get_fast_retransmission_count_from_df, get_spurious_retransmission_count_from_df
from lib.capture import IPs

from time_series_metrics import extract_metrics
# import Timeseries class

class TCPThroughputStats: 

    def __init__(self, flows: list, interval) -> None:

        self.throughput_timeseries = generic_ts_to_per_time_ts(flows[0].tseries.throughput, interval)
        self.tp_max = np.max(self.throughput_timeseries['values'])
        self.tp_mean = float(flows[0].rx_bytes*8/flows[0].flow_duration)
        self.tp_std = np.std(self.throughput_timeseries['values'])       

class TCPRTTStats: 

    def __init__(self, flows: list, capture_df: pd.DataFrame, ips:IPs) -> None:

        self.rtt_timeseries = flows[0].tseries.rtt
        rtts = [float(ts[1]) for ts in self.rtt_timeseries]

        rtts = [rtt for rtt in rtts if rtt > 0]
        self.rtt_sample_count = len(rtts)

        self.rtt_min = float(np.min(rtts))
        self.rtt_max = float(np.max(rtts))
        self.rtt_mean = float(np.mean(rtts))
        self.rtt_std = float(np.std(rtts))

        # metrics for congestion classification extracted from rtt time series
        self.rtt_normdiff = get_rtt_normdiff(capture_df, rtts)
        self.rtt_cov = get_cov(rtts)
        
class TCPRetransmissionStats: 

    def __init__(self, capture_df: pd.DataFrame, ips: IPs) -> None:
        self.retransmission_count = get_retransmission_count_from_df(capture_df)
        self.fast_retransmission_count = get_fast_retransmission_count_from_df(capture_df)
        self.spurious_retransmission_count = get_spurious_retransmission_count_from_df(capture_df)
        self.total_retransmissions = self.retransmission_count + self.fast_retransmission_count + self.spurious_retransmission_count

        self.total_retransmission_rate = get_packet_loss(capture_df, ips)

class TCPKPIs: 

    def __init__(self, basepath: str, domain: str, run_id: str, capture_df: pd.DataFrame, ips: IPs, debug: bool) -> None:

        if not debug: 
            time_series_extraction_conf = "./time_series_metrics/config/sample_config.json"
            capture_pcap = "{}/tcp_downloads/{}/{}/capture.pcap".format(basepath, domain, run_id)
            interval = 0.10000
            flows = extract_metrics.main(time_series_extraction_conf, capture_pcap)

        if debug: 
            time_series_extraction_conf = "./time_series_metrics/config/sample_config.json"
            capture_pcap = "{}/capture.pcap".format(basepath)
            interval = 0.10000
            flows = extract_metrics.main(time_series_extraction_conf, capture_pcap)            

        #print(flows[0].tseries.retransmission)

        # get statistics from tiem series data
        self.tp_stats = TCPThroughputStats(flows, interval)

        #get goodput
        self.gp_mean = get_goodput_from_df(capture_df, ips)

        self.rtt_stats = TCPRTTStats(flows, capture_df, ips)
        
        self.retransmission_stats = TCPRetransmissionStats(capture_df, ips)
        
        # extract from Capture.capture_df
        self.dtt = get_dtt(capture_df, ips)
        self.cst = get_cst(capture_df, ips)


   