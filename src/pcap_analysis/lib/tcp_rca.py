import pandas as pd
import numpy as np

from lib.capture import IPs
from lib.lib import generic_ts_to_per_time_ts

from time_series_metrics import extract_metrics
from time_series_metrics import perform_rca


# import Timeseries class


def count_periods(rca_results: list, rc_id: int): 
    
    count = 0

    for i in range(len(rca_results)): 
        if rca_results[i].root_cause == rc_id:
            count = count + 1

    return count


def get_bytes_per_rc(rca_results: list, rc_id: int):
    
    bytes = 0

    for i in range(len(rca_results)): 
        if rca_results[i].root_cause == rc_id:
            bytes = bytes + rca_results[i].byte_count

    return bytes


def get_packets_per_rc(rca_results: list, rc_id: int):
    
    packets = 0

    for i in range(len(rca_results)): 
        if rca_results[i].root_cause == rc_id:
            packets = packets + rca_results[i].pkt_count

    return packets

def get_duration_per_rc(rca_results: list, rc_id: int): 
        
    duration = 0

    for i in range(len(rca_results)): 
        if rca_results[i].root_cause == rc_id:
            duration = duration + rca_results[i].duration

    return float(duration)
 

class TCPRCA: 

    def __init__(self, basepath: str, domain: str, run_id: str, capture_df: pd.DataFrame, ips: IPs, debug: bool) -> None:

        if not debug: 
            time_series_extraction_conf = "./time_series_metrics/config/sample_config.json"
            capture_pcap = "{}/tcp_downloads/{}/{}/capture.pcap".format(basepath, domain, run_id)
            interval = 0.10000
            flows = extract_metrics.main(time_series_extraction_conf, capture_pcap)
            perform_rca.main(time_series_extraction_conf, flows, capture_pcap)
        
        if debug: 
            time_series_extraction_conf = "./time_series_metrics/config/sample_config.json"
            capture_pcap = "{}/capture.pcap".format(basepath)
            interval = 0.10000
            flows = extract_metrics.main(time_series_extraction_conf, capture_pcap)            
            perform_rca.main(time_series_extraction_conf, flows, capture_pcap)

        #print(type(flows[0]))

        rca_results = flows[0].siekkinen_data

        #print(rca_results) 
        #for i in range(len(rca_results)): 
        #    print(rca_results[i])
        #    print('=====================')

        self.number_alp     = count_periods(rca_results, 7)
        self.number_ub      = count_periods(rca_results, 5)
        self.number_sb      = count_periods(rca_results, 6)
        self.number_rw      = count_periods(rca_results, 3)
        self.number_tl      = count_periods(rca_results, 4)
        self.number_other   = count_periods(rca_results, 8)
        self.bytes_alp      = get_bytes_per_rc(rca_results, 7)
        self.bytes_ub       = get_bytes_per_rc(rca_results, 5)
        self.bytes_sb       = get_bytes_per_rc(rca_results, 6)
        self.bytes_rw       = get_bytes_per_rc(rca_results, 3)
        self.bytes_tl       = get_bytes_per_rc(rca_results, 4)
        self.bytes_other    = get_bytes_per_rc(rca_results, 8)
        self.duration_alp   = get_duration_per_rc(rca_results, 7)
        self.duration_ub    = get_duration_per_rc(rca_results, 5)
        self.duration_sb    = get_duration_per_rc(rca_results, 6)
        self.duration_rw    = get_duration_per_rc(rca_results, 3)
        self.duration_tl    = get_duration_per_rc(rca_results, 4)
        self.duration_other = get_duration_per_rc(rca_results, 8)
        self.packets_alp    = get_packets_per_rc(rca_results, 7)
        self.packets_ub     = get_packets_per_rc(rca_results, 5)
        self.packets_sb     = get_packets_per_rc(rca_results, 6)
        self.packets_rw     = get_packets_per_rc(rca_results, 3)
        self.packets_tl     = get_packets_per_rc(rca_results, 4)
        self.packets_other  = get_packets_per_rc(rca_results, 8)    

        self.max_outstanding = max([float(ts[1]) for ts in flows[0].tseries.outstanding_bytes])
        self.min_awnd = min([float(ts[1]) for ts in flows[0].tseries.receiver_advertised_window])
        self.max_awnd = max([float(ts[1]) for ts in flows[0].tseries.receiver_advertised_window])

        #print('number_alp', self.number_alp   )
        #print('number_ub', self.number_ub    )
        #print('number_sb', self.number_sb    )
        #print('number_rw', self.number_rw    )
        #print('number_tl', self.number_tl    )
        #print('number_other', self.number_other )
        #print('bytes_alp', self.bytes_alp    )
        #print('bytes_ub', self.bytes_ub     )
        #print('bytes_sb', self.bytes_sb     )
        #print('bytes_rw', self.bytes_rw     )
        #print('bytes_tl', self.bytes_tl     )
        #print('bytes_other', self.bytes_other  )
        #print('duration_alp', self.duration_alp )
        #print('duration_ub', self.duration_ub  )
        #print('duration_sb', self.duration_sb  )
        #print('duration_rw', self.duration_rw  )
        #print('duration_tl', self.duration_tl  )
        #print('duration_othe', self.duration_other)
        #print('packets_alp', self.packets_alp  )
        #print('packets_ub', self.packets_ub   )
        #print('packets_sb', self.packets_sb   )
        #print('packets_rw', self.packets_rw   )
        #print('packets_tl', self.packets_tl   )
        #print('packets_other', self.packets_other)



