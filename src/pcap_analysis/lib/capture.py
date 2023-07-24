import pandas as pd

from lib.lib import load_pcap_csv, process_pcap_to_csv, get_capture_df_filtered_for_synacks, filter_capture_df_for_download_tcp_stream, IPs

def get_number_of_synack_packets(df_synacks: pd.DataFrame):
    num_synack = len(df_synacks)
    return num_synack

def get_tcp_stream_num_of_download(num_synack, df_synacks):

    if num_synack == 0:
        return None
    elif num_synack == 1:
        max_index = 0
    elif num_synack > 1:
        max_count = max_index = 0
        df_synacks = df_synacks.reset_index()
        # check for the packet stream with the most seen packets and assume it is our download 
        for index, row in df_synacks.iterrows():
            tcp_stream = row["tcp.stream"]
            if len(df_synacks[df_synacks["tcp.stream"] == tcp_stream]) > max_count:
                max_count = len(df_synacks[df_synacks["tcp.stream"] == tcp_stream])
                max_index = index
    return int(df_synacks["tcp.stream"].values[max_index])

class Capture: 

    def __init__(self, tcp_path: str, debug: bool):
        
        self.debug = debug

        # process_pcap parses PCAP to CSV, returns path to CSV
        self.capture_csv_path = process_pcap_to_csv(tcp_path)
        # load_pcap parses CSV to DataFrame, returns DF
        self.capture_df = load_pcap_csv(self.capture_csv_path)
        # keep a SYN-only-filtered version of capture_df
        self.capture_df_synacks = get_capture_df_filtered_for_synacks(self.capture_df, self.debug)
        # get number of SYN packets in capture
        self.num_syn = get_number_of_synack_packets(self.capture_df_synacks)
        # get TCP stream id of our download
        self.tcp_stream_num_of_download = get_tcp_stream_num_of_download(self.num_syn, self.capture_df_synacks)
        # Filter capture dataframe for only DL traffic based on tcp stream number 
        self.capture_df = filter_capture_df_for_download_tcp_stream(self.capture_df, self.tcp_stream_num_of_download)
        self.capture_df_synacks = get_capture_df_filtered_for_synacks(self.capture_df, self.debug)
        # Get Ips from filtered capture_df
        self.ips = IPs(self.capture_df_synacks, "tcp", debug)

        