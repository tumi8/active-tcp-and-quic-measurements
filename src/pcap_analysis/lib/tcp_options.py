import pandas as pd

from lib.lib import get_capture_df_filtered_for_syns, get_capture_df_filtered_for_synacks

def get_options_from_handshake(self, filtered_capture_df: pd.DataFrame, debug: bool):

    df_syn = get_capture_df_filtered_for_syns(filtered_capture_df, debug)
    df_synack = get_capture_df_filtered_for_synacks(filtered_capture_df, debug)

    try: 
        # Get client options
        if df_syn["tcp.flags.ecn"].values[0] == 1:
            self.clientECN = True
       
        if df_syn["tcp.options.sack_perm"].values[0] == "04:02" or df_syn["tcp.options.sack_perm"].values[0] == 402:
            self.clientSACK = True
            self.clientSACK_value = df_syn["tcp.options.sack_perm"].values[0]
        else: 
            self.clientSACK_value = df_syn["tcp.options.sack_perm"].values[0]
        
        if df_syn["tcp.options.tfo.request"].values[0] == 1:
            self.clientTFO = True
            self.clientTFO_cookie = df_syn["tcp.options.tfo.cookie"].values[0]
        else: 
            self.clientTFO_cookie = df_syn["tcp.options.tfo.cookie"].values[0]
        self.clientWS = int(df_syn["tcp.options.wscale.shift"].values[0])
        
        # Get server options
        if df_synack["tcp.flags.ecn"].values[0] == 1:
            self.serverECN = True

        if df_synack["tcp.options.sack_perm"].values[0] == "04:02" or df_synack["tcp.options.sack_perm"].values[0] == 402:
            self.serverSACK = True
            self.serverSACK_value = df_synack["tcp.options.sack_perm"].values[0]
        else: 
            self.serverSACK_value = df_synack["tcp.options.sack_perm"].values[0]

        if  type(df_synack["tcp.options.tfo.cookie"].values[0]) == str:
            self.serverTFO = True
            self.serverTFO_cookie = df_synack["tcp.options.tfo.cookie"].values[0]
        else: 
            self.serverTFO_cookie = df_synack["tcp.options.tfo.cookie"].values[0]
        self.serverWS = int(df_synack["tcp.options.wscale.shift"].values[0])

    except Exception as e: 
        print("Extracting options failed")

def get_ecn_stats(self, df: pd.DataFrame, debug: bool):

    # tcp.flags.ecn	= ECN-Echo, tshark 1.0.0 to 3.6.14
    self.ecn_ece_count = len(df[df["tcp.flags.ecn"] != 0].index)
    self.ecn_cwr_count = len(df[df["tcp.flags.cwr"] != 0].index)

def get_sack_stats(self, df: pd.DataFrame, debug: bool):
    
    self.sack_count = len(df[df["tcp.options.sack"] != 0].index)
    self.sack_le_set_count = len(df[df["tcp.options.sack_le"] != 0].index)
    self.sack_re_set_count = len(df[df["tcp.options.sack_re"] != 0].index)

class TCPOptions: 

    def __init__(self, filtered_capture_df: pd.DataFrame, debug: bool):
        
        self.clientECN = False
        self.clientSACK = False
        self.clientSACK_value = False
        self.clientTFO = False
        self.clientTFO_cookie = False
        self.clientWS = 0
        self.serverECN = False
        self.serverSACK = False
        self.serverSACK_value = False
        self.serverTFO = False
        self.serverTFO_cookie = False
        self.serverWS = 0

        self.ecn_ece_count = 0
        self.ecn_cwr_count = 0

        self.sack_count = 0 # number of packets with tcp.options.sack flags
        self.sack_le_set_count = 0 # number of packet with a le / re block field set
        self.sack_re_set_count = 0

        # get options from handshake
        get_options_from_handshake(self, filtered_capture_df, debug)

        # get ECN stats 
        get_ecn_stats(self, filtered_capture_df, debug)

        # get SACK state
        get_sack_stats(self, filtered_capture_df, debug)

        print(self.ecn_ece_count)
        print(self.ecn_cwr_count)
        print(self.sack_count)
        print(self.sack_le_set_count)
        print(self.sack_re_set_count)

