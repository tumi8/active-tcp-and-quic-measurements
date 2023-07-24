import json

from lib.capture import Capture
from lib.target import TargetInfo
from lib.tcp_options import TCPOptions
from lib.tcp_flow_info import TCPFlowCharacteristics
from lib.tcp_kpis import TCPKPIs
from lib.tcp_rca import TCPRCA
from lib.quic_kpis import QUICRESULTs

class Result: 

    def __init__(self, basepath: str, domain: str, run_id: str, debug: bool):

        self.debug = debug

        if not debug:
            try:    
                self.run_id = run_id
                self.domain = domain 
                self.basepath = basepath

                self.tcp_path = "{}/{}/{}".format(basepath + "/tcp_downloads", domain, run_id)
                self.quic_path = "{}/{}".format(basepath + "/quic_downloads", domain)
   

                #try: 
                self.capture = Capture(self.tcp_path, self.debug) 
                if self.capture.num_syn <= 0: 
                    print("Result.init: No SYNs in capture.")
                    self.target = None
                    self.tcp_options = None
                    self.flow_chars = None
                    self.tcp_kpis = None
                    self.quic_kpis = None
                    self.tcp_rca = None
                self.target = TargetInfo(self.tcp_path, self.debug) 
                self.tcpoptions = TCPOptions(self.capture.capture_df, self.debug)
                self.tcpflowchars = TCPFlowCharacteristics(self.capture.capture_df, self.capture.ips)
                self.tcpkpis = TCPKPIs(basepath, domain, run_id, self.capture.capture_df, self.capture.ips, self.debug)
                self.quicresults = None
                self.tcprca = TCPRCA(basepath, domain, run_id, self.capture.capture_df, self.capture.ips, self.debug)

            except Exception as e: 
                print("EXCEPTION - reading pcap and creating capture instance failed")
                print(e)
                self.capture = None 
                self.target = None
                self.tcpoptions = None
                self.tcpflowchars = None
                self.tcpkpis = None
                self.quicresults = None
                self.tcprca = None
            
        else: 
            self.run_id = ""
            self.domain = ""
            self.basepath = basepath

            self.tcp_path = "{}".format(basepath)

            self.capture = Capture(self.tcp_path, self.debug) 
            self.target = TargetInfo(self.tcp_path, self.debug) 
            self.tcpoptions = TCPOptions(self.capture.capture_df, self.debug)
            self.tcpflowchars = TCPFlowCharacteristics(self.capture.capture_df, self.capture.ips)
            self.tcpkpis = TCPKPIs(basepath, domain, run_id, self.capture.capture_df, self.capture.ips, self.debug)
            self.tcprca = TCPRCA(basepath, domain, run_id, self.capture.capture_df, self.capture.ips, self.debug)

    def get_output_dict(self):   

        if self.capture == None: 
            return None

        output = {
                # meta
                "basepath": self.basepath,
                "domain": self.domain,
                "run_id": self.run_id, 
                "quic_run_id": self.quicresults.quic_run_id,
                "debug_mode": self.debug,
                #"target": { 
                    "url": self.target.url,
                    "crawled_size": self.target.crawled_size,
                    "asnr": self.target.asnr, 
                    "orgid": self.target.orgid, 
                    "ip_version": self.capture.ips.ip_version,
                    "server_ip": self.capture.ips.server_ip,
                    "client_ip": self.capture.ips.client_ip,
                    "status": self.target.http_status,
                    "tcp_stream_id_before_filtering": self.capture.tcp_stream_num_of_download,
                #},
               # "options": { 
                    "client_ECN": self.tcpoptions.clientECN,
                    "client_SACK": self.tcpoptions.clientSACK,
                    "client_SACK_value": self.tcpoptions.clientSACK_value,
                    "client_TFO": self.tcpoptions.clientTFO,
                    "client_TFO_cookie": self.tcpoptions.clientTFO_cookie,
                    "client_WS": self.tcpoptions.clientWS,
                    "server_ECN": self.tcpoptions.serverECN,
                    "server_SACK": self.tcpoptions.serverSACK,
                    "server_SACK_value": self.tcpoptions.serverSACK_value,
                    "server_TFO": self.tcpoptions.serverTFO,
                    "server_TFO_cookie": self.tcpoptions.serverTFO_cookie,
                    "server_WS": self.tcpoptions.serverWS,
                    "ecn_ece_count": self.tcpoptions.ecn_ece_count ,
                    "ecn_cwr_count": self.tcpoptions.ecn_cwr_count ,
                    "sack_count": self.tcpoptions.sack_count ,
                    "sack_le_block_count": self.tcpoptions.sack_le_set_count,
                    "sack_re_block_count": self.tcpoptions.sack_re_set_count,
                #"tcp_flow_chars": { 
                    "tcp_flow_size": self.tcpflowchars.flowbytes.total_bytes,
                    "tcp_flow_duration": self.tcpflowchars.flowduration.duration,
                    "tcp_flow_packets": self.tcpflowchars.flowpackets.total_packets,
                    "tcp_flow_rate": self.tcpflowchars.flowrate,
                    "tcp_tx_bytes": self.tcpflowchars.flowbytes.tx_bytes,
                    "tcp_rx_bytes": self.tcpflowchars.flowbytes.rx_bytes,
                    "tcp_tx_packets": self.tcpflowchars.flowpackets.tx_packets,
                    "tcp_rx_packets": self.tcpflowchars.flowpackets.rx_packets,
                #"aioquic_flow_chars"
                    "aioquic_success": 0,
                    "aioquic_flow_size": 0,
                    "aioquic_flow_duration": 0,
                    "aioquic_flow_packets": 0,
                    "aioquic_flow_rate": 0,
                    "aioquic_tx_bytes": 0,
                    "aioquic_rx_bytes": 0,
                    "aioquic_tx_packets": 0,
                    "aioquic_rx_packets": 0,
                #"quiche_flow_chars"
                    "quiche_success": 0,
                    "quiche_flow_size": 0,
                    "quiche_flow_duration": 0,
                    "quiche_flow_packets": 0,
                    "quiche_flow_rate": 0,
                    "quiche_tx_bytes": 0,
                    "quiche_rx_bytes": 0,
                    "quiche_tx_packets": 0,
                    "quiche_rx_packets": 0,
                #"tcp_kpis"
                    "tcp_tp_max": self.tcpkpis.tp_stats.tp_max,
                    "tcp_tp_mean": self.tcpkpis.tp_stats.tp_mean,
                    "tcp_tp_std": self.tcpkpis.tp_stats.tp_std,
                    "tcp_gp_mean": self.tcpkpis.gp_mean,
                    "tcp_rtt_samples": self.tcpkpis.rtt_stats.rtt_sample_count,
                    "tcp_rtt_min": self.tcpkpis.rtt_stats.rtt_min,
                    "tcp_rtt_max": self.tcpkpis.rtt_stats.rtt_max,
                    "tcp_rtt_mean": self.tcpkpis.rtt_stats.rtt_mean,
                    "tcp_rtt_std": self.tcpkpis.rtt_stats.rtt_std,
                #congestion type
                    "tcp_rtt_normdiff": self.tcpkpis.rtt_stats.rtt_normdiff,
                    "tcp_rtt_cov": self.tcpkpis.rtt_stats.rtt_cov,
                    "tcp_retransmission_count": self.tcpkpis.retransmission_stats.retransmission_count,
                    "tcp_fast_restransmisson_count": self.tcpkpis.retransmission_stats.fast_retransmission_count,
                    "tcp_spurious_retransmission_count": self.tcpkpis.retransmission_stats.spurious_retransmission_count,
                    "tcp_total_retransmission_count": self.tcpkpis.retransmission_stats.total_retransmissions,
                    "tcp_retransmission_rate": self.tcpkpis.retransmission_stats.total_retransmission_rate,
                    "tcp_dtt": self.tcpkpis.dtt,
                    "tcp_cst": self.tcpkpis.cst,
                #"rca": { 
                    "tcp_rca_number_alp":       self.tcprca.number_alp,     
                    "tcp_rca_number_ub":        self.tcprca.number_ub,      
                    "tcp_rca_number_sb":        self.tcprca.number_sb,      
                    "tcp_rca_number_rw":        self.tcprca.number_rw,      
                    "tcp_rca_number_tl":        self.tcprca.number_tl,      
                    "tcp_rca_number_other":     self.tcprca.number_other,   
                    "tcp_rca_bytes_alp":        self.tcprca.bytes_alp,      
                    "tcp_rca_bytes_ub":         self.tcprca.bytes_ub,       
                    "tcp_rca_bytes_sb":         self.tcprca.bytes_sb,       
                    "tcp_rca_bytes_rw":         self.tcprca.bytes_rw,       
                    "tcp_rca_bytes_tl":         self.tcprca.bytes_tl,       
                    "tcp_rca_bytes_other":      self.tcprca.bytes_other,   
                    "tcp_rca_duration_alp":     self.tcprca.duration_alp,   
                    "tcp_rca_duration_ub":      self.tcprca.duration_ub,    
                    "tcp_rca_duration_sb":      self.tcprca.duration_sb,    
                    "tcp_rca_duration_rw":      self.tcprca.duration_rw,    
                    "tcp_rca_duration_tl":      self.tcprca.duration_tl,    
                    "tcp_rca_duration_other":   self.tcprca.duration_other, 
                    "tcp_rca_packets_alp":      self.tcprca.packets_alp,    
                    "tcp_rca_packets_ub":       self.tcprca.packets_ub,     
                    "tcp_rca_packets_sb":       self.tcprca.packets_sb,     
                    "tcp_rca_packets_rw":       self.tcprca.packets_rw,     
                    "tcp_rca_packets_tl":       self.tcprca.packets_tl,    
                    "tcp_rca_packets_other":    self.tcprca.packets_other,
                    "tcp_rca_max_outstanding":  self.tcprca.max_outstanding,  
                    "tcp_rca_min_awnd":         self.tcprca.min_awnd,
                    "tcp_rca_max_awnd":         self.tcprca.max_awnd,
            }
  
        return output

    def __str__(self): 
        
        output_dict = self.get_output_dict()

        return json.dumps(output_dict, sort_keys=False, indent=4, separators=(',', ': '))




            