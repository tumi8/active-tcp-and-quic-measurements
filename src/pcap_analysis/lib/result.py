import json

from lib.capture import Capture
from lib.target import TargetInfo
from lib.tcp_options import TCPOptions
from lib.tcp_flow_info import TCPFlowCharacteristics
from lib.tcp_kpis import TCPKPIs
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
                self.target = TargetInfo(self.tcp_path, self.debug) 
                self.tcpoptions = TCPOptions(self.capture.capture_df, self.debug)
                self.tcpflowchars = TCPFlowCharacteristics(self.capture.capture_df, self.capture.ips)
                self.tcpkpis = TCPKPIs(basepath, domain, run_id, self.capture.capture_df, self.capture.ips, self.debug)
                self.quicresults = QUICRESULTs(self.quic_path)

            except Exception as e: 
                print("EXCEPTION - reading pcap and creating capture instance failed")
                print(e)
                self.capture = None 
                self.target = None
                self.tcpoptions = None
                self.tcpflowchars = None
                self.tcpkpis = None
                self.quicresults = None
            
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
                    "aioquic_success": self.quicresults.aioquic_result.quic_dl_successful,
                    "aioquic_flow_size": self.quicresults.aioquic_result.flowbytes.total_bytes ,
                    "aioquic_flow_duration": self.quicresults.aioquic_result.flowduration.duration,
                    "aioquic_flow_packets": self.quicresults.aioquic_result.flowpackets.total_packets,
                    "aioquic_flow_rate": self.quicresults.aioquic_result.flowrate,
                    "aioquic_tx_bytes": self.quicresults.aioquic_result.flowbytes.tx_bytes,
                    "aioquic_rx_bytes": self.quicresults.aioquic_result.flowbytes.rx_bytes,
                    "aioquic_tx_packets": self.quicresults.aioquic_result.flowpackets.tx_packets,
                    "aioquic_rx_packets": self.quicresults.aioquic_result.flowpackets.rx_packets,
                #"quiche_flow_chars"
                    "quiche_success": self.quicresults.quiche_result.quic_dl_successful,
                    "quiche_flow_size": self.quicresults.quiche_result.flowbytes.total_bytes ,
                    "quiche_flow_duration": self.quicresults.quiche_result.flowduration.duration,
                    "quiche_flow_packets": self.quicresults.quiche_result.flowpackets.total_packets,
                    "quiche_flow_rate": self.quicresults.quiche_result.flowrate,
                    "quiche_tx_bytes": self.quicresults.quiche_result.flowbytes.tx_bytes,
                    "quiche_rx_bytes": self.quicresults.quiche_result.flowbytes.rx_bytes,
                    "quiche_tx_packets": self.quicresults.quiche_result.flowpackets.tx_packets,
                    "quiche_rx_packets": self.quicresults.quiche_result.flowpackets.rx_packets,
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
            }
  
        return output

    def __str__(self): 
        
        output_dict = self.get_output_dict()

        return json.dumps(output_dict, sort_keys=False, indent=4, separators=(',', ': '))




            
