import pandas as pd

from lib.lib import get_json_data


class TargetInfo:
    """"
    contains ips, as info, and download http status extracted from capture_df and files written during DLs
    """

    def __init__(self, tcp_path: str, debug: bool):
        
        if not debug: 

            self.tcp_path = tcp_path

            target_info = get_json_data("{}/target_info.json".format(self.tcp_path))
            meta_info = get_json_data("{}/meta_lines.txt".format(self.tcp_path))

            self.url = meta_info["url"]
            self.crawled_size = meta_info["bytes_downloaded"] 
            self.asnr = target_info["asnr"]
            self.orgid = target_info["orgid"]
            self.http_status = meta_info["reply_headers"]["Status"]  

        if debug: 

            self.url = "debug"
            self.crawled_size = "debug"
            self.asnr = "debug"
            self.orgid = "debug"
            self.http_status = "debug"     

 



