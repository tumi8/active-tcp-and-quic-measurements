from copy import copy
from datetime import datetime
from forcediphttpsadapter.adapters import ForcedIPHTTPSAdapter
import ipaddress
import json
import logging
import os
import requests
import time
import re
from typing import List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit, urlparse
import socket

from dns import DnsLu
from tools import get_socket_addr_remote, get_socket_addr_local, Blacklist, get_logger

import capture
import pandas as pd
import subprocess


class Downloader:
    def __init__(self, capture: capture.Capture, logger: logging.Logger, cfg: dict, keylog: str, wdir: str):
        socket.setdefaulttimeout(10)

        self.sockinfo = ()
        self.capture = capture
        self.logger = logger
        self.dns_lu = DnsLu.get_inst(logger)
        self.use_ipv = cfg['ipv']
        self.download_limit = cfg['download_limit']
        self.max_download_domains = cfg['max_download_domains']
        self.sleep_between = cfg['sleep_between']
        self.wdir = wdir
        self.meta = []
        self.interface = cfg['interface']
        _now = datetime.now()
        self.meta_cfg = {
            'start': _now.isoformat('T', 'seconds').replace(':', '-'),
            'start_ts': _now.timestamp(),
            'download_limit': cfg['download_limit'],
            'cap_rotate_interval': cfg['cap_rotate_interval'],
            'cap_rotate_size': cfg['cap_rotate_size'],
            'capture_snaplen': cfg['cap_snaplen'],
            'sleep_before': cfg['sleep_before'],
            'sleep_between': self.sleep_between,
            'sleep_after': cfg['sleep_after'],
        }
        self.last_server_status = None

        blf_v4 = cfg.get('v4_blacklist')
        blf_v6 = cfg.get('v6_blacklist')
        bl_logger = get_logger('blacklist', wdir, logging.DEBUG)

        self.blacklist = Blacklist(blf_v4, blf_v6, bl_logger)
        self.progress_logger = get_logger('dl_progress', wdir, logging.DEBUG)
        self.sock_conn_fail = None  # None: Unknown, True/False: socket fail state

    def download(self, url: str):
        self.__clear4file()
        if len(url) == 0:
            self.logger.warning("Invalid url: {}".format(url))
            return
        self.logger.info("Downloading file: {}".format(url))

        additional_meta = Downloader.__get_additional_meta(None, None, None, None, None, None)
        self._download_resolving(url, additional_meta)

    def download_multi(self, urllist: dict):
        limit_ctr = 0
        domaincnt = len(urllist)
        print("Debug = function download_multi")
        # Urls are grouped by domain
        for domain, urldata in urllist.items():
            self.__clear4domain()
            self.progress_logger.info("Downloading from domain {} - {} of {}".format(domain, limit_ctr+1, domaincnt))

            if 0 < self.max_download_domains <= limit_ctr:
                self.logger.warning("Exceeded domain count limit. Cancelling.")
                return

            self.logger.info("Downloading from domain: {}".format(domain))

            continue_next_domain = False
            # Do not follow redirects at first, but if all downloads of a domain fail, try again and follow them
            for follow_redirects in [False, True]:
                if continue_next_domain:
                    break

                # Loop over URLs of domain
                for ctr_url, c_res in enumerate(urldata):
                    self.__clear4file()

                    url = c_res['url']
                    preferred_v4 = Downloader.__process_iplist(c_res['preferred_v4'])
                    preferred_v6 = Downloader.__process_iplist(c_res['preferred_v6'])

                    additional_meta = Downloader.__get_additional_meta(
                        c_res['scan_domain'],
                        int(c_res['rank']),
                        ctr_url+1,
                        int(c_res['size']),
                        c_res['size_is_lower_bound'] == "True",
                        c_res['crawl']
                    )

                    # Download file using preferred IPs
                    res_pref_v4 = self._download_once_from_list(url, preferred_v4, additional_meta, 'preferred', 4, follow_redirects)
                    pref_conn_fail_v4 = self.sock_conn_fail

                    res_pref_v6 = self._download_once_from_list(url, preferred_v6, additional_meta, 'preferred', 6, follow_redirects)
                    pref_conn_fail_v6 = self.sock_conn_fail

                    res_recent_v4, res_recent_v6, rec_conn_fail_v4, rec_conn_fail_v6 = self._download_resolving(url, additional_meta, follow_redirects)

                    if all([res_pref_v4, res_pref_v6, res_recent_v4, res_recent_v6]):
                        # We downloaded the file, continue with next domain
                        continue_next_domain = True
                        break

                    # Check, if all connections to Servers failed for this file
                    # Explicitly check for True and None, as None means unknown state (e.g. IP version not tried).
                    # This also counts as failed
                    if (pref_conn_fail_v4 or pref_conn_fail_v4 is None) and \
                            (pref_conn_fail_v6 or pref_conn_fail_v6 is None) and \
                            (rec_conn_fail_v4 or rec_conn_fail_v4 is None) and \
                            (rec_conn_fail_v6 or rec_conn_fail_v6 is None):
                        self.logger.error("No IP of this domain is replying. Failing ALL downloads for this domain")
                        continue_next_domain = True
                        break

            limit_ctr += 1

    def _download_resolving(self, url: str, additional_meta: dict, follow_redirects: bool = True) -> Tuple[bool, bool, bool, bool]:
        recent_v4 = []
        recent_v6 = []
        # Download file using live resolved IPs
        for ip in self.dns_lu.resolve(urlparse(url).netloc):
            if ipaddress.ip_address(ip).version == 4:
                recent_v4.append(ip)
            elif ipaddress.ip_address(ip).version == 6:
                recent_v6.append(ip)


        for ipv4 in recent_v4:
            if self.blacklist.is_blacklisted(ipv4):
                self.logger.warning("\tIP {} is blacklisted, skipping".format(ipv4))
                return

        for ipv6 in recent_v6:
            if self.blacklist.is_blacklisted(ipv6):
                self.logger.warning("\tIP {} is blacklisted, skipping".format(ipv6))
                return
        
        with open(os.path.join(self.wdir, "server_ips.txt"), 'a') as f:
            for ip in recent_v4:    
                f.writelines(ip)
            for ip in recent_v6:
                f.writelines(ip)

        res_recent_v4 = self._download_once_from_list(url, recent_v4, additional_meta, 'recent', 4, follow_redirects)
        conn_fail_v4 = self.sock_conn_fail
        res_recent_v6 = self._download_once_from_list(url, recent_v6, additional_meta, 'recent', 6, follow_redirects)
        conn_fail_v6 = self.sock_conn_fail

        return res_recent_v4, res_recent_v6, conn_fail_v4, conn_fail_v6

    def _download_once_from_list(self, url: str, iplist: List[str], additional_meta: dict, dltype: str, ipv: int = 0, follow_redirects: bool = True) -> bool:
        if self.last_server_status is not None:
            return True
        if not self._check_use_ipv(ipv) or len(iplist) == 0:
            self.logger.info("\tShould not use IPv{} or no IPs given.".format(ipv))
            return True  # This download should internally count as successful (do not retry with different IP)!

        self.logger.info("\tTrying download using {} IPv{} list".format(dltype, ipv))
        additional_meta = copy(additional_meta)
        for pos, ip in enumerate(iplist):
            if not ip:
                continue

            if self.last_server_status and (400 <= self.last_server_status < 500):
                self.logger.warning("\tReceived status {}. Cancelling this file".format(self.last_server_status))
                break

            if self._check_use_ip(ip):
                additional_meta.update({
                    'tried_ips': pos+1,
                    'request_type': dltype,
                })

                res = self._replace_httphost(url, ip, additional_meta, follow_redirects)
            else:
                self.logger.warning("\tWrong IP version found in iplist at {}: {}. This should not happen.".format(pos, ip))
                continue

            if res:
                self.logger.info("\tDownload succeeded (tried {} IPs)".format(pos+1))
                return True

        self.logger.warning(
            "\tDownloading failed: Exhausted provided IP addresses (tried {}) - all downloads failed".format(
                len(iplist),
            )
        )
        return False

    def _replace_httphost(self, url: str, ip: str, additional_meta: dict = {}, follow_redirects: bool = True) -> bool:
        self.__clear4conn()
        split_url = list(urlsplit(url))
        urlparts = urlparse(url)

        if not self._check_use_ip(ip):
            self.logger.warning("Can't use IP {} - wrong IP version".format(ip))
            return False

        ipv = ipaddress.ip_address(ip).version

        # Reformat host-part in case of IPv6
        if ipv == 4:
            split_url[1] = ip
        elif ipv == 6:
            split_url[1] = "[{}]".format(ip)
        new_url = urlunsplit(split_url)

        is_https = split_url[0] == "https"

        return self._download_file(url, new_url, urlparts.netloc, ip, is_https, additional_meta, follow_redirects)

    def _download_file(self, org_url: str, new_url: str, http_host: str, force_ip: str, is_https: bool, additional_meta: dict = {}, follow_redirects: bool = True) -> bool:
        if not new_url:
            return False

        # Start Packet capture
        self.capture.start(self.interface)

        start = datetime.now().timestamp()
        download_cancelled = False
        r_ip, r_port = None, None
        l_ip, l_port = None, None
        content = None
        headers = None
        length = None
        content_length = None
        stop = None
        dl_err = None
        dl_from = None
        blacklisted = False
        transfer_time = None
        response_time = None


        if self.blacklist.is_blacklisted(force_ip):
            self.logger.warning("\tIP {} is blacklisted, skipping".format(force_ip))
            blacklisted = True
            self.last_server_status = 451

        try:
            if not blacklisted:
                self.logger.info("\tDownloading file {} from IP {}. Following redirects: {}".format(org_url, force_ip, follow_redirects))


                if is_https:
                    self.logger.info("\tHTTPS - Using ForcedIPHTTPSAdapter adapter and original url")
                    dl_from = org_url
                else:
                    self.logger.info("\tHTTP - Using modified URL containing IP")
                    dl_from = new_url

                #cmd = "wget2 -O /dev/null -S --stats-site=csv:{}/download_stats.csv --output-file={}/wget2_logfile '{}'".format(self.wdir,self.wdir,org_url)
                cmd = ['wget2', '--https-enforce=hard', '--no-cache', '-O', '/dev/null', '-S', '--stats-site=csv:{}/download_stats.csv'.format(self.wdir), '--output-file={}/wget2_logfile'.format(self.wdir), org_url]
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
                
                try:
                    proc.wait(timeout=45)
                except Exception as e:
                    proc.kill()
                    self.logger.error(e)

                

                download_cancelled = True
                stop = datetime.now().timestamp()
                time.sleep(1)
                try:
                    df_stats = pd.read_csv('{}/download_stats.csv'.format(self.wdir))
                    df_stats_OK = df_stats[df_stats['Status'] == 200]
                    if len(df_stats_OK) == 0:
                        self.last_server_status = int(df_stats.iloc[-1]['Status'])
                    else:
                        self.last_server_status = int(df_stats_OK .iloc[-1]['Status'])
                        length = int(df_stats_OK .iloc[-1]['Size'])
                        transfer_time = int(df_stats_OK.iloc[0]['TransferTime'])
                        response_time = int(df_stats_OK.iloc[0]['ResponseTime'])
                except Exception as e:
                    self.last_server_status = 599
                    self.logger.error("\t can't process download_stats.csv: {}".format(e))
                
                try:
                    headers = self._get_wget2_logs()
                    content_length = headers['Content-Length']
                    if self.last_server_status == 599 and headers['Status'] is not None:
                        self.last_server_status = headers['Status']
                except Exception as e:
                    self.logger.error("\t can't process wget2 logs: {}".format(e))

                self.logger.info(
                    "\tDownload finished (code {}, size: {})".format(self.last_server_status, length)
                )


                return self.last_server_status == 200

        except Exception as req_err:
            self.logger.error("\tDownload failed: {}".format(req_err))

            self.last_server_status = None
            stop = datetime.now().timestamp()
            download_cancelled = None
            dl_err = str(req_err)

        finally:
            # Stop Packet capture
            self.capture.stop()
            meta = {
                'host': http_host,
                'url': dl_from,
                'local_ip': l_ip,
                'local_port': l_port,
                'remote_ip': r_ip,
                'remote_port': r_port,
                'desired_ip': force_ip,
                'follow_redirects': follow_redirects,
                'ip_blacklisted': blacklisted,
                'http_status': self.last_server_status,
                'reply_headers': headers,
                'reply_content': content,
                'bytes_downloaded': length,
                'download_cancelled': download_cancelled,
                'content_length': content_length,
                'transfer_time' : transfer_time,
                'response_time' : response_time,
                'start_ts': start,
                'stop_ts': stop,
                'fail': dl_err is not None,
                'error': dl_err,
            }
            meta.update(additional_meta)
            self._write_metapart(meta)
            self.meta.append(meta)
            self.sock_conn_fail = r_ip is None
            if length and length > 50:
                # Do not wait after very small (=failed) downloads
                time.sleep(self.sleep_between)

        return False

    def _check_use_ip(self, ip: str) -> bool:
        dl_ip_version = ipaddress.ip_address(ip).version

        for ipv in self.use_ipv:
            if dl_ip_version == ipv.value:
                return True

        return False

    def _check_use_ipv(self, ipv: int) -> bool:
        for ip in self.use_ipv:
            if ipv == ip.value:
                return True

        return False

    def __clear4domain(self):
        pass

    def __clear4file(self):
        self.last_server_status = None

    def __clear4conn(self):
        self.sock_conn_fail = None

    def _write_metapart(self, meta: dict):
        with open(os.path.join(self.wdir, "meta_lines.txt"), 'w') as f:
            try:
                f.write(json.dumps(meta) + "\n")
            except Exception as e:
                self.logger.error("Failed to write metapart: {}".format(e))
    def _get_wget2_logs(self):
        data = {}
        filepath = self.wdir+'/wget2_logfile'
        with open(filepath, 'r') as document:
            server = date = content_type = content_length = last_modified = status = None
            process = 0
            for line in document:
                if 'Server:'.casefold() in line.casefold():
                    server = re.split("Server:", line, flags=re.IGNORECASE)[1].strip()
                    process += 1
                elif 'Date:'.casefold() in line.casefold():
                    date = re.split("Date:", line, flags=re.IGNORECASE)[1].strip()
                    process += 1
                elif 'Content-type:'.casefold() in line.casefold():
                    content_type = re.split("Content-type:", line, flags=re.IGNORECASE)[1].strip()
                    process += 1
                elif 'Content-Length:'.casefold() in line.casefold():
                    content_length = int(re.split("Content-Length:", line, flags=re.IGNORECASE)[1].strip())
                    process += 1
                elif 'Last-Modified:'.casefold() in line.casefold():
                    last_modified = re.split("Last-Modified:", line, flags=re.IGNORECASE)[1].strip()
                    process += 1
                elif ':status:'.casefold() in line.casefold():
                    status= int(re.split("status:", line, flags=re.IGNORECASE)[1].strip())
                elif '200 OK'.casefold() in line.casefold():
                    status= 200
                if process == 5:
                    break
            data = {"Server": server, 'Content-type': content_type, "Content-Length": content_length, "Last-Modified": last_modified, "Status": status}
        return data

    def write_meta(self, dest: str):
        _now = datetime.now()
        self.meta_cfg.update({
            'stop': _now.isoformat('T', 'seconds').replace(':', '-'),
            'stop_ts': _now.timestamp(),
            'duration': _now.timestamp() - self.meta_cfg['start_ts'],
        })

        # Write config part of meta
        try:
            mdest = dest.replace("meta.json", 'metacfg.json')
            with open(mdest, "w") as f:
                f.write(
                    json.dumps({
                        'conf': self.meta_cfg,
                    }, indent=2)
                )
        except Exception as e:
            msg = "Serializing meta_cfg failed: {}".format(e)
            print(msg)
            print(self.meta_cfg)
            self.logger.error(msg)

        # We use meta_lines for now
        """
        with open(dest.replace('.json', '_dl.txt'), "w") as f:
            f.write(
                str(self.meta)
            )

        with open(dest, "w") as f:
            f.write(
                json.dumps({
                    'conf': self.meta_cfg,
                    'downloads': self.meta,
                }, indent=2)
            )
        """

    @staticmethod
    def __get_additional_meta(
            domain: Optional[str],
            domain_rank: Optional[int],
            tried_files: Optional[int],
            crawler_size: Optional[int],
            crawler_size_is_lbound: Optional[bool],
            crawler_run: Optional[int]
    ) -> dict:
        return {
            'domain': domain,
            'domain_rank': domain_rank,
            'tried_files': tried_files,
            'crawler_size': crawler_size,
            'crawler_size_is_lower_bound': crawler_size_is_lbound,
            'crawler_run': crawler_run,
        }

    @staticmethod
    def __process_iplist(iplist: str) -> list:
        # Check for empty string, otherwise empty ip lists are ['']
        if len(iplist) > 0:
            return iplist.split(" ")
        else:
            return []

