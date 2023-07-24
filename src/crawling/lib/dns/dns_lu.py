import csv
from datetime import datetime
import logging
import re
import socket
from urllib.parse import urlparse
from typing import List, Dict, Set


class DnsLu:
    inst = None
    write_lock = False

    def __init__(self, *args, **kwargs):
        self._dns_cache = {}
        self.logger = None

    @classmethod
    def get_inst(cls, logger: logging.LoggerAdapter) -> 'DnsLu':
        if not cls.inst:
            cls.inst = DnsLu()
            cls.inst.logger = logger
            cls.inst.logger.setLevel(logging.INFO)

        return cls.inst

    def resolve(self, domain: str) -> List[str]:
        if re.match(r'^https?:\/\/', domain):
            domain = urlparse(domain).netloc

        # Remove Port if present
        domain = domain.split(":")[0]

        if domain in self._dns_cache:
            self.logger.debug("Using DNS Cache for " + domain)
            return self._dns_cache[domain]
        else:
            ips = []
            lst = []
            try:
                lst = socket.getaddrinfo(domain, None)
            except Exception as e:
                self.logger.error("Failed to resolve {}: {}".format(domain, e))

            for rec in lst:
                ip = rec[4][0]
                if ip not in ips:
                    ips.append(ip)

            self.logger.debug("Resolved {} to {} ".format(domain, ips))
            self._dns_cache[domain] = ips
            return ips

    def save_resolved(self, path_full: str, path_diff: str, path_cur: str):
        self.logger.info("Resolved {} domains to {} IPs".format(
            len(self._dns_cache), len([ip for ips in self._dns_cache.values() for ip in ips]))
        )

        if DnsLu.write_lock:
            print('Saving in progress')
            return

        DnsLu.write_lock = True

        ts = datetime.now().isoformat('T', 'seconds')
        dns_list_full = []  # Complete list (including those from previous crawls)
        dns_list_cur = []  # All Domains from this run
        new_ips = []  # Only domains not already in dns_list_full
        new = DnsLu._dict2list(self._dns_cache)

        # Read existing data
        try:
            with open(path_full, 'r') as f:
                csv_r = csv.DictReader(f)
                for row in csv_r:
                    dns_list_full.append(row)
        except FileNotFoundError:
            pass

        # Loop over resolved domains
        for domain, ip in new:
            found = False
            dns_list_cur.append({
                'ip': ip,
                'domain': domain,
            })

            # Search for existing entry and update last seen
            for idx, row in enumerate(dns_list_full):
                if row['ip'] == ip and row['domain'] == domain:
                    row['last_seen'] = ts
                    found = True
                    dns_list_full[idx] = row

            # If not found, add it to list
            if not found:
                if ip not in new_ips:
                    new_ips.append(ip)
                dns_list_full.append({
                    'ip': ip,
                    'domain': domain,
                    'added': ts,
                    'last_seen': ts,
                })

        # Write files
        with open(path_full, 'w') as f:
            csv_w = csv.DictWriter(f, fieldnames=['ip', 'domain', 'added', 'last_seen'])
            csv_w.writeheader()
            for row in dns_list_full:
                csv_w.writerow(row)
        self.logger.info("Wrote complete list of domains to {} ({} rows)".format(path_full, len(dns_list_full)))

        with open(path_diff, 'w') as f:
            f.write("\n".join(new_ips))
            f.write("\n")
        self.logger.info("Wrote list of new IPs to {} ({} rows)".format(path_full, len(new_ips)))

        with open(path_cur, 'w') as f:
            csv_w = csv.DictWriter(f, fieldnames=['ip', 'domain'])
            csv_w.writeheader()
            for row in dns_list_cur:
                csv_w.writerow(row)
        self.logger.info("Wrote list data from this scan to {} ({} rows)".format(path_full, len(dns_list_cur)))

        DnsLu.write_lock = False

    @staticmethod
    def _dict2list(a: Dict) -> List:
        """
        Flattens a dictionary into a list
        {k1: [va, vb], k2: [vc, vd]} -> [(k1, va), (k1, vb), (k2, vc), (k2, vd)]

        :param a: Dictionary to be flattened
        :return: Flattened dictionary
        """

        return [(k, v) for k in a.keys() for v in a[k]]
