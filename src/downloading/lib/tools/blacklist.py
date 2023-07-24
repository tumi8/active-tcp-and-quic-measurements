import ipaddress
import logging
from typing import Optional


class Blacklist:
    def __init__(self, v4_file: Optional[str], v6_file: Optional[str], logger: logging.Logger):
        self._blacklist_networks = []
        self.logger = logger
        self.logger.level = logging.DEBUG
        if v4_file:
            self._load_blacklist(v4_file)
        if v6_file:
            self._load_blacklist(v6_file)

    def _load_blacklist(self, file: str):
        lines = 0
        with open(file, 'r') as f:
            for line in f:
                if len(line) > 0:
                    lines += 1
                    try:
                        self._blacklist_networks.append(ipaddress.ip_network(line.replace("\r", "").replace("\n", "")))
                    except ValueError as e:
                        self.logger.error("Failed to load address {}: {}".format(line, e))

        self.logger.info("Loaded {} lines from {}".format(lines, file))

    def is_blacklisted(self, ip: str) -> Optional[bool]:
        try:
            ip = ipaddress.ip_address(ip)
        except ValueError as e:
            self.logger.error("Invalid address supplied {}: {}".format(ip, e))
            return

        for network in self._blacklist_networks:
            if ip in network:
                self.logger.debug("IP {} is blacklisted by {}".format(ip, network))
                return True

        self.logger.debug("IP {} is not blacklisted".format(ip))
        return False
