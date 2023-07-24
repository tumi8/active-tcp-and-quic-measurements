import csv
from datetime import datetime
import logging
import json
import os
import pathlib
import re

from .dns_lu import DnsLu
from .cfg import dns_cfg
from matool import get_logger


def main():
    cfg = dns_cfg()
    d_cfg = cfg['dns']
    g_cfg = cfg['']

    now = datetime.now()
    isodate = now.isoformat('T', 'seconds').replace(':', '-')

    wdir = g_cfg['dir']  # Main working directory
    ddir = os.path.join(wdir, now.strftime('%Y-%m'), now.strftime('%Y-%m-%d'))  # Day directory (for full data)
    pathlib.Path(ddir).mkdir(parents=True, exist_ok=True)
    ldir = os.path.join(wdir, 'logs')  # Log directory
    pathlib.Path(ldir).mkdir(parents=True, exist_ok=True)

    # Logging
    logger = get_logger('dns', ldir, logging.DEBUG)
    d = DnsLu.get_inst(logger)

    f_full = os.path.abspath(os.path.join(wdir, "dns.csv"))
    f_diff = os.path.abspath(os.path.join(wdir, "dns-diff.txt"))
    f_cur = os.path.abspath(os.path.join(ddir, "{}.csv".format(isodate)))

    domains = []

    if d_cfg['domain_file']:
        with open(d_cfg['domain_file'], 'r') as f:
            for row in csv.reader(f):
                domains.append(row[-1])

    domains.extend(d_cfg['domains'])

    if d_cfg['auto_www']:
        www_domains = []
        for domain in domains:
            if not re.match(r'^www\.', domain):
                logger.info("auto_www: Adding {} to list of domains.".format("www." + domain))
                www_domains.append("www." + domain)
        domains.extend(www_domains)

    for domain in domains:
        d.resolve(domain)

    d.save_resolved(f_full, f_diff, f_cur)


if __name__ == "__main__":
    # execute only if run as a script
    main()
