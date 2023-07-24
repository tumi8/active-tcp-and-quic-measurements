from collections import defaultdict
import csv
from datetime import datetime
import logging
import os
import pathlib
import time
import json
import sys
from cfg import downloader_cfg
from dl_file import Downloader
from capture import Capture

from tools import get_logger, count_running


def main():
    """
    Main handler: Download file

    :return: None
    """

    # Redirect urrlib SSL Warning to logger py.warnings
    logging.captureWarnings(True)
    wdir = sys.argv[1]
    cfg = downloader_cfg()
    d_cfg = cfg['downloader']
    g_cfg = cfg['']

    # Create per-download subfolder
    #wdir = os.path.join(g_cfg['dir'], datetime.now().isoformat('T', 'seconds').replace(':', '-'))
    pathlib.Path(wdir).mkdir(parents=True, exist_ok=True)
    meta_file = os.path.join(wdir, "meta.json")
    keylog = os.path.join(wdir, "sslkeylog.txt")

    logger_dl = get_logger('downloader', wdir, logging.DEBUG)
    logger_cpt = get_logger('capture', wdir, logging.DEBUG)
    get_logger("urllib3", wdir, logging.DEBUG)
    get_logger("py.warnings", wdir, logging.DEBUG)

    if count_running('python', 'downloader/main.py') > 1:
        logger_dl.error('Previous downloader still running, exiting.')
        return

    c = Capture(wdir, d_cfg, logger_cpt)
    d = Downloader(c, logger_dl, d_cfg, keylog, wdir)

    #c.start(d_cfg['interface'])

    try:
        if d_cfg.get('url_file'):
            #time.sleep(10)
            d.download_multi(get_urls_from_csv(d_cfg['url_file']))

        if d_cfg.get('urls'):
            for url in d_cfg['urls']:
                if url:
                    d.download(url)

        d.write_meta(meta_file)
    except Exception as e:
        logger_dl.error("Downloading failed: {}".format(e))
        raise e


def get_urls_from_csv(file: str) -> dict:
    csvdata = defaultdict(list)
    with open(file, 'r') as f:
        for row in csv.DictReader(f):
            domain = row['scan_domain']
            csvdata[domain].append(row)

    return csvdata


if __name__ == "__main__":
    # execute only if run as a script
    main()
