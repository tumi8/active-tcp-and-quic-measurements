## from ma-brzoza/code/schwarzenberg-tools/crawler/

import csv
import logging
import os
import random
from scrapy.crawler import CrawlerProcess
import socket
import sys
import subprocess
import time
from typing import List, Tuple

from cfg import batchcrawler_cfg, scrapy_cfg, spider_cfg
from matool import get_logger
from spider import FileSearch


def check_wait(queue: List[Tuple[str, subprocess.Popen]], nparallel: int, spawn_wait: int) -> int:
    running = 0
    for _, p in queue:
        if p.poll() is None:
            running += 1

    if running <= nparallel:
        return running
    else:
        time.sleep(spawn_wait)
        return check_wait(queue, nparallel, spawn_wait)


def get_terminated(queue: List[Tuple[str, subprocess.Popen]], known_terminated: List[str] = None) -> List[str]:
    check_terminated = known_terminated is not None
    known_terminated = []  # Init with iterable value
    running = []
    for n, p in queue:
        if not p.poll() is None:
            if n not in known_terminated:
                if check_terminated:
                    known_terminated.append(n)
                running.append(n)

    return running


def log_terminated(logger: logging.Logger, terminated: List[str]):
    if len(terminated) > 0:
        logger.info("Crawling finished for: {}".format(", ".join(terminated)))


def main():
    """
    Main handler: Start crawling

    :return: None
    """

    cfg = batchcrawler_cfg()

    nparallel = cfg['batchcrawler']['nparallel']
    spawn_wait = cfg['batchcrawler']['spawn_wait']
    if 'urls' in cfg['batchcrawler']:
        crawl_urls = cfg['batchcrawler']['urls']
    else:
        crawl_urls = []

    try:
        crawl_urlfile_handle = cfg['batchcrawler']['url_file']
    except KeyError:
        crawl_urlfile_handle = None

    known_terminated = []
    domain_list = []
    domain_count_total = 0
    modpath = os.path.abspath(os.path.dirname(__file__))

    if len(crawl_urls) > 1 or crawl_urlfile_handle:
        procs = []
        # Init here, otherwise we create empty logfiles for every run
        logger = get_logger('batchcrawler', cfg['']['dir'], logging.DEBUG)

        for domain in crawl_urls:
            domain_list.append((None, domain))

            if not crawl_urlfile_handle:
                # Do not count when running
                domain_count_total += 1

        if crawl_urlfile_handle:
            for row in csv.reader(crawl_urlfile_handle):
                sys.stdout.write('lol')
                rank = row[0]
                domain = row[1]
                domain_list.append((rank, domain))
                domain_count_total += 1

        logger.info("Crawling {} domains, {} in parallel, wait time after each domain: {}s".format(
            domain_count_total,
            nparallel,
            spawn_wait
        ))

        for rank, domain in domain_list:
    
            args = [
                'python3',
                os.path.join(modpath, 'singlecrawler.py'),
                cfg['']['dir'],
                cfg['']['cfg'].name,
                '-singlecrawler_url', domain,
            ]
            if rank:
                args.extend([
                    '-singlecrawler_domain_rank', rank,
                ])

            logger.info("Spawning for {}: {}".format(domain, " ".join(args)))

            p = subprocess.Popen(args)
            procs.append((domain, p))
            running = check_wait(procs, nparallel, spawn_wait)
            log_terminated(logger, get_terminated(procs, known_terminated))
            logger.info("{} crawlers are running".format(running))

            print("Crawled {} of {} domains".format(len(get_terminated(procs)), domain_count_total))

        logger.info("Waiting for remaining processes to finish...")
        for domain, p in procs:
            p.wait()
            log_terminated(logger, get_terminated(procs, known_terminated))
            print("Crawled {} of {} domains".format(len(get_terminated(procs)), domain_count_total))

if __name__ == "__main__":
    main()
