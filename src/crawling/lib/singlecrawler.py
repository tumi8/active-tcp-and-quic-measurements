# from schwarzenberg tools

import csv
import logging
import random
from scrapy.crawler import CrawlerProcess
import socket
import sys
import subprocess
import time
from typing import List, Tuple

from cfg import singlecrawler_cfg, scrapy_cfg, spider_cfg
from tools import get_logger
from spider import FileSearch


def main():
    """
    Main handler: Start crawling

    :return: None
    """

    cfg = singlecrawler_cfg()

    socket.setdefaulttimeout(20)

    #time.sleep((random.randint(2, 18)))
    #return

    process = CrawlerProcess(settings=scrapy_cfg(cfg))
    process.crawl(FileSearch, **spider_cfg(cfg))
    process.start()


if __name__ == "__main__":
    main()
