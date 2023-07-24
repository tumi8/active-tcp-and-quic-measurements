import copy
from collections import defaultdict
from datetime import datetime
import json
import logging
import os
import re
import requests
import scrapy
from scrapy.exceptions import CloseSpider
from scrapy.linkextractors import LinkExtractor
import socket
from typing import List, Optional, Tuple
from urllib.parse import urlparse
from tools import MACfg, get_socket_addr_remote
from dns.dns_lu import DnsLu
import mastats


class FileSearch(scrapy.Spider):
    """
    File search Spider

    """
    name = "FileSearch"
    le = LinkExtractor(tags=('img', 'link', 'script'), attrs=('src', 'href'), deny_extensions=set())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger.setLevel(logging.INFO)
        logging.getLogger('scrapy').setLevel(logging.INFO)
        logging.getLogger('urllib3').setLevel(logging.INFO)

        # Initialized via kwargs (Spider-specific settings, no dedicated variable)!
        self.auto_www = self.__dict__.get('mycrawler_auto_www')
        self.minsize = max(1, self.__dict__.get('mycrawler_minsize'))
        self.maxsize = self.__dict__.get('mycrawler_maxsize')
        self.extensions = self.__dict__.get('mycrawler_extensions')
        self.outdir = self.__dict__.get('mycrawler_outdir')
        self.domain_rank = self.__dict__.get('mycrawler_domain_rank')

        self.allowed_domains = []

        self.dns_lu = DnsLu.get_inst(logging.LoggerAdapter(logging.getLogger('dnslookup'), {'spider': self}))

        stats_logger = logging.LoggerAdapter(logging.getLogger('mastats'), {'spider': self})

        self.stats_requestcnt = mastats.RequestCnt(logger=stats_logger)
        self.stats_matchcnt_lt200 = mastats.MatchCnt(logger=stats_logger, name="Matchcount<200")
        self.stats_matchcnt_gt200 = mastats.MatchCnt(logger=stats_logger, name="Matchcount>200", max_crawls_per_depth=5)
        self.stats_bytes_found = mastats.BytesFound(logger=stats_logger)

        self.stats_modules = [
            self.stats_requestcnt,
            self.stats_matchcnt_lt200,
            self.stats_matchcnt_gt200,
            self.stats_bytes_found,
        ]

    def closed(self, reason: str):
        """
        Called on spider close event

        :param reason: Reason for closing
        :return: None
        """

        stats = {}
        for mod in self.stats_modules:
            stats[mod.name] = mod.get_stats()

        self.logger.info("Dumping my stats (Close reason: {}):\n{}".format(reason, json.dumps(stats, indent=2)))

    def start_requests(self):
        """
        Process the page(s) given in spider_urls

        :return: Request instance for each url
        :rtype: scrapy.Request
        """

        meta = []
        meta_file = "{}.meta.json".format(self.settings.get('out_file_basename'))

        for url in self.settings.get('spider_urls'):
            # Fix urls starting not with scheme
            if not re.match(r'^https?:\/\/', url):
                url = "http://" + url

            parsed_url = urlparse(url)

            # Add crawl URLs to allowed_domains
            netloc = parsed_url.netloc
            if netloc not in self.allowed_domains:
                self.allowed_domains.append(netloc)

            req, _meta = self.create_request(url)
            yield req
            meta.append(_meta)

            if self.auto_www and not re.match(r'^www\.', netloc):
                url_www = "www." + netloc
                if url_www not in self.allowed_domains:
                    self.allowed_domains.append(url_www)

                ips = self.resolve(url)
                ips_www = self.resolve(url_www)

                # Check, if DNS records for both domains overlap. If not, also crawl www.domain.tld
                if not all(self.check_ip(ip, ips_www) for ip in ips):
                    self.logger.info("Adding www-URL to domains to be scanned: {} -> {}".format(url, url_www))

                    req, _meta = self.create_request(url_www)
                    yield req
                    meta.append(_meta)

        with open(meta_file, 'w') as f:
            f.write(json.dumps(
                {
                    "cfg": MACfg.get().get_config('singlecrawler'),
                    "run": meta,
                },
                indent=2
            ))

    def create_request(self, url: str, meta: Optional[dict] = None) -> (scrapy.Request, dict):
        """
        Helper for issuing a Scrapy request

        :param url:
        :param meta:
        :return:
        """
        # Fix urls starting not with scheme
        if not re.match(r'^https?:\/\/', url):
            url = "http://" + url
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc

        if parsed_url.scheme == "":
            url = "http://" + url

        if not meta:
            cur_meta = {
                'crawl_url': url,
                'netloc': netloc,
                'ip_list': self.resolve(netloc),
                'processed_urls': [],
                'queued_urls': [],
            }
        else:
            cur_meta = meta

        target_domain = cur_meta['netloc']

        if self.check_limit_reached(target_domain):
            req = None
        else:
            req = scrapy.Request(url=url, callback=self.parse, cb_kwargs={'meta': cur_meta})

        meta = copy.copy(cur_meta)
        del meta['processed_urls']
        del meta['queued_urls']

        return req, meta

    def parse(self, response: scrapy.http.response, meta: dict):
        """
        Parse the response of a request. Search for files and recursively follow links

        :param response: response instance
        :type response: scrapy.http.Response
        :param meta:
        :return: Either Request instance for followed links or dict containing infos about processed resource
        :rtype:  scrapy.http.Response | dict
        """

        filefilter = []
        crawl_depth = response.meta.get('depth')

        # Process this page
        yield self.process_resource(response.url, meta, crawl_depth)

        # Process files on this page
        for elt in self.le.extract_links(response):
            yield self.process_resource(elt.url, meta, crawl_depth)

        # Process linked files
        for ext in self.extensions:
            filefilter.append('a[href$="{}"]::attr(href)'.format(ext))

        files = response.css(", ".join(filefilter)).getall()
        for href in files:
            yield self.process_resource(response.urljoin(href), meta, crawl_depth)

        # Follow page links
        if int(self.settings.get('DEPTH_LIMIT')) > 0:
            for child in response.css('a::attr(href)').getall():
                if child not in files:
                    c_url = response.urljoin(child)
                    c_netlok = urlparse(c_url).netloc

                    if not self.check_skip(c_url, meta['processed_urls'], False, meta['queued_urls']):
                        if self.check_url(c_url) or self.check_ips(self.resolve(c_netlok), meta['ip_list']):
                            self.logger.info("Following link to " + c_url)
                            req, _ = self.create_request(c_url, meta)
                            yield req
                        else:
                            self.logger.info("NOT Following (external) link to " + c_url)

    def process_resource(self, url: str, meta: dict, crawler_depth: int) -> Optional[dict]:
        """
        Downloads the headers for the given url and accepts the file as valid, if conditions are fulfilled

        :param url: URL where the file is located
        :type url: str
        :param meta: Crawler Metadata (not the one from scrapy)
        :param crawler_depth: Current depth of the crawler
        :return: Dictionary containing gathered information
        :rtype: dict
        """

        netloc = meta['netloc']
        crawl_url = meta['crawl_url']
        ip_list = meta['ip_list']

        if self.check_limit_reached(netloc):
            return

        if self.check_skip(url, meta['processed_urls']):
            return

        domain_check = self.check_url(crawl_url)
        ip_check = self.check_ips(ip_list, self.resolve(urlparse(url).netloc))

        if not (domain_check or ip_check):
            self.logger.info("Skipping file {}: Domain match {}, IP match {} ".format(crawl_url, domain_check, ip_check))
            return

        # Init request
        r, peer_ip, estimate_length = self.download_file(url, meta, crawler_depth)

        if (not url == r.url) and self.check_skip(r.url, meta['processed_urls']):
            # Already processed. Logged in check_skip
            return

        domain_check = self.check_url(r.url)
        # Check if either IP of original or redirected url match the DNS record
        ip_check = self.check_ip(peer_ip, ip_list)

        if not (domain_check or ip_check):
            self.logger.info("Skipping file {}: Domain match {}, IP match {} ".format(r.url, domain_check, ip_check))
            return

        # Check content length
        content_length = None
        if r.headers.get('content-length'):
            content_length = int(r.headers.get('content-length'))
        elif estimate_length:
            content_length = estimate_length
            self.logger.info("Using estimated length (lower bound) of {} bytes for {} ".format(content_length, url))

        if content_length is None:
            self.logger.warning("Omitted {}: Unknown size".format(url))
        elif self.minsize > content_length:
            self.logger.info("Omitted {}: File too small (Size: {})".format(url, content_length))
        elif 0 < self.maxsize < content_length:
            self.logger.info("Omitted {}: File too large (Size: {})".format(url, content_length))
        else:
            if content_length > 200*1024:
                self.stats_matchcnt_gt200.inc(netloc, crawler_depth, url=url)
            else:
                self.stats_matchcnt_lt200.inc(netloc, crawler_depth, url=url)
            self.stats_bytes_found.inc(netloc, crawler_depth, url=url, by=content_length)
            self.logger.info("Accepting file {} ({}): IP match: {}".format(r.url, netloc, peer_ip))

            return {
                'scan_domain': netloc,
                'url': r.url,  # Use url from request, as this contains url after redirecting
                'size': content_length,
                'size_is_lower_bound': bool(estimate_length),
                'ts': datetime.now().isoformat('T', 'seconds'),
                'remote_ip': peer_ip,
                'crawler_depth': crawler_depth,
            }

    def download_file(self, url: str, meta: dict, crawler_depth: int) -> Tuple[requests.Response, str, Optional[int]]:
        netloc = meta['netloc']
        length = None

        # Init request
        r = requests.head(
            url,
            allow_redirects=True,
            stream=True,
            timeout=10,
            headers={
                'User-Agent': 'TCP-KPI-Measurements TUM-I8',
            }
        )
        peer_ip = self.get_peer_ip(r.raw._connection)
        self.stats_requestcnt.inc(netloc, crawler_depth, url=url)

        # If content_length is undefined, fall back to HTTP GET
        if int(r.headers.get('content-length', -1)) <= 0:
            r.close()
            self.logger.info("content-length for {} is zero or not set, falling back to GET".format(url))
            r = requests.get(
                url,
                allow_redirects=True,
                stream=True,
                timeout=10,
                headers={
                    'User-Agent': 'TCP-KPI-Measurements TUM-I8',
                }
            )
            peer_ip = self.get_peer_ip(r.raw._connection)
            length = 0
            for chunk in r.iter_content(2048):
                if chunk:  # filter out keep-alive new chunks
                    length += len(chunk)
                    if length > max(self.maxsize, 1024 * 512):
                        self.logger.info("{}: Cancelling download after {} bytes".format(url, length))
                        break

            self.logger.info("{}: Downloaded {} bytes".format(url, length))

            self.stats_requestcnt.inc(netloc, crawler_depth, url=url, useget=True)

        r.close()

        if not peer_ip:
            self.logger.error("Can't determine remote IP for {}".format(url))
            peer_ip = "0.0.0.0"

        return r, peer_ip, length

    def check_url(self, url: str) -> bool:
        """
        Check, whether url is in allowed_domains

        :param url: URL to be checked
        :type url: str
        :return: Is domain of url in allowed_domains
        :rtype: bool
        """
        # Check if our current url (with and without www.) is listed in allowed_domains
        netloc = urlparse(url).netloc
        netlocs = [netloc]
        if netloc.startswith('www.'):
            netlocs.append(str(netloc[4:]))
        else:
            netlocs.append("www." + netloc)

        valid = any(url in netlocs for url in self.allowed_domains)

        if not valid:
            self.logger.info("Skipping file {} ({}): Not in allowed_domains".format(url, netloc))

        return valid

    def check_ip(self, peer_ip: str, ip_list: List[str]) -> bool:
        return peer_ip in ip_list

    def check_ips(self, peer_ips: List[str], ip_list: List[str]) -> bool:
        return any(self.check_ip(ip, ip_list) for ip in peer_ips)

    def check_limit_reached(self, domain: str, close_spider: bool = True) -> bool:
        limit_reached = any([
            self.stats_requestcnt.is_limit_reached(domain, domain_rank=self.domain_rank),
            self.stats_matchcnt_lt200.is_limit_reached(domain),
            self.stats_matchcnt_gt200.is_limit_reached(domain),
        ])

        if limit_reached and close_spider:
            raise CloseSpider("Closing Spider: Limit reached")

        return limit_reached

    def resolve(self, domain: str) -> List[str]:
        return self.dns_lu.resolve(domain)

    def check_skip(self, url: str, processed_urls: list, scraped: bool = True, queued_urls: Optional[List] = None) -> bool:
        url = url.split('#')[0]
        if scraped:
            if url in processed_urls:
                self.logger.info("Skipping file {}: Already processed".format(url))
                return True
            else:
                if scraped:
                    processed_urls.append(url)
                return False
        else:
            if queued_urls is None:
                raise ValueError("Parameter queued_urls undefined")

            if url in queued_urls:
                self.logger.info("Skipping file {}: Already queued".format(url))
                return True
            else:
                queued_urls.append(url)
                return False

    def get_peer_ip(self, connection) -> Optional[str]:
        return get_socket_addr_remote(connection.sock, self.logger)
