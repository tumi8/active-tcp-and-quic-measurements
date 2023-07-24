from collections import defaultdict
from copy import deepcopy
from enum import Enum, auto
import logging
from typing import Optional, Tuple


class MaStatsProp:
    name = ""

    def __init__(self, *args, **kwargs):
        self._logger = kwargs.get('logger')
        self._stats = {}

    def is_limit_reached(self, domain: str) -> bool:
        raise NotImplemented()

    def _check_init_domain(self, domain: str):
        if domain not in self._stats:
            self._stats[domain] = defaultdict(int)

    def inc(self, domain: str, depth: int, by: int = 1, url: str = None, useget: bool = False):
        self._check_init_domain(domain)
        self._stats[domain][depth] += by
        self._logger.debug('Increasing {} for {} at depth {} ({}). Url: {} GET: {}'.format(
            self.name, domain, depth, self._stats[domain][depth], url, useget
        ))

    def get_all(self, domain: str) -> dict:
        self._check_init_domain(domain)
        return self._stats[domain]

    def get(self, domain: str, depth: Optional[int] = None) -> int:
        if depth is None:
            return sum(self.get_all(domain).values())

        return self.get_all(domain)[depth]

    def _log_limit_warning(self, domain: str,  warning: str):
        self._logger.warning("Cancelling for domain {}: {}".format(domain, warning))

    def get_stats(self):
        return self._stats


class RequestCnt(MaStatsProp):
    name = "RequestCount"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_crawls_per_depth = kwargs.get('max_crawls_per_depth', 1000)
        self.max_crawls_per_depthTop = kwargs.get('max_crawls_per_depthTop', 5000)
        self.total_max_crawls = kwargs.get('total_max_crawls', 50000)

    def is_limit_reached(self, domain: str, **kwargs) -> bool:
        limit_reached = False
        domain_rank = kwargs.get('domain_rank', 101)

        if domain_rank <= 100:
            crawl_limit = self.max_crawls_per_depthTop
        else:
            crawl_limit = self.max_crawls_per_depth

        if any([v > crawl_limit for v in self.get_all(domain).values()]):
            self._log_limit_warning(domain, "More than {} links on any depth crawled".format(self.max_crawls_per_depth))
            limit_reached = True

        if self.get(domain) > self.total_max_crawls:
            self._log_limit_warning(domain, "More than {} links crawled in total".format(self.total_max_crawls))
            limit_reached = True

        return limit_reached


class MatchCnt(MaStatsProp):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_match_count = kwargs.get('max_crawls_per_depth', 10)
        self.name = kwargs.get('name', 'MatchCount')

    def is_limit_reached(self, domain: str) -> bool:
        limit_reached = False

        if self.get(domain) >= self.max_match_count:
            self._log_limit_warning(domain, "More than {} matches found".format(self.max_match_count))
            limit_reached = True

        return limit_reached


class BytesFound(MaStatsProp):
    name = "BytesFound"

    def is_limit_reached(self, domain: str) -> bool:
        return False


class MaStats:
    def __init__(self, logger: logging.LoggerAdapter):
        self.logger = logger



    """
    def inc(self, prop: MaStatsProperties, domain: str, depth: int, by: int = 1, url: str = None, useget: bool = False):
        self.props[prop.name]
        self._check_init_domain(domain)
        self._stats[domain][prop.value][depth] += by
        self.logger.debug('Increasing {} for {} at depth {} ({}). Url: {} GET: {}'.format(
            prop.value, domain, depth, self._stats[domain][prop.value][depth], url, useget
        ))

    def get_all(self, prop: MaStatsProperties, domain: str) -> dict:
        self._check_init_domain(domain)
        return self._stats[domain][prop.value]

    def get(self, prop: MaStatsProperties, domain: str, depth: Optional[int] = None) -> int:
        if depth is None:
            return sum(self.get_all(prop, domain).values())

        return self.get_all(prop, domain)[depth]

    def get_stats(self):
        return json.dumps(self._stats, indent=2)
    """
