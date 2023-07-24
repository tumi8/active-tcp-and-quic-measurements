## from ma-brzoza/code/schwarzenberg-tools/crawler/

from argparse import FileType
from datetime import datetime
import re
import os
import pathlib
from tools import MACfg, ArgEnum, EnumType
from urllib.parse import urlparse


def singlecrawler_cfg() -> dict:
    name = 'singlecrawler'
    cfg = MACfg.get().add_goup(name)
    cfg.add_prop(
        '-url',
        help='Base url to crawl'
    )
    cfg.add_prop(
        '-auto_www',
        type=bool,
        default=True,
        help='Automatically also scan www subdomain'
    )
    cfg.add_prop(
        '-depth',
        default=1,
        type=int,
        help='Follow links up to given depth (0 = Do not follow links)'
    )
    cfg.add_prop(
        '-minsize',
        default=102400,
        type=int,
        help='Omit all files in output that are smaller than the specified size'
    )
    cfg.add_prop(
        '-maxsize',
        default=-1,
        type=int,
        help='Omit all files in output that are larger than the specified size (-1: Include all)'
    )
    cfg.add_prop(
        '-format',
        default='csv',
        choices=['json', 'jsonlines', 'csv', 'xml'],
        help='Output format for found resources'
    )
    cfg.add_prop(
        '-log2stdout',
        type=bool,
        default=False,
        help='Do not log to file (for debugging)'
    )
    cfg.add_prop(
        '-domain_rank',
        type=int,
        default=None,
        help='Rank of the domain to be crawled (used internally)'
    )

    MACfg.get().load()
    c_cfg = MACfg.get().get_config(name)
    g_cfg = MACfg.get().get_config('')

    return {
        '': g_cfg,
        name: c_cfg
    }


def batchcrawler_cfg() -> dict:
    name = 'batchcrawler'
    cfg = MACfg.get().add_goup(name)
    cfg.add_prop(
        '-urls',
        nargs='+',
        help='Base url to crawl'
    )
    cfg.add_prop(
        '-url_file',
        type=FileType('r'),
        help='CSV file with rank-domain mapping of domains to crawl'
    )
    cfg.add_prop(
        '-nparallel',
        default=5,
        type=int,
        help='How many crawlers run in parallel at maximum (1 per specified domain)'
    )
    cfg.add_prop(
        '-spawn_wait',
        default=2,
        type=int,
        help='How long to wait before spawning the next crawler instance after a previous finished'
    )

    MACfg.get().load()
    c_cfg = MACfg.get().get_config(name)
    g_cfg = MACfg.get().get_config('')

    # Create per-crawl subfolder
    g_cfg['dir'] = os.path.join(g_cfg['dir'], datetime.now().isoformat('T', 'seconds').replace(':', '-'))
    pathlib.Path(g_cfg['dir']).mkdir(parents=True, exist_ok=True)

    return {
        '': g_cfg,
        name: c_cfg
    }


def scrapy_cfg(parsed_cfg: dict) -> dict:
    c_cfg = parsed_cfg['singlecrawler']
    g_cfg = parsed_cfg['']

    ts = datetime.now().isoformat('T', 'seconds').replace(':', '-')
    opath = os.path.join(g_cfg['dir'], c_cfg['url'])
    pathlib.Path(opath).mkdir(parents=True, exist_ok=True)
    out_file_name = "{}".format(ts)

    feed_file = os.path.join(opath, "{}.{}".format(out_file_name, c_cfg['format']))
    if not c_cfg['log2stdout']:
        log_file = os.path.join(opath, "{}.log".format(out_file_name))
    else:
        log_file = None

    # Global scrapy config
    return {
        'FEED_FORMAT': c_cfg['format'],
        'FEED_URI': feed_file,
        'LOG_FILE': log_file,
        'DOWNLOAD_TIMEOUT': 30,
        'DEPTH_LIMIT': c_cfg['depth'],
        'ROBOTSTXT_OBEY': True,
        'ROBOTSTXT_USER_AGENT': 'Googlebot',
        'USER_AGENT': 'TCP-KPI-Measurements TUM-I8',
        # Custom args
        'spider_urls': [c_cfg['url']],
        'out_file_basename': os.path.join(opath, out_file_name),
    }


def spider_cfg(parsed_cfg: dict) -> dict:
    c_cfg = parsed_cfg['singlecrawler']
    g_cfg = parsed_cfg['']

    # Config for our Spider (mycrawler_... is specific for code for further analysis)
    return {
        'mycrawler_auto_www': c_cfg['auto_www'],
        'mycrawler_minsize': c_cfg['minsize'],
        'mycrawler_maxsize': c_cfg['maxsize'],
        # Extensions of additional files, that probably fit our size requirements
        # They are linked via <a href=""> (not src="")
        'mycrawler_extensions': ['.pdf', '.doc', '.docx'],
        'mycrawler_outdir': g_cfg['dir'],
        'mycrawler_domain_rank': c_cfg['domain_rank'],
    }
