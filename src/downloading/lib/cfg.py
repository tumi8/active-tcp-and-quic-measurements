from tools import MACfg, ArgEnum, EnumType


class IPversion(ArgEnum):
    v4 = 4
    v6 = 6


def downloader_cfg():
    cfg = MACfg.get().add_goup('downloader')
    cfg.add_prop(
        '-urls',
        nargs='+',
        help='URLs to be Downloaded'
    )
    cfg.add_prop(
        '-url_file',
        help='File with URLs to be Downloaded'
    )
    cfg.add_prop(
        '-interface',
        help='Interface to be used for capturing'
    )
    cfg.add_prop(
        '-sleep_before',
        type=float,
        default=1,
        help='Start capturing n seconds before downloading'
    )
    cfg.add_prop(
        '-sleep_between',
        type=float,
        default=3,
        help='Wait n seconds between downloads'
    )
    cfg.add_prop(
        '-sleep_after',
        type=float,
        default=1,
        help='Wait n seconds after every download'
    )
    cfg.add_prop(
        '-download_limit',
        type=int,
        default=10*1024*1024,
        help='Stop capturing after downloading n bytes'
    )
    cfg.add_prop(
        '-max_download_domains',
        type=int,
        default=-1,
        help='Download from max n domains (-1 = no limit)'
    )
    cfg.add_prop(
        '-cap_rotate_interval',
        type=int,
        default=-1,
        help='TCPdump file rotation interval (seconds) (negative values disable this rotation)'
    )
    cfg.add_prop(
        '-cap_rotate_size',
        type=int,
        default=1000,
        help='TCPdump file rotation after size (in MB; 10^6 bytes) (negative values disable this rotation)'
    )
    cfg.add_prop(
        '-cap_snaplen',
        type=int,
        default=100,
        help='TCPdump snaplength (bytes)'
    )
    cfg.add_prop(
        '-ipv',
        help='List of IP versions to use for downloading',
        nargs='+',
        type=EnumType(IPversion),
        choices=IPversion,
        default=[IPversion.v4, IPversion.v6]
    )
    cfg.add_prop(
        '-v4_blacklist',
        type=str,
        default=None,
        help='File containing blacklisted IPv4 Networks',
    )
    cfg.add_prop(
        '-v6_blacklist',
        type=str,
        default=None,
        help='File containing blacklisted IPv6 Networks',
    )

    MACfg.get().load()
    return MACfg.get().all_config()
