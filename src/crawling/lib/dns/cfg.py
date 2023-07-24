from matool import MACfg


def dns_cfg():
    cfg = MACfg.get().add_goup('dns')
    cfg.add_prop(
        '-domains',
        nargs='+',
        help='Domains to be resolved',
    )
    cfg.add_prop(
        '-domain_file',
        help='Use file with domain names, instead',
    )
    cfg.add_prop(
        '-auto_www',
        type=bool,
        default=True,
        help='Automatically also resolve www subdomain'
    )

    MACfg.get().load()
    return MACfg.get().all_config()
