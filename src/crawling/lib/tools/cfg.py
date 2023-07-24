from argparse import Action, ArgumentParser, FileType
import io
import json
import logging
from typing import Dict


class CfgGroup:
    # Parameters that are hidden from argparse
    my_properties = ['any_required']

    def __init__(self, groupname: str, cfg_class: 'MACfg'):
        self.cfg_class: 'MACfg' = cfg_class
        self._config: Dict = {}
        self._argparse_args: Dict[str, Action] = {}
        self.name: str = groupname
        self.logger = logging.getLogger('macfg')

    def add_prop(self, *args, **kwargs) -> None:
        argparse_args = {}
        my_args = {}

        if len(args) == 0:
            raise ValueError('First argument must be name of parameter')

        name = self.name2argparse_name(args[0])

        # Distinguish between argparse args and matool args
        for k, v in kwargs.items():
            if k not in CfgGroup.my_properties:
                argparse_args[k] = v
            else:
                my_args[k] = v

        a = self.cfg_class.p.add_argument(name, **argparse_args)
        self._argparse_args[name] = a

    def is_default_value(self, name: str, val: str) -> bool:
        n = self.name2argparse_name_prefixed(name)
        return self._argparse_args[n].default == val

    def name2argparse_name(self, argname: str) -> str:
        # Prefix argument name with name of group if it has one
        if len(self.name) == 0:
            return argname
        else:
            prefix = ""
            old_name = ""
            for i in reversed(range(1, 2)):
                old_name = argname
                if old_name[:i] == "-":
                    prefix = "-"
                    old_name = old_name[i:]

            return "{}{}_{}".format(prefix, self.name, old_name)

    def name2argparse_name_prefixed(self, name: str) -> str:
        name = self.name2argparse_name(name)
        c = 0
        while name not in self._argparse_args.keys():
            name = "-" + name
            c += 1
            if c > 1:
                raise Exception("Argument {} is missing".format(name))

        return name

    def check_prop(self, name: str, val: str):
        name = self.name2argparse_name_prefixed(name)

        argp_action = self._argparse_args[name]

        # Do we have to do a type conversion (e.g. map to enum?)
        if argp_action.type:
            # Can there be multiple values for this argument?
            if argp_action.nargs == '+':
                ret = []
                for v in val.split(' '):
                    ret.append(argp_action.type(v))
            else:
                ret = argp_action.type(val)
        else:
            ret = val

        return ret

    def set_config(self, config: dict) -> None:
        """

        :param config:
        :return:
        """
        if config:
            self._config.update(config)

    def get_config(self) -> Dict:
        return self._config

    def get_argparse(self, name: str) -> Action:
        return self._argparse_args[name]


class MACfg:
    __instance = None
    p: ArgumentParser = ArgumentParser()

    @staticmethod
    def get():
        if not MACfg.__instance:
            MACfg.__instance = MACfg()

        return MACfg.__instance

    def __init__(self):
        self.groups: Dict[str, CfgGroup] = {}
        self.loaded: bool = False
        self.logger = logging.getLogger('macfg')

        g = self.add_goup('')
        g.add_prop(
            'dir',
            type=str,
            help="Working directory",
            default='.'
        )

        g.add_prop(
            'cfg',
            type=FileType('r'),
            help='Config file',
        )

    def add_goup(self, name: str):
        g: CfgGroup = CfgGroup(name, self)
        self.groups[name] = g

        return g

    def load(self):
        if self.loaded:
            return

        args = MACfg.get().p.parse_args()
        self._load_from_file(args.cfg)

        # Unpack argparse values from group_prop into group[prop]
        for arg, val in vars(args).items():
            try:
                group, arg = arg.split("_", 1)
            except ValueError:
                group = ""

            val_from_file = None
            if arg in self.groups[group].get_config():
                val_from_file = self.groups[group].get_config()[arg]

            if self.groups[group].is_default_value(arg, val):
                # The value from argparse is the default value, so we prefer the value read from configfile
                if val_from_file is None and val is not None:
                    self.groups[group].set_config({arg: val})
            else:
                # The argparse value differs from the default value, so we use it
                if val is not None:
                    self.groups[group].set_config({arg: val})

        self.loaded = True

    def all_config(self) -> dict:
        d = {}
        for n, g in self.groups.items():
            d[n] = g.get_config()

        return d

    def get_config(self, group: str) -> dict:
        return self.groups[group].get_config()

    def _load_from_file(self, f: 'io.TextIOWrapper'):
        conf = {}

        try:
            conf = json.load(f)
        except ValueError:
            self.logger.error("Invalid config file:")

        for n, g in self.groups.items():
            group_conf = conf.get(n)
            if group_conf is not None:
                parsed_conf = {}
                for key, val in group_conf.items():
                    parsed_conf[key] = g.check_prop(key, val)
            else:
                parsed_conf = group_conf
            g.set_config(parsed_conf)
