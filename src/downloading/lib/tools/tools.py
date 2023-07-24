import argparse
from enum import Enum
import logging
import re
from typing import Optional, Tuple, Union


# https://stackoverflow.com/a/17871737
re_v4 = re.compile(r'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])')
re_v6 = re.compile(
    r'('
    r'([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'          # 1:2:3:4:5:6:7:8
    r'([0-9a-fA-F]{1,4}:){1,7}:|'                         # 1::                              1:2:3:4:5:6:7::
    r'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'         # 1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
    r'([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'  # 1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
    r'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'  # 1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
    r'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'  # 1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
    r'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'  # 1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
    r'[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'       # 1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8
    r':((:[0-9a-fA-F]{1,4}){1,7}|:)|'                     # ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8 ::8       ::
    r'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'     # fe80::7:8%eth0   fe80::7:8%1     (link-local IPv6 addresses with zone index)
    r'::(ffff(:0{1,4}){0,1}:){0,1}'
    r'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
    r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|'          # ::255.255.255.255   ::ffff:255.255.255.255  ::ffff:0:255.255.255.255  (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
    r'([0-9a-fA-F]{1,4}:){1,4}:'
    r'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
    r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'           # 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
    r')'
)
# https://regexr.com/3au3g
re_host = re.compile(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]')


class ArgEnum(Enum):
    def __str__(self):
        return str(self.name)


class EnumType(object):
    """
    Factory for creating enum object types
    """

    # Adapted from https://bugs.python.org/issue25061#msg250703

    def __init__(self, enumclass):
        self.enums = enumclass

    def __call__(self, astring):
        name = self.enums.__name__
        try:
            return self.enums[astring]
        except KeyError:
            msg = "{}: use one of {}".format(name, ', '.join([t.name for t in self.enums]))
            raise argparse.ArgumentTypeError(msg)

    def __repr__(self):
        return "{} ({})".format(self.enums.__name__, ', '.join([t.name for t in self.enums]))


class AddrType(Enum):
    v4 = "IPv4"
    v6 = "IPv6"
    host = "host"
    unknown = None


def get_addr_type(addr: str) -> AddrType:
    if re_v4.match(addr):
        return AddrType.v4

    if re_v6.match(addr):
        return AddrType.v6

    if re_host.match(addr):
        return AddrType.host

    return AddrType.unknown


def get_socket_addr_remote(socket, logger: logging.Logger, get_port: bool = False) -> Union[str, Tuple[str, int]]:
    e_http = None
    e_https = None

    # HTTP case
    try:
        attrs = socket.getpeername()
    except AttributeError as _e_http:
        e_http = _e_http

        # HTTPS case
        try:
            attrs = socket.socket.getpeername()
        except AttributeError as _e_https:
            e_https = _e_https
            attrs = []

    if len(attrs) < 2:
        logger.error(
            "Getting remote address of socket failed. Got data: {} HTTP: {} || HTTPS: {}".format(attrs, e_http, e_https)
        )
        ip = None
        port = None
    else:
        ip = attrs[0]
        port = attrs[1]

    if get_port:
        return ip, port
    else:
        return ip


def get_socket_addr_local(socket, logger: logging.Logger, get_port: bool = False) -> Union[str, Tuple[str, int]]:
    e_http = None
    e_https = None

    # HTTP case
    try:
        attrs = socket.getsockname()
    except AttributeError as _e_http:
        e_http = _e_http

        # HTTPS case
        try:
            attrs = socket.socket.getsockname()
        except AttributeError as _e_https:
            e_https = _e_https
            attrs = []

    if len(attrs) < 2:
        logger.error(
            "Getting local address of socket failed. Got data: {} HTTP: {} || HTTPS: {}".format(attrs, e_http, e_https)
        )
        ip = None
        port = None
    else:
        ip = attrs[0]
        port = attrs[1]

    if get_port:
        return ip, port
    else:
        return ip
