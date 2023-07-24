'''
    This script extended from ma-brzoza
'''

from io import StringIO
import logging
import os
import signal
import subprocess
import time
from typing import Optional


class Capture:
    def __init__(self, dir: str, logger: logging.Logger):
        self.proc: Optional[subprocess.Popen] = None
        self.file: Optional[StringIO] = None
        self.h_stdout: Optional[StringIO] = None
        self.h_stderr: Optional[StringIO] = None
        self.dir: str = dir
        self.sleep_before: float = 5
        self.sleep_after: float = 5
        self.cap_rotate_interval: int = -1
        self.cap_rotate_size: int = 1000
        self.cap_snaplen: int = 100
        self.logger = logger
        modpath = os.path.abspath(os.path.dirname(__file__))
        self.compressor = os.path.join(modpath, "compress.sh")
    def start(self, interface: str):
        rot = []
        fname = "capture{}.pcap"
        f_stdout = "tcpdump{}.log"
        f_stderr = "tcpdump{}.err"

        if self.cap_rotate_interval > 0:
            rot.extend(["-G", str(self.cap_rotate_interval)])
            fname = fname.format("_%s")
            f_stdout = f_stdout.format("_%s")
            f_stderr = f_stderr.format("_%s")
        if self.cap_rotate_size > 0:
            rot.extend(["-C", str(self.cap_rotate_size)])
            fname = fname.format("")
            f_stdout = f_stdout.format("")
            f_stderr = f_stderr.format("")

        self.h_stdout = open(os.path.join(self.dir, f_stdout), 'w')
        self.h_stderr = open(os.path.join(self.dir, f_stderr), 'w')

        p_args = [
            "tcpdump",
            "-i", interface,
            "udp",
            "-w", os.path.join(self.dir, fname),
            *rot,
            "-s", str(self.cap_snaplen),
            "-z", self.compressor,
            "-Z", 'root'
        ]

        self.proc = subprocess.Popen(p_args, stdout=self.h_stdout, stderr=self.h_stderr)

        self.logger.info("Started capturing cmdline: '{}'".format(" ".join(p_args)))
        time.sleep(self.sleep_before)

    def stop(self):
        time.sleep(self.sleep_after)
        self.logger.info("Stopped capturing")
        self.proc.send_signal(signal.SIGTERM)
        self.proc.wait()
        if self.file:
            self.file.flush()
            self.file.close()

        if self.h_stdout:
            self.h_stdout.flush()
            self.h_stdout.close()

        if self.h_stderr:
            self.h_stderr.flush()
            self.h_stderr.close()
