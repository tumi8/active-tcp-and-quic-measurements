from datetime import datetime
from io import StringIO
import logging
import os
import signal
import subprocess
import time
from typing import Optional


class Capture:
    def __init__(self, dir: str, cfg: dict, logger: logging.Logger):
        self.proc: Optional[subprocess.Popen] = None
        self.file: Optional[StringIO] = None
        self.h_stdout: Optional[StringIO] = None
        self.h_stderr: Optional[StringIO] = None
        self.dir: str = dir
        self.sleep_before: float = cfg['sleep_before']
        self.sleep_after: float = cfg['sleep_after']
        self.cap_rotate_interval: int = cfg['cap_rotate_interval']
        self.cap_rotate_size: int = cfg['cap_rotate_size']
        self.cap_snaplen: int = cfg['cap_snaplen']
        self.logger = logger
        modpath = os.path.abspath(os.path.dirname(__file__))
        self.compressor = os.path.join(modpath, "compress.sh")

    def __start_old(self, interface: str):
        self.file = open(os.path.join(self.dir, "capture.csv"), 'w')
        self.proc = subprocess.Popen(
            [
                "tshark",
                "-i", interface,
                "-w", os.path.join(self.dir, "capture.pcap"),
                "-E", "separator=;",
                "-T", "fields",
                "-E", "header=y",
                "-e", "frame.time_epoch",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "ip.len",
            ],
            stdout=self.file,
        )
        time.sleep(self.sleep_before)

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
            "tcp",
            "port", "80",
            "or",
            "port", "443",
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
