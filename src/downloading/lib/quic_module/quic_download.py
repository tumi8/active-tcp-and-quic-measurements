'''
    Module: Download file using quic
    Required: aioquic
    Input:
    	wdir: output directory
    	interface: interface
    	url: download url : Note must contain https
    Output file:
        meta_info.json: Download stats
        header.info: H3 header response
        capture.pcap: pcap file
        qlog: qlog stored in zst
        seckey.log: secrets
        capture, downloader, quic, tcpdum logs file
'''
import os
import json
import sys
import logging
import subprocess

from lib.quic_module.util.logger import *
from lib.quic_module.util.capture import Capture


def aioquic_download(wdir, interface, url):

    logging.captureWarnings(True)
    logger_cpt = get_logger('capture', wdir, logging.DEBUG)
    logger_cpt.propagate = False
    c = Capture(wdir,logger_cpt)
    try:
        c.start(interface)
        cmd = ["python3", "lib/quic_module/http3_client.py", "--ca-certs", "lib/quic_module/util/pycacert.pem", "--output-dir", wdir, "--quic-log", wdir, "--secrets-log", "{}/seckey.log".format(wdir), url]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        try:
            proc.wait(timeout=15)
        except Exception as e:
            proc.kill()
            logging.error(e)
    except Exception as req_err:
        logging.error(req_err)
    finally:
        c.stop()
        logger_cpt.removeHandler(logger_cpt.handlers[0])
    subprocess.run("zstd --rm -9 {}/*.qlog".format(wdir), shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not os.path.exists("{}/header.info".format(wdir)):
        sys.stdout.write("Aioquic download failed! Please refer to {}/quic_download.log \n".format(wdir))
        logging.error("Aioquic download failed! Please refer to {}/quic_download.log".format(wdir))
    else: 
        sys.stdout.write("Aioquic download succeeded. \n")
        logging.info("Aioquic download succeeded")

def quiche_download(wdir, interface, url):

    logging.captureWarnings(True)
    logger_cpt = get_logger('capture', wdir, logging.DEBUG)
    logger_cpt.propagate = False
    c = Capture(wdir,logger_cpt)
    try:
        c.start(interface)
        cmd = ["../quiche/target/debug/quiche-client","--dump-json","--idle-timeout","10000", "--", url]
        with open(wdir+"/dump.json", "w") as dump:
            proc = subprocess.Popen(cmd, stdout=dump)
        try:
            proc.wait(timeout=15)
        except Exception as e:
            proc.kill()
            logging.error(e)
    except Exception as req_err:
        logging.error(req_err)
    finally:
        c.stop()
        logger_cpt.removeHandler(logger_cpt.handlers[0])
    subprocess.run("zstd --rm -9 {}/*.qlog".format(wdir), shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try: 
        with open(wdir+"/dump.json", "r") as dump: 
            data = json.load(dump)
        if data['entries'][0]['response']['headers'][0]['value'] == '200': 
            sys.stdout.write("Quiche download succeeded! \n")
            logging.info("Quiche download succeeded!")
        else: 
            sys.stdout.write("Quiche download failed! Status =! 200, but: ", data['entries'][0]['response']['headers'][0]['value'])
            logging.error("Quiche download failed! Status =! 200, but: ", data['entries'][0]['response']['headers'][0]['value'])
    except Exception as e:
        sys.stdout.write("Quiche download failed! No json was dumped \n")
        logging.error("Quiche download failed! No json was dumped")


