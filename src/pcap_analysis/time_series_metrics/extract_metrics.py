# Python code for Extracting
# TCP flow metrics
# main program file

#!/usr/bin/python

import argparse
import json

from time_series_metrics.helper.process_pcap import *
from time_series_metrics.helper.parse_config import *
from time_series_metrics.helper.json_helper import *
from time_series_metrics.helper.timeseries import *

# Global list to store all flows
flows = []


def main(conf, path): 
	
    flows.clear()	
    sys.stdout.write("\nParsing Config")
    config = parse_config(conf)

    # Process Pcap to extract metrics
    sys.stdout.write("\nProcess pcap started")
    process_pcap(path, config, flows)
    sys.stdout.write("\nProcess pcap done")

    # Clean up and update flows
    sys.stdout.write("\nRemove unsatisfactory flows")
    update_flows(config, flows)

    # Generate Timeseries
    sys.stdout.write("\nTimeseries generating")
    generate_all_timeseries(config, flows)

    return flows

