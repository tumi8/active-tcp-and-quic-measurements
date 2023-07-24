# Python code for Refined TCP RCA
# main program file

#!/usr/bin/python

import argparse
import json

from time_series_metrics.helper.custom_rca_approach import *
from time_series_metrics.helper.siekkinen_approach import *
from time_series_metrics.helper.parse_config import *
global_flows = []

def main(conf, flows, path):

    config = parse_config(conf)
    global_flows= flows
    # Run IM algorithm
    run_IM_algorithm(config, global_flows) 

    # Perform RCA toolkit of siekkinen
    if config["Siekkinen"]["enabled"] == 1:
        perform_siekkinen_rca(config, global_flows, path)

    perform_custom_rca(config, global_flows, path)
