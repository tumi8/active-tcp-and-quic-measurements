# Configuration parser file
#!/usr/bin/python

import sys
import json
import yaml

def parse_config(config_file):
    config = {}
    with open(config_file) as conf_file:
        if "json" in config_file:
        # load JSON file
            try:
                config = json.load(conf_file)
            except ValueError as err:
                sys.exit("Invalid json format in configuration file")
        elif "yaml" in config_file:
        # load YAML file
            try:
                config = yaml.safe_load(conf_file)
            except yaml.YAMLError as err:
                sys.exit("Invalid yaml format in configuration file")
    return config
