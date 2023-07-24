# Python code for Refined TCP RCA
# utility functions file

#!/usr/bin/python
import os
import sys

def get_output_dir_name(flow_num, output_folder):
    # Create directories for every flow
    output_dir = os.path.join(output_folder)
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    flow_dir = os.path.join(output_dir, "Flow_"+str(flow_num))
    if not os.path.exists(flow_dir):
        os.mkdir(flow_dir)
    return flow_dir

def get_input_dir_name(flow_num, directory_name):
    # Create directories for every flow
    input_dir = os.path.join(directory_name)
    if not os.path.exists(input_dir):
        sys.exit("Input directory does not exist")
    flow_dir = os.path.join(input_dir, "Flow_"+str(flow_num))
    if not os.path.exists(flow_dir):
        sys.exit("Input flow directory does not exist")
    return flow_dir

def is_list_decreasing_order(item_list):
    if (type(item_list) == int) or (len(item_list) <= 1):
        return 1
    sorted_list = item_list[:]
    sorted_list.sort(reverse=True)
    prev = sorted_list[0]
    for entry in sorted_list:
        if (entry > prev):
            continue
        else:
            return 0
    return 0
