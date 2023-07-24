"""
    Utility script : Post processing, Generate TCP KPIs from PCAP and store the stats of all runs in CSV file
    Input :
        1. Path to download runs
        2. Number of process
        3. Output path to store the result
    Output:
        1. Individual KPI json file in the run directory
        2. CSV file in output directory

What we extract: 


"""
from datetime import datetime
import glob
import pandas as pd
import os
import subprocess
import json
import numpy as np
import decimal
from collections import defaultdict, OrderedDict
import multiprocessing as mp
import argparse
import logging

from lib.result import Result 


class CustomEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, list):
            emp_list = []
            for x in o:
                emp_list.append(x.__dict__)
            return emp_list
        elif isinstance(o, decimal.Decimal):
            return float(o)
        else:
            return o.__dict__

def get_kpi(basepath, domain, run_id):

    
    result = Result(basepath, domain, run_id, False)

    print(result)

    return result


def get_download_runs(path: str):
    dirslist = glob.glob("{}/*/".format(path))
    runs = []
    for run in dirslist:
        runs.append(run.split("/")[-2])
    return runs


def save_dict_as_json(run_kpi_dic, path, filename, encoder=None):
    # print(run_kpi_dic)
    os.makedirs(path, exist_ok=True)
    with open(path + "/" + filename, "w") as out:
        json.dump(run_kpi_dic, out, indent=4, sort_keys=True, cls=encoder)


def split_list(_list, parts):
    lists = defaultdict(list)
    for i in range(0, parts):
        lists[i] = []
    for i in range(0, len(_list)):
        lists[i % parts].append(_list[i])
    return lists


def _process_pcap(*args):
    [basepath, domains, id, output] = args[0]
    result_df = pd.DataFrame()
    l = len(domains)
    for index, domain in enumerate(domains):
        if index % 10 == 0:
            logging.info(
                "\n Process id: {}, Domain processed: {}, Domain left: {}".format(
                    id, index, l - index
                )
            )
        num_runs_list = glob.glob(
            "{}/{}/**/meta_lines.txt".format(basepath + "/tcp_downloads", domain)
        )
        # print(num_runs_list)
        for run in num_runs_list:
            run_id = run.split("/")[-2]
            print(run)
            print(run_id)

            run_kpi = get_kpi(basepath, domain, run_id)

            if run_kpi.capture == None: 
                continue

            tcp_path = basepath + "/tcp_downloads/" + domain + "/" + run_id
            save_dict_as_json(run_kpi.get_output_dict(), tcp_path, "run_kpi.json", CustomEncoder)
            
            df_dictionary = pd.DataFrame([run_kpi.get_output_dict()])
            result_df = pd.concat([result_df, df_dictionary], ignore_index=True)
    
    result_df.to_csv("{}/all_kpi_stats_id{}.csv".format(output, id))


def run():
    
    debug = False 
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--path", help="Directory Path", type=str, required=True)
    parser.add_argument(
        "-n", "--process", default=1, help="Number of process", type=int
    )
    parser.add_argument(
        "-o", "--output", help="Path to output folder", type=str, required=True
    )
    parser.add_argument('-d', help="only process a single pcap for debuging", action='store_true')
    
    args = parser.parse_args()
    print(args)

    if args.d:

        result = Result(args.path, "", "", True)
        print(result)
        
        return 

    # Create output directory
    if not os.path.exists(args.output):
        os.makedirs(args.output + "/logs")

    basepath = args.path
    nprocs = args.process

    #  Logging options
    logging.basicConfig(
        filename=args.output + "/kpi_processing.log", level=logging.INFO
    )

    pvars_ = []
    domains_lists = get_download_runs(basepath + "/tcp_downloads")
    split_domain_list = split_list(domains_lists, nprocs)

    logging.info("\n=======================================================")
    logging.info("\n Base Path : {}".format(basepath))
    logging.info("\n Number of process : {}".format(nprocs))
    logging.info("\n Number of domains : {}".format(len(domains_lists)))
    logging.info("\n Output Path : {}".format(args.output))
    logging.info("\n=======================================================")

    for i in range(0, nprocs):
        pvars_.append([basepath, split_domain_list[i], i, args.output])

    # start process
    logging.info("\n Script started at: {}".format(datetime.now()))
    pool = mp.Pool(processes=nprocs)
    try:
        pool.map(_process_pcap, pvars_)
    except Exception as e:
        pool.terminate()
        raise Exception(e)
    finally:
        pool.close()
    logging.info("\n Script stopped at: {}".format(datetime.now()))


if __name__ == "__main__":
    run()
