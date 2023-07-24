import json
import os
import subprocess
import sys
import argparse
import pandas as pd
from datetime import datetime

MAX_RETRY = [1] # number of retry for in range eg: 2 in 1-1000, 2 in 1001-5000 , 4 in ...
MAX_FILE = 100000  # max number of unique domain for each range
rank_range_list = [(0, 100000)]
colnames=['scan_domain', 'url', 'size', 'size_is_lower_bound', 'ts', 'remote_ip', 'crawler_depth']

def load_domain_list(file):
    colnames = ['domain']
    df = pd.read_csv(file, names=colnames, header=None)
    return df

def load_alexa_top_list():
    colnames = ['Rank', 'Website']
    df = pd.read_csv('top-1m.csv', names=colnames, header=None)
    return df

def save_dict_as_json(dictionary, path, filename):
    os.makedirs(path, exist_ok=True)
    with open(path + '/' + filename, 'w') as out:
        json.dump(dictionary, out, indent=4, sort_keys=True)

def get_config_file(path, min, max, depth):
    return {"batchcrawler": {
        "urls": [],
        "nparallel": 50,
        "url_file": path
    }, "singlecrawler": {
        "depth": depth, "minsize": min, "maxsize": max
    }}

def process_domainsonly(min, max, depth, file, max_files):
    ranked = False
    print("only expecting domains and no ranks as input")

    sys.stdout.write("\n=======Starting Crawler ========")

    domains = load_domain_list(file)
    run_id = datetime.now().isoformat('T', 'seconds').replace(':', '-')
    cur_dir = os.getcwd()

    os.makedirs(run_id + '/config', exist_ok=True)
    os.makedirs(run_id + '/crawled_domains', exist_ok=True)
    os.makedirs(run_id + '/crawled_files', exist_ok=True)
    os.makedirs(run_id + '/result', exist_ok=True)

    domains_list = domains["domain"].values.tolist()
    sys.stdout.write("\nInput: list of {} domains, no ranks\n".format(len(domains_list)) )

    run_dir = run_id + "/crawled_files"

    if max_files == 0:
        max_files = len(domains_list)

    #File to store the result
    output_file_name = "temp_no_rank_size_{}_{}.csv".format(min, max)
    re_try_count = 0
    file_count = 0
    _df_local = pd.DataFrame()

    # avoid to hit upper limit of crawling: 
    while file_count < MAX_FILE:
        re_try_count =+ 1
        print(len(pd.concat([domains, _df_local]).drop_duplicates(keep=False)))
        _df_cur = pd.concat([domains, _df_local]).drop_duplicates(keep=False).sample(n=500)

        #Update
        _df_local =  pd.concat([_df_local, _df_cur], ignore_index=True, sort=True)
        crawl_run_domains = "crawled_domains_run_{}.csv".format(re_try_count)
        _df_cur.to_csv(run_id + "/crawled_domains/" + crawl_run_domains, header=False, index=False)

        # Genrate config based on sample of domain list
        csv_path = cur_dir + "/" + run_id + "/crawled_domains/" + crawl_run_domains
        config = get_config_file(csv_path, min, max, depth)
        config_file_name = "config_run_{}.json".format(re_try_count)
        save_dict_as_json(config, run_id + '/config', config_file_name)

        # Create a dir to store the result of this  run
        subrun_dir = run_dir + "/run_{}".format(re_try_count)
        os.makedirs(subrun_dir, exist_ok=True)

        sys.stdout.write("\n=======Crawling domain list for files of size in range {} B to {} B ========".format(min, max))
        
        cmd = ['python3', 'lib/batchcrawler_norank.py', cur_dir + '/'+ run_dir + '/', cur_dir + '/' + run_id + '/config/' + config_file_name]
      
        print(cmd)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE) 
        output, error = p.communicate()

        os.system("cat {}/**/**/*.csv >> {}/result/{}".format(run_dir, run_id,output_file_name))
        #clean the file
        os.system("sed -i '/scan_domain/d' {}/result/{}".format(run_id,output_file_name))
        try:
            file_count = pd.read_csv("{}/result/{}".format(run_id,output_file_name),names=colnames, header=None).scan_domain.unique().size
        except:
            pass

    with open(run_id + "/run_info.txt", "w") as text_file:
        text_file.write("\n MinSize - {}, MaxSize - {}, Depth - {}, Min. Number of File {}".format(min, max, depth ,MAX_FILE))


def process_alexa(min, max, depth):
    ranked = True

    sys.stdout.write("\n===============================")
    sys.stdout.write("\n=======Starting Crawler========")
    sys.stdout.write("\n===============================")
    df = load_alexa_top_list()
    run_id = datetime.now().isoformat('T', 'seconds').replace(':', '-')
    cur_dir = os.getcwd()
    os.makedirs(run_id + '/config', exist_ok=True)
    os.makedirs(run_id + '/alexalist', exist_ok=True)
    os.makedirs(run_id + '/crawled_files', exist_ok=True)
    os.makedirs(run_id + '/result', exist_ok=True)

    for id_outer, ranks in enumerate(rank_range_list):
        rank_dir = run_id + "/crawled_files/rank_{}_{}".format(ranks[0], ranks[1])
        os.makedirs(rank_dir, exist_ok=True)
        #File to store the result
        output_file_name = "temp_rank_{}_{}_size_{}_{}.csv".format(ranks[0], ranks[1], min, max)
        re_try_count = 0
        file_count = 0
        _df_local = pd.DataFrame()
        # Get the domains based on rank
        if ranks[1] == "END":
            _df_rank = df[ranks[0]:].sort_values(by=['Rank'], ascending=True)
        else:
            _df_rank = df[ranks[0]:ranks[1]].sort_values(by=['Rank'], ascending=True)

        while re_try_count < MAX_RETRY[id_outer] and file_count < MAX_FILE:
            re_try_count+=1
            # Diff  (_df_rank - _df_local) then sample
            _df_cur = pd.concat([_df_rank, _df_local, _df_local]).drop_duplicates(keep=False).sample(n=500)
            #Update
            _df_local =  pd.concat([_df_local, _df_cur], ignore_index=True, sort=True)
            alexa_file_name = "alexa_class_{}_{}_try{}.csv".format(ranks[0], ranks[1], re_try_count)
            _df_cur.to_csv(run_id + "/alexalist/" + alexa_file_name, header=False, index=False)

            # Genrate config based on sample alexalist and user input
            csv_path = cur_dir + "/" + run_id + "/alexalist/" + alexa_file_name
            config = get_config_file(csv_path, min, max, depth)
            config_file_name = "config_{}_{}_try{}.json".format(ranks[0], ranks[1], re_try_count)
            save_dict_as_json(config, run_id + '/config', config_file_name)

            # Create a dir to store the result of this  run

            run_dir = rank_dir + "/run{}".format(re_try_count)
            os.makedirs(run_dir, exist_ok=True)

            sys.stdout.write(
                "\n=======Crawling for files from alexa top list between rank {} to {} for size in range {} B to {} B ========".format(
                    ranks[0], ranks[1], min, max))
            cmd = ['python3', 'lib/batchcrawler.py',
                   cur_dir + '/'+ run_dir + '/', cur_dir + '/' + run_id + '/config/' + config_file_name]
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            output, error = p.communicate()

            os.system("cat {}/**/**/*.csv >> {}/result/{}".format(run_dir, run_id,output_file_name))
            #clean the file
            os.system("sed -i '/scan_domain/d' {}/result/{}".format(run_id,output_file_name))
            try:
                file_count = pd.read_csv("{}/result/{}".format(run_id,output_file_name),names=colnames, header=None).scan_domain.unique().size
            except:
                pass

    git_hash_str = ""
    try:
        git_hash_str = subprocess.check_output(["git log crawler_based_on_Size.py"], shell=True).decode("utf-8")

    except:
        pass
    with open(run_id + "/run_info.txt", "w") as text_file:
        text_file.write(git_hash_str)
        text_file.write("\n MinSize - {}, MaxSize - {}, Depth - {}, Min. Number of File {}".format(min, max,depth ,MAX_FILE))

def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('--min', help='minimum file size', default=1000000, type=int)
    parser.add_argument('--max', help='maximum file size', default=10000000, type=int)
    parser.add_argument('--depth', help='maximum crawler depth', default=5, type=int)
    parser.add_argument('--input', help='input format', default="domains", type=str)
    parser.add_argument('--file', help='input file', default="./targets.csv", type=str)
    parser.add_argument('--max_files', help='number of max files resultin from crawling', default=0, type=str)

    args = parser.parse_args()
    if args.input == "rankdomains":
        process_alexa(args.min, args.max, args.depth)
    if args.input == "domains":
        process_domainsonly(args.min, args.max, args.depth, args.file, args.max_files)

if __name__ == '__main__':
    run()
