import argparse
import sys
from datetime import datetime
import os
import subprocess
import logging
import json
import pandas as pd
import decimal
import logging
from lib import post_processing
from lib.quic_module.quic_download import *


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


def get_json_data(path):
    with open(path) as f:
        data = json.load(f)
    return data


def configure_ws(tcp_rmem, rmem_default, rmem_max):
    subprocess.run(
        "bash -c 'echo \"{} {} {}\" > /proc/sys/net/ipv4/tcp_rmem'".format(
            tcp_rmem, rmem_default, rmem_max
        ),
        shell=True,
    )
    subprocess.run(
        "bash -c 'echo {} > /proc/sys/net/core/rmem_default'".format(rmem_default),
        shell=True,
    )
    subprocess.run(
        "bash -c 'echo {} > /proc/sys/net/core/rmem_max'".format(rmem_max), shell=True
    )


def configure_client_tcp_stack(ecn, sack, tfo, ws):

    logging.info("Configuring Server TCP Stack")
    logging.info("Explicit Congestion Notification is enabled : {}".format(ecn))
    if ecn is True:
        subprocess.run("sysctl -w net.ipv4.tcp_ecn=1", shell=True)
    else:
        subprocess.run("sysctl -w net.ipv4.tcp_ecn=0", shell=True)
    logging.info("Selective Acknowledgments is enabled : {}".format(sack))
    if sack is True:
        subprocess.run("sysctl -w net.ipv4.tcp_sack=1", shell=True)
    else:
        subprocess.run("sysctl -w net.ipv4.tcp_sack=0", shell=True)

    logging.info("TCP Fast Open is enabled : {}".format(tfo))
    if tfo is True:
        subprocess.run("sysctl -w net.ipv4.tcp_fastopen=1", shell=True)
    else:
        subprocess.run("sysctl -w net.ipv4.tcp_fastopen=0", shell=True)

    logging.info("Window Scale : {}x".format(ws))

    # no window sclaing
    if ws == 0:
        subprocess.run("sysctl -w net.ipv4.tcp_window_scaling=0", shell=True)

    # window sclaing with factor 2ˆ1     
    if ws == 1:
        subprocess.run("sysctl -w net.ipv4.tcp_window_scaling=1", shell=True)
        configure_ws(4096, 131070, 131070)

    # window sclaing with factor 2ˆ2     
    if ws == 2:
        subprocess.run("sysctl -w net.ipv4.tcp_window_scaling=1", shell=True)
        configure_ws(4096, 262144, 262144)
 
    # window sclaing with factor 2ˆ3   
    if ws == 3:
        subprocess.run("sysctl -w net.ipv4.tcp_window_scaling=1", shell=True)
        configure_ws(4096, 524288, 524288)
    
    # window sclaing with factor 2ˆ7
    if ws == 7:
        subprocess.run("sysctl -w net.ipv4.tcp_window_scaling=1", shell=True)
        configure_ws(4096, 8388480, 8388480)    

    # window sclaing with factor 2ˆ14       
    if ws == 14:
        subprocess.run("sysctl -w net.ipv4.tcp_window_scaling=1", shell=True)
        configure_ws(4096, 1073725440, 1073725440)

    # used to identify warm up run 
    if ws == 1337:
        subprocess.run("sysctl -w net.ipv4.tcp_window_scaling=0", shell=True)

    subprocess.run("sysctl -p", shell=True)


def run_downloader(path):
    cmd = ["python3", "./lib/main.py", path, "config.json"]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output, error = p.communicate()
    return output


def save_dict_as_json(dictionary, path, filename, encoder=None):
    os.makedirs(path, exist_ok=True)
    with open(path + "/" + filename, "w") as out:
        json.dump(dictionary, out, indent=4, sort_keys=True, cls=encoder)


def calculate_peak_kpi(list):
    return {
        "max": max(list, key=lambda item: item[1]),
        "min": min(list, key=lambda item: item[1]),
    }


def cleanup():
    os.remove("config.json")


def prepare_downloader_config(interface, server, v4_blacklist, v6_blacklist):
    config = {
        "downloader": {
            "interface": interface,
            "urls": [server],
            "v4_blacklist": v4_blacklist,
            "v6_blacklist": v6_blacklist,
        }
    }
    save_dict_as_json(config, ".", "config.json")


def run_dls_with_all_cfg_permutations(client_config,
                                      dl_row, dl_index, path_to_save, current_domain, permutate_options,
                                      num_download_url, run_count, repeat_count,
                                      local_interface, v4_blacklist, v6_blacklist):

    base_domain_path = os.path.join(path_to_save, current_domain)
    os.makedirs(base_domain_path, exist_ok=True)
    run_id = datetime.now().isoformat("T", "seconds").replace(":", "-")

    # Configure client options
    configure_client_tcp_stack(client_config["ECN"], client_config["SACK"], client_config["TFO"], client_config["WS"])
    current_dl = "\n Downloading: Run Id - {}, Domain - {}, TCP Options: ECN: {} | SACK: {} | TFO: {} | WS: {} => Download: {}/{}, Repeat: {}/{}".format(
    run_id,
        dl_row.scan_domain,
        client_config["ECN"],
        client_config["SACK"],
        client_config["TFO"],
        client_config["WS"],
        dl_index + 1,
        num_download_url,
        run_count,
        repeat_count,
    )
    # output current dl info
    logging.info(current_dl)
    sys.stdout.write(current_dl)

    path = os.path.join(base_domain_path, run_id + code_mapping(client_config))

    # Prepare config for the downloader
    prepare_downloader_config(
        local_interface, dl_row.url, v4_blacklist, v6_blacklist
    )
    # Run downloader
    run_downloader(path)

    # Get Server TCP Options
    try:
        supported_tcp_options = post_processing.get_server_tcp_option(path)
        supported_tcp_options["scan_domain"] = dl_row.scan_domain
        supported_tcp_options["class_range"] = dl_row.class_range
        supported_tcp_options["size"] = dl_row.size
        supported_tcp_options["url"] = dl_row.url
        supported_tcp_options["run_type"] = "First"
        save_dict_as_json(supported_tcp_options, path, "server_config.json")
    except Exception as e:
        logging.error(
            "\n Failed to get server TCP Options for domain {}, run-id {}, Exception: {}".format(
                dl_row.scan_domain, run_id, e
            )
        )

    save_dict_as_json(client_config, path, "client_config.json")

    if supported_tcp_options["Num_SYN"] == 0:
        logging.info(
            "\n Skipping Domain : {} from further runs".format(
                dl_row.scan_domain
            )
        )
        return

    # if permutete_options:
    # Step 2 Run with other supported TCP options
    if permutate_options:
        total_num_options = curr_num_options = 1
        if supported_tcp_options["ECN"] == True:
            total_num_options = 2 * total_num_options
        if supported_tcp_options["SACK"] == True:
            total_num_options = 2 * total_num_options
        if supported_tcp_options["TFO"] == True:
            total_num_options = 2 * total_num_options
        if supported_tcp_options["WS"] > 0:
            total_num_options = 2 * total_num_options

        for ecn in True, False:
            if ecn == True and supported_tcp_options["ECN"] == False:
                continue
            for sack in True, False:
                if sack == True and supported_tcp_options["SACK"] == False:
                    continue
                for ws in [0, client_config["WS"]]:
                    logging.error(supported_tcp_options["WS"])
                    if ws == client_config["WS"] and supported_tcp_options["WS"] == 0:
                        continue
                    for tfo in True, False:
                        if tfo == True and supported_tcp_options["TFO"] == False:
                            continue

                        ## Configure client TCP options
                        client_config = {
                            "ECN": ecn,
                            "SACK": sack,
                            "TFO": tfo,
                            "WS": ws,
                        }

                        # Saving directory
                        run_id = (
                            datetime.now()
                            .isoformat("T", "seconds")
                            .replace(":", "-")
                        )
                        path = os.path.join(
                            path_to_save,
                            current_domain,
                            run_id + code_mapping(client_config),
                        )

                        current_dl = "\n Downloading: Run Id - {}, Domain - {}, TCP Options: ECN: {} | SACK: {} | TFO: {} | WS: {} => Options: {}/{}, Download: {}/{}, Repeat: {}/{}".format(
                            run_id,
                            dl_row.scan_domain,
                            client_config["ECN"],
                            client_config["SACK"],
                            client_config["TFO"],
                            client_config["WS"],
                            curr_num_options,
                            total_num_options,
                            dl_index + 1,
                            num_download_url,
                            run_count,
                            repeat_count,
                        )

                        logging.info(current_dl)
                        sys.stdout.write(current_dl)

                        configure_client_tcp_stack(
                            client_config["ECN"],
                            client_config["SACK"],
                            client_config["TFO"],
                            client_config["WS"],
                        )
                        save_dict_as_json(client_config, path, "client_config.json")

                        # Run TCP Downloader based on wget2
                        run_downloader(path)
                        curr_num_options += 1
                        try:
                            supported_tcp_options_local = (
                                post_processing.get_server_tcp_option(path)
                            )
                            supported_tcp_options_local[
                                "scan_domain"
                            ] = dl_row.scan_domain
                            supported_tcp_options_local[
                                "class_range"
                            ] = dl_row.class_range
                            supported_tcp_options_local["size"] = dl_row.size
                            supported_tcp_options_local["url"] = dl_row.url
                            supported_tcp_options_local["run_type"] = "Second"
                            save_dict_as_json(
                                supported_tcp_options_local,
                                path,
                                "server_config.json",
                            )
                        except Exception as e:
                            logging.error(
                                "\n Failed to get server TCP Options for domain {}, run-id {}, Exception: {}".format(
                                    dl_row.scan_domain, run_id, e
                                )
                            )

        cleanup()
    return


def run_dls_with_selected_cfgs(client_config, configs, 
                               dl_row, current_dl_dict, dl_index, path_to_save, current_domain,
                               num_download_url, run_count, repeat_count,
                               local_interface, v4_blacklist, v6_blacklist):

    base_domain_path = os.path.join(path_to_save, current_domain)
    os.makedirs(base_domain_path, exist_ok=True)
    run_id = datetime.now().isoformat("T", "seconds").replace(":", "-")

    # Prepare config for the downloader
    prepare_downloader_config(
        local_interface, dl_row.url, v4_blacklist, v6_blacklist
    )

    curr_num_options = 1
    total_num_options = len(configs)

    for config in configs:
        ## Configure client TCP options
        client_config = {
            "ECN": config[0],
            "SACK": config[1],
            "TFO": config[2],
            "WS": config[3],
        }
        # Saving directory
        run_id = (datetime.now().isoformat("T", "seconds").replace(":", "-"))

        path = os.path.join(path_to_save, current_domain, run_id + code_mapping(client_config), )
        print(path)

        current_dl = "\n Downloading: Run Id - {}, Domain - {}, TCP Options: ECN: {} | SACK: {} | TFO: {} | WS: {} => Options: {}/{}, Download: {}/{}, Repeat: {}/{}".format(
            run_id,
            dl_row.scan_domain,
            client_config["ECN"],
            client_config["SACK"],
            client_config["TFO"],
            client_config["WS"],
            curr_num_options,
            total_num_options,
            dl_index + 1,
            num_download_url,
            run_count,
            repeat_count,
        )

        logging.info(current_dl)
        sys.stdout.write(current_dl)

        configure_client_tcp_stack(
            client_config["ECN"],
            client_config["SACK"],
            client_config["TFO"],
            client_config["WS"],
        )

        save_dict_as_json(client_config, path, "client_config.json")
        save_dict_as_json(current_dl_dict, path, "target_info.json")

        # Run TCP Downloader based on wget2
        run_downloader(path)

        curr_num_options += 1
#        try:
#            supported_tcp_options_local = (post_processing.get_server_tcp_option(path))
#            supported_tcp_options_local["scan_domain"] = dl_row.scan_domain
#            supported_tcp_options_local["class_range"] = dl_row.class_range
#            supported_tcp_options_local["size"] = dl_row.size
#            supported_tcp_options_local["url"] = dl_row.url
#            supported_tcp_options_local["run_type"] = "Second"
#            save_dict_as_json(supported_tcp_options_local, path, "server_config.json", )
#        except Exception as e:
#            logging.error("\n Failed to get server TCP Options for domain {}, run-id {}, Exception: {}".format(
#                dl_row.scan_domain, run_id, e))
    cleanup()
    return


def run():
    parser = argparse.ArgumentParser()
    define_arguments(parser)
    args = parser.parse_args()
    run_config_data = get_json_data(args.config)
    local_interface = run_config_data["interface"]
    path_to_download_urls = run_config_data["url_file"]
    repeat_count = run_config_data["repeat_count"]
    path_to_save = run_config_data["path"]
    v4_blacklist = run_config_data["v4_blacklist"]
    v6_blacklist = run_config_data["v6_blacklist"]
    client_ecn = run_config_data["client_ecn"]
    client_sack = run_config_data["client_sack"]
    client_tfo = run_config_data["client_tfo"]
    client_ws = run_config_data["client_ws"]
    permutate_options = run_config_data["permutate_options"]
    configs = run_config_data["configs"]
    mode = run_config_data["mode"]
    quic_enabled = run_config_data["quic"]

    path_to_save = path_to_save + "-" + str(datetime.now().isoformat("T", "seconds").replace(":", "-"))
    os.makedirs(path_to_save)

    path_to_save_tcp = os.path.join(path_to_save, "tcp_downloads")

    os.makedirs(path_to_save_tcp)

    if quic_enabled:
        path_to_save_quic = os.path.join(path_to_save, "quic_downloads")
        os.makedirs(path_to_save_quic)

    run_instant = datetime.now().isoformat("T", "seconds").replace(":", "-")
    save_dict_as_json(
        run_config_data, path_to_save, "{}_run_config.json".format(run_instant)
    )

    logging.basicConfig(
        filename=path_to_save + "/{}_batch_downloader.log".format(run_instant),
        level=logging.INFO,
    )

    # Read database
    if run_config_data.get("database_config") == None:
        db_config = None
    else:
        db_config = run_config_data["database_config"]

    download_list = pd.read_csv(path_to_download_urls, on_bad_lines="warn")
    num_download_url = len(download_list)

    print("Mode: ", mode)
    print("QUIC: ", quic_enabled)
    print("Baseline options: ECN:", client_ecn, "SACK:", client_sack, "TFO:", client_tfo, "WS:", client_ws)

    for ith_repeat in range(repeat_count):
        for dl_index, dl_row in enumerate(download_list.itertuples(index=False)):

            run_count = ith_repeat + 1

            # Step 1 initialize, Try with all possible config

            client_config = {"ECN": client_ecn, "SACK": client_sack, "TFO": client_tfo, "WS": client_ws}
            # Get the current domain
            current_domain = dl_row.scan_domain
            current_dl_dict = {'index':dl_row.index, 'scanid':dl_row.scanid, 'scan_domain':dl_row.scan_domain, 'url':dl_row.url, 'server_ECN':dl_row.server_ECN, 'server_SACK':dl_row.server_SACK, 'server_TFO':dl_row.server_TFO, 'server_WS':dl_row.server_WS, 'asnr':dl_row.asnr, 'asname':dl_row.asname,  'orgid':dl_row.orgid}

                
            sys.stdout.write(
                "\n ############################################ TCP ####################################################################\n")
            logging.info(
                "\n ############################################ TCP ####################################################################\n")
            if mode == "all":
                logging.info("Mode = All ")
                #sys.stdout.write("\n Mode = All \n")
                run_dls_with_all_cfg_permutations(
                    client_config,
                    dl_row,
                    dl_index,
                    path_to_save_tcp,
                    current_domain,
                    permutate_options,
                    num_download_url,
                    run_count,
                    repeat_count,
                    local_interface,
                    v4_blacklist,
                    v6_blacklist
                )
            if mode == "selected":
                logging.info("Mode = Selected ")
                #sys.stdout.write("\n Mode = selected \n")
                run_dls_with_selected_cfgs(
                    client_config,
                    configs,
                    dl_row,
                    current_dl_dict,
                    dl_index,
                    path_to_save_tcp,
                    current_domain,
                    num_download_url,
                    run_count,
                    repeat_count,
                    local_interface,
                    v4_blacklist,
                    v6_blacklist
                )

            if quic_enabled:
                # Quic
                base_domain_path_quic = os.path.join(path_to_save_quic, current_domain)
                os.makedirs(base_domain_path_quic, exist_ok=True)
                run_id = datetime.now().isoformat("T", "seconds").replace(":", "-")
                path = os.path.join(base_domain_path_quic, run_id)
                os.makedirs(path+"_aioquic")
                os.makedirs(path+"_quiche")
                sys.stdout.write(
                    "\n ############################################ QUIC ####################################################################\n")
                logging.info(
                    "\n ############################################ QUIC ####################################################################\n")
                current_dl = "\n Downloading QUIC: Run Id- {}, Domain- {} \n".format(run_id, current_domain)
                logging.info(current_dl)
                sys.stdout.write(current_dl)
                # aioquic 
                save_dict_as_json(current_dl_dict, path+"_aioquic", "target_info.json")
                aioquic_download(path+"_aioquic", local_interface, dl_row.url.replace("http:", "https:"))
                # quiche 
                save_dict_as_json(current_dl_dict, path+"_quiche", "target_info.json")
                quiche_download(path+"_quiche", local_interface, dl_row.url.replace("http:", "https:"))

def code_mapping(client_config):
    text = "_OPTIONS_"
    if client_config["ECN"]:
        text += "ECN_"
    if client_config["SACK"]:
        text += "SACK_"
    if client_config["TFO"]:
        text += "TFO_"
    text += "WS_" + str(client_config["WS"])
    return text


def define_arguments(parser):
    parser.add_argument(
        "-c",
        "--config",
        help="Config file for the batch downloader",
        type=str,
        required=True,
    )


if __name__ == "__main__":
    run()




