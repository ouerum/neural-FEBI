import argparse
import csv
import json
import logging
import os
import pickle
import re
import sys
import time
import psutil

import fbdconfig

folder = os.path.dirname(__file__)
sys.path.append(folder + "/..")

from multiprocessing import Process, SimpleQueue, Manager, Event
from os.path import join
from function_boundary_detection import *


parser = argparse.ArgumentParser(
    description="A batch analyzer for ground truth."
)

parser.add_argument(
    "--contract_dir",
    metavar = "DIR",
    nargs="?",
    default=fbdconfig.contracts_dir,
    const=fbdconfig.contracts_dir,
)


parser.add_argument(
    "--fsi_result_path",
    metavar="DIR",
    nargs="?",
    default=fbdconfig.fsi_result_path,
    const=fbdconfig.fsi_result_path
)

parser.add_argument(
    "--result_csv",
    metavar="DIR",
    nargs="?",
    default="temp.csv"
)

parser.add_argument("--jobs",
                    type=int,
                    nargs="?",
                    default=24,
                    const=24,
                    metavar="NUM",
                    help="The number of subprocesses to run at once.")

parser.add_argument("--timeout_secs",
                    type=int,
                    nargs="?",
                    default=120,
                    const=120,
                    metavar="SECONDS",
                    help="Forcibly halt analysing any single contact after "
                         "the specified number of seconds.")

args = parser.parse_args()


# CONTRACT_DIR = args.contract_dir

JOBS_NUM = args.jobs
if config.debug:
    TIMEOUT_SECS = 1200000
else:
    TIMEOUT_SECS = args.timeout_secs
FLUSH_PERIOD = 3

fsi_result_path = args.fsi_result_path
contracts_dir = args.contract_dir
result_csv = args.result_csv


log_level = logging.INFO + 1
log = lambda msg: logging.log(logging.INFO + 1, msg)
logging.basicConfig(format='%(message)s', level=log_level)

fsi_result_paths = os.listdir(fsi_result_path)
fsi_results = {}

for fsi_result_file in fsi_result_paths:
    with open(os.path.join(fsi_result_path, fsi_result_file), 'rb') as f:
        addrs, crf_scores, bmap_lengths_sorted, decoded_time, tag_map = pickle.load(f)
        crf_scores = crf_scores.to("cpu")
        bmap_lengths_sorted = bmap_lengths_sorted.to("cpu")
        for i, addr in enumerate(addrs):
            fsi_results[addr] = (crf_scores[i], bmap_lengths_sorted[i], decoded_time)




def flush_queue(period, run_sig,
                result_queue, result_list):
    while run_sig.is_set():
        time.sleep(period)
        while not result_queue.empty():
            item = result_queue.get()
            result_list.append(item)



def compare(runtime1_path, runtime2_path):
    runtime1 = open(runtime1_path).read()
    runtime2 = open(runtime2_path).read()
    return runtime2 == runtime1



def analysis(job_index, index, contract_address, result_queue):
    try:
        ground_path = os.path.join(contracts_dir, contract_address)
        files = os.listdir(ground_path)
        runtime_files = [filename for filename in files if re.match(".*\.bin-runtime", filename)]
        assert len(runtime_files) == 1
        binary_full_path = os.path.join(ground_path, runtime_files[0])
        fsi_result = fsi_results[contract_address]
        func_boundary, body_pc, analy_time = function_boundary_detection(binary_full_path, (fsi_result[0], fsi_result[1]), tag_map)
        golden = load_ground_truth(ground_path)
        fb_results = compare_fb(golden[1], func_boundary)
        pred_fs = set(func_boundary.keys())
        result_start_pcs = pred_fs - golden[0][0] - golden[0][2]
        fs_results1 = compare_fs(golden[0][1], result_start_pcs)
        print("{}: {} : {} sec".format(index, contract_address, fsi_result[2]+analy_time))
        if config.debug:
            print(fs_results1)
            print(fb_results)
            print(func_boundary.keys())
            print(golden[1].keys())
        result_queue.put((contract_address, [], {"fs":fs_results1, "fb":fb_results, "time1":fsi_result[2], "time2":analy_time}))

    except Exception as e:
        log("{}: {} exception: {:.20}..".format(index, contract_address, str(e)))
        result_queue.put((contract_address, ["{:.20}..".format(str(e))], {}))



log("Setting up workers.")
manager = Manager()
res_list = manager.list()
res_queue = SimpleQueue()

run_signal = Event()
run_signal.set()
flush_proc = Process(target=flush_queue, args=(FLUSH_PERIOD, run_signal, res_queue, res_list))

flush_proc.start()

workers = []

to_process = list(fsi_results.keys())
# to_process = ["0x9ec5b92af227933fbdec6b6078da43675d8352b2"]
avail_jobs = list(range(JOBS_NUM))
contract_iter = enumerate(to_process)
contract_exhausted = False

log("Analysing...\n")
start_time = time.time()
try:
    while not contract_exhausted:
        while not contract_exhausted and len(avail_jobs) > 0:
            try:
                index ,fname = next(contract_iter)
                job_index = avail_jobs.pop()
                proc = Process(target=analysis, args=(job_index, index, fname, res_queue))
                proc.start()
                start_time = time.time()
                workers.append({"name":fname, "proc":proc, "time":start_time, "job_index":job_index})
            except StopIteration:
                contract_exhausted = True

        while len(avail_jobs) == 0 or (contract_exhausted and 0 < len(workers)):
            to_remove = []
            for i in range(len(workers)):
                start_time = workers[i]["time"]
                proc = workers[i]["proc"]
                name = workers[i]["name"]
                job_index = workers[i]["job_index"]

                if time.time() - start_time > TIMEOUT_SECS:
                    res_queue.put((name, ["TIMEOUT"], {}))
                    parent = psutil.Process(proc.pid)
                    for child in parent.children(recursive=True):
                        child.kill()
                    parent.kill()
                    log("{} timed out.".format(name))
                    to_remove.append(i)
                    avail_jobs.append(job_index)
                elif not proc.is_alive():
                    to_remove.append(i)
                    proc.join()
                    avail_jobs.append(job_index)

            for i in reversed(to_remove):
                workers.pop(i)

            time.sleep(0.01)
    log("\nFinishing...\n")
    run_signal.clear()
    flush_proc.join(FLUSH_PERIOD + 1)


    log("\nWriting results to {}".format(result_csv))
    with open(result_csv, 'w') as f:
        data = []
        for contract, meta, analytics in res_list:
            d = [''] * 10
            d[0] = contract
            if len(meta) == 0:
                d[1] = analytics["fs"][0]
                d[2] = analytics['fs'][1]
                d[3] = analytics['fs'][2]
                d[4] = analytics['fb'][0]
                d[5] = analytics['fb'][1]
                d[6] = analytics['fb'][2]
                d[7] = analytics["time1"]
                d[8] = analytics["time2"]
            else:
                d[1] = d[2] = d[3] = d[4] = d[5] = d[6] = 0
                d[9] = meta
            data.append(d)
        writer = csv.writer(f)
        writer.writerow(["addr", "fs_f1", "fs_p", "fs_r", "fb_f1", "fb_p", "fb_r", "time1", "time2", "meta"])
        for _d in data:
            writer.writerow(_d)

    end_time = time.time()
    log("jobs time:{:.2f}sec".format(end_time-start_time))

except Exception as e:
    import traceback

    traceback.print_exc()
    flush_proc.terminate()
