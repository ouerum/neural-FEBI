import json
import logging
import os
import pickle
import re
import sys
import time
import psutil


folder = os.path.dirname(__file__)
sys.path.append(folder + "/..")

from multiprocessing import Process, SimpleQueue, Manager, Event
from os.path import join
from getGroundTruth import _analysis
from getCFGPathGroundTruth import extract_optimized_acyclic_paths

# SOLC_VERSION = ["0.5.17"]
SOLC_VERSION = ["0.4.25"]
opt = False
TEMP_WORKING_DIR = "/Users/oueru/Documents/neural-FIBD/.temp/"

if opt:
    contract_dir = "/Users/oueru/Documents/neural-FIBD/data/ground-truth/" + SOLC_VERSION[0] + "-optimized"
else:
    contract_dir = "/Users/oueru/Documents/neural-FIBD/data/ground-truth/" + SOLC_VERSION[0] + "-unoptimized"


JOBS_NUM = 8
TIMEOUT_SECS = 120
FLUSH_PERIOD = 3
debug = True

log_level = logging.INFO + 1
log = lambda msg: logging.log(logging.INFO + 1, msg)
logging.basicConfig(format='%(message)s', level=log_level)


def empty_working_dir(index) -> None:
    """
    Empty the working directory for the job indicated by index.
    """
    for d_triple in os.walk(working_dir(index)):
        for fname in d_triple[2]:
            os.remove(join(d_triple[0], fname))


def backup_and_empty_working_dir(index) -> None:
    if os.path.exists(working_dir(index)):
        empty_working_dir(index)


def flush_queue(period, run_sig,
                result_queue, result_list):
    """
    For flushing the queue periodically to a list so it doesn't fill up.

    Args:
        period: flush the result_queue to result_list every period seconds
        run_sig: terminate when the Event run_sig is cleared.
        result_queue: the queue in which results accumulate before being flushed
        result_list: the final list of results.
    """
    while run_sig.is_set():
        time.sleep(period)
        while not result_queue.empty():
            item = result_queue.get()
            result_list.append(item)


def working_dir(index, output_dir=False):
    if output_dir:
        return join(TEMP_WORKING_DIR, str(index), "out")
    return join(TEMP_WORKING_DIR, str(index))


def analysis(job_index, index, contract_address, result_queue):
    try:
        files = os.listdir(os.path.join(contract_dir, "data", contract_address))
        annotation_files = [filename for filename in files if re.match(".*\.annotation", filename)]
        runtime_files = [filename for filename in files if re.match(".*\.bin-runtime", filename)]
        # boundary_files = [filename for filename in files if re.match(".*\.boundary", filename)]
        # paths_files = [filename for filename in files if re.match(".*\.paths", filename)]
        boundary_files = [filename.split('.')[0]+'.boundary' for filename in files if
                          re.match(".*\.annotation", filename)]
        paths_files = [filename.split('.')[0] + '.path' for filename in files if
                          re.match(".*\.annotation", filename)]
        assert len(annotation_files) == 1 and len(runtime_files) == 1 and len(boundary_files) == 1

        runtime_bin_path = os.path.join(contract_dir, "data", contract_address, runtime_files[0])
        annotation_path = os.path.join(contract_dir, "data", contract_address, annotation_files[0])

        # flag, j_flag, e_flag, fb, tag_id_to_address, call_graph = _analysis(annotation_path, runtime_bin_path)
        # output_path = os.path.join(contract_dir, "data", contract_address, boundary_files[0])
        # if flag and j_flag and e_flag:
        #     with open(output_path, 'wb') as f:
        #         pickle.dump((fb, tag_id_to_address, call_graph), f)

        output_path2 = os.path.join(contract_dir, "data", contract_address, paths_files[0])
        equal, contract_acyclic_paths, basic_blocks, optimized_items = extract_optimized_acyclic_paths(
                annotation_path, runtime_bin_path)
        if equal:
            if os.path.exists(output_path2):
                os.remove(output_path2)
            with open(output_path2, 'wb') as f:
                pickle.dump((contract_acyclic_paths, basic_blocks), f)

        log("{}: {}".format(index, contract_address))
        result_queue.put((contract_address, [], {}))
    except Exception as e:
        log("{}: {} exception: {:.20}..".format(index, contract_address, str(e)))
        result_queue.put((contract_address, ["{:.20}..".format(str(e))], {}))


if __name__ == '__main__':
    ADDRESSES = os.listdir(os.path.join(contract_dir, "data"))
    # ADDRESSES = ['0xd459dfceaf783ece471de136079838788a48dc4e']
    os.system("rm -rf "+TEMP_WORKING_DIR+'*')

    log("Setting up working directory {}.".format(TEMP_WORKING_DIR))
    for i in range(JOBS_NUM):
        os.makedirs(working_dir(i, True), exist_ok=True)
        empty_working_dir(i)

    log("Setting up workers.")
    manager = Manager()
    res_list = manager.list()
    res_queue = SimpleQueue()

    run_signal = Event()
    run_signal.set()
    flush_proc = Process(target=flush_queue, args=(FLUSH_PERIOD, run_signal, res_queue, res_list))

    flush_proc.start()

    workers = []

    to_process = ADDRESSES
    avail_jobs = list(range(JOBS_NUM))
    contract_iter = enumerate(to_process)
    contract_exhausted = False

    log("Analysing...\n")
    start_time = time.time()
    try:
        while not contract_exhausted:
            while not contract_exhausted and len(avail_jobs) > 0:
                try:
                    index, fname = next(contract_iter)
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
                        parent = psutil.Process(proc.pid)
                        res_queue.put((name, ["TIMEOUT"], {}))
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

        counts = {}
        total_flagged = 0
        for contract, meta, analytics in res_list:
            rlist = meta
            if len(rlist) > 0:
                total_flagged += 1
            for res in rlist:
                if res not in counts:
                    counts[res] = 1
                else:
                    counts[res] += 1

        total = len(res_list)
        log("{} of {} contracts flagged.\n".format(total_flagged, total))
        for res, count in counts.items():
            log("  {}: {:.2f}%".format(res, 100 * count / total))

        end_time = time.time()
        log("jobs time:{:.2f}sec".format(end_time-start_time))

    except Exception as e:
        import traceback

        traceback.print_exc()
        flush_proc.terminate()
