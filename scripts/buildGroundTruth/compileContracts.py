import argparse
import itertools
import json
import logging
import os
import pickle
import subprocess
import sys
import time
import random
import psutil
import shutil


folder = os.path.dirname(__file__)
sys.path.append(folder + "/..")

from multiprocessing import Process, SimpleQueue, Manager, Event
from os.path import join
from parseGroundTruth.getGroundTruth import _analysis


TEMP_WORKING_DIR = ""
CONTRACT_DIR = ""
ADD_SOLC_EXECUTABLE = ""
ORI_SOLC_EXECUTABLE = ""
unique_addresses_path = ""
result_dir = ""
optimized = None

JOBS_NUM = 120
TIMEOUT_SECS = 120
FLUSH_PERIOD = 3

log_level = logging.INFO + 1
log = lambda msg: logging.log(logging.INFO + 1, msg)
logging.basicConfig(format='%(message)s', level=log_level)

UNIQUE_ADDRESSES = pickle.load(open(unique_addresses_path, "rb"))

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


def getName(contract_address):
    infostr = open(os.path.join(CONTRACT_DIR, contract_address, "info")).read()
    infos = infostr.split('\n')
    contract_name = infos[0]
    return contract_name


def compare(runtime1_path, runtime2_path):
    runtime1 = open(runtime1_path).read()
    runtime2 = open(runtime2_path).read()
    return runtime2 == runtime1


def compileSol(job_index, index, contract_address, result_queue):
    try:
        sol_path = os.path.join(CONTRACT_DIR, contract_address, 'code.sol')
        # sol_path = CONTRACT_DIR + os.sep + contract_address + os.sep + 'code.sol'
        out_dir = working_dir(job_index, True)
        empty_working_dir(job_index)

        contract_name = getName(contract_address)

        compile_start = time.time()

        if optimized is not None:
            compiled_args = [ADD_SOLC_EXECUTABLE, "--bin-runtime", "--annotation", sol_path, optimized, "-o",
                    os.path.join(out_dir, "add")]

            subprocess.run(compiled_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

            compiled_args = [ORI_SOLC_EXECUTABLE, "--bin-runtime", sol_path, optimized, "-o",
                    os.path.join(out_dir, "ori")]
            subprocess.run(compiled_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        else:
            compiled_args = [ADD_SOLC_EXECUTABLE, "--bin-runtime", "--annotation", sol_path, "-o",
                             os.path.join(out_dir, "add")]

            subprocess.run(compiled_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

            compiled_args = [ORI_SOLC_EXECUTABLE, "--bin-runtime", sol_path, "-o",
                             os.path.join(out_dir, "ori")]
            subprocess.run(compiled_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        if os.path.exists(out_dir+os.sep+"ori"+os.sep+contract_name+".bin-runtime"):
            with open(out_dir+os.sep+"ori"+os.sep+contract_name+".bin-runtime") as f:
                binary = f.read()
            if len(binary) == 0:
                raise Exception("the binary is empty")
            if not (os.path.exists(out_dir+os.sep+"add"+os.sep+contract_name+".bin-runtime") and
                    os.path.exists(out_dir+os.sep+"add"+os.sep+contract_name+".annotation")):
                raise Exception("instrument error")
            else:
                compile_time = time.time()

                runtime_bin_path = out_dir+os.sep+"ori"+os.sep+contract_name+".bin-runtime"
                annotation_path = out_dir+os.sep + "add" + os.sep+contract_name + ".annotation"
                flag, j_flag, e_flag, function_boundaries, tag_id_to_address = _analysis(annotation_path, runtime_bin_path)
                if flag and j_flag and e_flag:
                    analysis_time = time.time()
                    with open(out_dir+os.sep+"add"+os.sep+contract_name+".boundary", 'wb+') as f:
                        pickle.dump((function_boundaries, tag_id_to_address), f)

                    if not os.path.exists(result_dir + os.sep + "data" + os.sep + contract_address):
                        os.system("mkdir " + result_dir + os.sep + "data" + os.sep + contract_address)

                    shutil.copy(out_dir+os.sep + "add" + os.sep+contract_name + ".bin-runtime",
                                    result_dir + os.sep + "data" + os.sep + contract_address)
                    shutil.copy(out_dir+os.sep + "add" + os.sep+contract_name + ".annotation",
                                result_dir + os.sep + "data" + os.sep + contract_address)
                    shutil.copy(out_dir+os.sep + "add" + os.sep+contract_name + ".boundary",
                                result_dir + os.sep + "data" + os.sep + contract_address)

                    analytics = {}
                    comp_time = compile_time - compile_start
                    analytics["comp_time"] = comp_time
                    analy_time = analysis_time - compile_time
                    analytics['analy_time'] = analy_time
                    log("{}: {} completed in {:.2f} secs, analyze in {:.2f}".format(index, contract_address, comp_time,
                                                                                    analy_time))
                    result_queue.put((contract_address, [], analytics))
                else:
                    log("{}: {} Error: {}".format(index, contract_address, "check error"))
                    result_queue.put((contract_address, ["check error"], {}))
        else:
            log("{}: {} Error: {}".format(index, contract_address, "compile error"))
            result_queue.put((contract_address, ["compile error"], {}))

    except Exception as e:
        log("{}: {} exception: {:.20}..".format(index, contract_address, str(e)))
        result_queue.put((contract_address, ["{:.20}..".format(str(e))], {}))


os.system("rm -rf "+TEMP_WORKING_DIR+'*')

if os.path.exists(result_dir + os.sep + "data"):
    os.system("rm -rf "+result_dir + os.sep + "data")
os.system("mkdir " + result_dir + os.sep + "data")

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

to_process = UNIQUE_ADDRESSES
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
                proc = Process(target=compileSol, args=(job_index, index, fname, res_queue))
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

    log("\nWriting results to {}".format(result_dir+os.sep+"results.json"))
    with open(result_dir+os.sep+"results.json", 'w+') as f:
        f.write(json.dumps(list(res_list)))
    end_time = time.time()
    log("jobs time:{:.2f}sec".format(end_time-start_time))

except Exception as e:
    import traceback

    traceback.print_exc()
    flush_proc.terminate()
