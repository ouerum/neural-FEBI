import argparse
import csv
import io
import json
import logging
import os
import pickle
import re
import sys
import time
import psutil
import torch

import fbdconfig

folder = os.path.dirname(__file__)
sys.path.append(folder + "/..")

from multiprocessing import Process, SimpleQueue, Manager, Event
from os.path import join
# from fbdconfig import *
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
    "--result_path",
    metavar="DIR",
    nargs="?",
    default=fbdconfig.result_path,
    const=fbdconfig.result_path
)

parser.add_argument("--jobs",
                    type=int,
                    nargs="?",
                    default=8,
                    const=8,
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
    TIMEOUT_SECS = 120
else:
    TIMEOUT_SECS = args.timeout_secs
FLUSH_PERIOD = 3

fsi_result_path = args.fsi_result_path
contracts_dir = args.contract_dir
result_path = args.result_path


log_level = logging.INFO + 1
log = lambda msg: logging.log(logging.INFO + 1, msg)
logging.basicConfig(format='%(message)s', level=log_level)


class CPU_Unpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == 'torch.storage' and name == '_load_from_bytes':
            return lambda b: torch.load(io.BytesIO(b), map_location='cpu')
        else:
            return super().find_class(module, name)


fsi_result_paths = os.listdir(fsi_result_path)
fsi_results = {}

for fsi_result_file in fsi_result_paths:
    with open(os.path.join(fsi_result_path, fsi_result_file), 'rb') as f:
        addrs, crf_scores, bmap_lengths_sorted, decoded_time, tag_map = CPU_Unpickler(f).load()
        crf_scores = crf_scores.to("cpu")
        bmap_lengths_sorted = bmap_lengths_sorted.to("cpu")
        for i, addr in enumerate(addrs):
            fsi_results[addr] = (crf_scores[i], bmap_lengths_sorted[i], decoded_time)

# ADDRESSES = os.listdir(ground_contracts_dir)
# ADDRESSES = ["0xa991aeac42ffdee21e86ea4f20148092722c73ff"]
# def empty_working_dir(index) -> None:
#     """
#     Empty the working directory for the job indicated by index.
#     """
#     for d_triple in os.walk(working_dir(index)):
#         for fname in d_triple[2]:
#             os.remove(join(d_triple[0], fname))
#
#
# def backup_and_empty_working_dir(index) -> None:
#     if os.path.exists(working_dir(index)):
#         empty_working_dir(index)


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


# def working_dir(index, output_dir=False):
#     if output_dir:
#         return join(TEMP_WORKING_DIR, str(index), "out")
#     return join(TEMP_WORKING_DIR, str(index))
#
#
# def getName(contract_address):
#     infostr = open(os.path.join(CONTRACT_DIR, contract_address, "info")).read()
#     infos = infostr.split('\n')
#     contract_name = infos[0]
#     return contract_name

class AverageMeter(object):
    def __init__(self):
        self.reset()
        self.count = 0
        self.sum = 0

    def reset(self):
        self.val = 0
        self.avg = 0
        self.sum = 0
        self.count = 0

    def update(self, val, n=1):
        self.val = val
        self.sum += val * n
        self.count += n
        self.avg = self.sum / self.count


class Result:
    def __init__(self):
        self.precisions = AverageMeter()
        self.recalls = AverageMeter()
        self.f1_scores = AverageMeter()

    def update(self, f1_score, precision, recall, weight=1):
        self.precisions.update(precision, weight)
        self.recalls.update(recall, weight)
        self.f1_scores.update(f1_score, weight)

    def avg(self):
        return self.precisions.avg, self.recalls.avg, self.f1_scores.avg


def print_results(results):
    fsi_results = Result()
    cfg_results = Result()
    fb_results = Result()
    ctx_results = Result()
    total_count = 0
    counts = {}
    for contract, meta, analytics in results:
        rlist = meta
        if len(rlist) == 0:  # analysis successfully
            weighted = 1
            fsi_results.update(analytics['fs'][0], analytics['fs'][1], analytics['fs'][2],
                                    weighted)
            # fsi_results.update(analytics['fsi'][0], analytics['fsi'][1], analytics['fsi'][2], weighted)
            fb_results.update(analytics['fb'][0], analytics['fb'][1], analytics['fb'][2], weighted)
            ctx_results.update(analytics['ctx'][0], analytics['ctx'][1], analytics['ctx'][2], weighted)
            if analytics['cfg'][0] != -1:
                cfg_results.update(analytics['cfg'][0], analytics['cfg'][1], analytics['cfg'][2], weighted)
        else:
            total_count += 1
        for res in rlist:
            if res not in counts:
                counts[res] = 1
            else:
                counts[res] += 1
    print("Total Contracts number: [{0}][{1} {2}]".format(len(results), len(results) - total_count, total_count))
    for res, count in counts.items():
        print("  {}: {:.2f}%".format(res, 100 * count / len(results)))

    print("Function Starts:")
    print("F1-score {f1.avg:.3f}\n"
          "Precision {p.avg:.3f}\n"
          "Recall {r.avg:.3f}".format(f1=fsi_results.f1_scores, p=fsi_results.precisions,
                                      r=fsi_results.recalls))

    print("Function Boundaries:")
    print("F1-score {f1.avg:.3f}\n"
          "Precision {p.avg:.3f}\n"
          "Recall {r.avg:.3f}".format(f1=fb_results.f1_scores, p=fb_results.precisions, r=fb_results.recalls))

    print("Call Graph:")
    print("F1-score {f1.avg:.3f}\n"
          "Precision {p.avg:.3f}\n"
          "Recall {r.avg:.3f}".format(f1=ctx_results.f1_scores, p=ctx_results.precisions, r=ctx_results.recalls))

    print("CFG:")
    print("F1-score {f1.avg:.3f}\n"
          "Precision {p.avg:.3f}\n"
          "Recall {r.avg:.3f}".format(f1=cfg_results.f1_scores, p=cfg_results.precisions, r=cfg_results.recalls))


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
        func_boundary, start_pcs, instr_seq, ctx_strs, paths, analy_time = function_boundary_detection(binary_full_path, (fsi_result[0], fsi_result[1]), tag_map)
        entry_golden, fb_golden, n, ctx_str_golden = load_ground_truth(ground_path)

        fb_results = compare_fb(fb_golden, func_boundary)
        pred_fs = start_pcs - entry_golden[1] - entry_golden[3]
        result_start_pcs = pred_fs
        fs_results1 = compare_fs(entry_golden[2], result_start_pcs)

        ctx_results = compare_ctx_strs(ctx_str_golden, ctx_strs)

        try:
            files = os.listdir(ground_path)
            paths_files = [filename for filename in files if re.match('.*\.path', filename)]
            if len(paths_files) == 1:
                paths_golden = load_ground_truth_paths(ground_path)
                paths_results = compare_paths(paths_golden, paths)
            else:
                paths_results = [-1, -1, -1]
        except Exception as e:
            paths_results = [-1, -1, -1]

        with open(os.path.join(result_path, "data", contract_address), "wb") as f:
            _instr_seq = []
            for instr in instr_seq:
                _instr_seq.append((instr.name, instr.address, instr.tag_id))
            pickle.dump((func_boundary, _instr_seq), f)

        print("{}: {} : {} sec".format(index, contract_address, fsi_result[2]+analy_time))
        result_queue.put((contract_address, [], {"fs": fs_results1, "fb": fb_results, "ctx": ctx_results,
                                                 "cfg": paths_results, "time1": fsi_result[2], "time2": analy_time}))

    except Exception as e:
        log("{}: {} exception: {:.20}..".format(index, contract_address, str(e)))
        result_queue.put((contract_address, ["{:.20}..".format(str(e))], {}))


# os.system("rm -rf "+TEMP_WORKING_DIR+'*')
#
# log("Setting up working directory {}.".format(TEMP_WORKING_DIR))
# for i in range(JOBS_NUM):
#     os.makedirs(working_dir(i, True), exist_ok=True)
#     empty_working_dir(i)

if __name__ == "__main__":

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
    # to_process = ["0xab1b7674a92a4b788855915e6bda60841c284189"]
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

        print_results(res_list)

        with open(os.path.join(result_path, 'result.json'), 'w') as f:
            f.write(json.dumps(list(res_list)))

        end_time = time.time()
        log("jobs time:{:.2f}sec".format(end_time-start_time))

    except Exception as e:
        import traceback

        traceback.print_exc()
        flush_proc.terminate()
