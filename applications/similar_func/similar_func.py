import json
import re
import os
import pickle
import logging
import time
import psutil

from disassembly.evmdasm import EvmBytecode
from multiprocessing import Process, SimpleQueue, Manager, Event


JOBS_NUM = 8
TIMEOUT_SECS = 120000
FLUSH_PERIOD = 3
debug = True

log_level = logging.INFO + 1
log = lambda msg: logging.log(logging.INFO + 1, msg)
logging.basicConfig(format='%(message)s', level=log_level)

solc_version = "0.5.17"
optimized = "-optimized"
boundary_contracts_dir = os.path.join("/Users/oueru/Documents/neural-FIBD/results/fbd/" + solc_version +
                                      optimized, "data")
result_json = os.path.join("/Users/oueru/Documents/neural-FIBD/results/similar_func/", solc_version+optimized+".json")


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


def cal(instr_seq):
    code_size = 0
    for instr in instr_seq:
        if instr[0].startswith('PUSH'):# push instruction
            value_size = int(instr[0][4:])
            code_size += 1 + value_size
        else:
            code_size += 1
    return code_size


def simliar_tag(tag_pc1, tag_pc2, instr_seq, pc_to_index):
    instr_seq1 = fetch_tag_instr(tag_pc1, instr_seq, pc_to_index)
    instr_seq2 = fetch_tag_instr(tag_pc2, instr_seq, pc_to_index)
    if equal(instr_seq1, instr_seq2):
        return True, cal(instr_seq2)
    return False, 0


def equal(instr_seq1, instr_seq2):
    if len(instr_seq1) != len(instr_seq2):
        return False
    for index, instr in enumerate(instr_seq1):
        if instr[0] != instr_seq2[index][0]:
            return False
    return True


def fetch_tag_instr(tag_pc, instr_seq, pc_to_index):
    instrs = []
    current_index = pc_to_index[tag_pc]
    while current_index < len(instr_seq):
        current_instr = instr_seq[current_index]
        if current_instr[0] in ["RETURN", "REVERT", "JUMP", "SELFDESTRUCT", "STOP"]:
            instrs.append(current_instr)
            break
        elif current_instr[0] == 'PUSH' and current_instr[2] is not None:
            continue
        else:
            instrs.append(current_instr)
        current_index += 1
    return instrs


def read_runtime_bin(runtime_bin_path):
    runtime_bin = open(runtime_bin_path).read()
    runtime_bytecode = EvmBytecode(runtime_bin)
    runtime_disassembly = runtime_bytecode.disassemble()
    return runtime_disassembly


def load_FEBI_result(ground_path):
    with open(ground_path, 'rb') as f:
        func_boundaries, instr_seq = pickle.load(f)
    return func_boundaries, instr_seq


def analysis(job_index, index, contract_address, result_queue):
    try:
        boundaries_path = os.path.join(boundary_contracts_dir, contract_address)
        fbs, runtime_disassembly = load_FEBI_result(boundaries_path)

        pc_to_index = {}
        for i, instr in enumerate(runtime_disassembly):
            pc_to_index[instr[1]] = i

        remove_tags = set()
        remove_size = 0
        for function_entry_x in fbs.keys():
            fb_x = fbs[function_entry_x]
            for function_entry_y in fbs.keys():
                fb_y = fbs[function_entry_y]
                for tag_pc_x in fb_x:
                    for tag_pc_y in fb_y:
                        if tag_pc_y != tag_pc_x:
                            flag, code_size = simliar_tag(tag_pc_x, tag_pc_y, runtime_disassembly, pc_to_index)
                            if tag_pc_y not in remove_tags:
                                remove_size += code_size
                                remove_tags.add(tag_pc_y)
        log("{}: {}, {}".format(index, contract_address, str(remove_size)))
        result_queue.put((contract_address, remove_size, []))
    except Exception as e:
        result_queue.put((contract_address, 0, [str(e)]))
        log("{}: {} exception: {:.20}..".format(index, contract_address, str(e)))


if __name__ == "__main__":
    remove_sizes = {}
    ADDRESSES = os.listdir(boundary_contracts_dir)
    ADDRESSES = ['0x14f11e6939975cf207890d181c405e6f814fefaa']

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

        total_remove_size = 0
        contract_num = 0
        for address, remove_size, meta in res_list:
            total_remove_size += remove_size
            if remove_size > 0:
                contract_num += 1

        with open(result_json, 'w') as f:
            json.dump(list(res_list), f)

        print("==== " + str(contract_num) + "/" + str(len(ADDRESSES)) + " ====")
        print("==== " + str(total_remove_size) + " ====")
        print("==== " + str(total_remove_size * 200) + " ====")
        print("==== " + str(total_remove_size * 200 * 13) + "Gwei ==== 20220515")
        print("==== " + str(total_remove_size * 200 * 13 / (10 ** 9)) + "ETH")

        end_time = time.time()
        log("jobs time:{:.2f}sec".format(end_time-start_time))

    except Exception as e:
        import traceback

        traceback.print_exc()
        flush_proc.terminate()



# if __name__ == "__main__":
#     # solc_version = "0.4.25"
#     solc_version = "0.5.17"
#     optimized = "-optimized"
#     boundary_contracts_dir = os.path.join("/Users/oueru/Documents/neural-FIBD/results/fbd/" + solc_version +
#                                         optimized, "data")
#     remove_sizes = {}
#     for address in os.listdir(boundary_contracts_dir):
#
#         b_contract_dir = os.path.join(boundary_contracts_dir, address)
#
#         remove_size = analysis(os.path.join(boundary_contracts_dir, address))
#         remove_sizes[address] = remove_size
#         print(remove_size)
#
#     total_remove_size = 0
#     contract_num = 0
#     for address, remove_size in remove_sizes.items():
#         total_remove_size += remove_size
#         if remove_size > 0:
#             contract_num += 1
#
#     print("==== " + str(contract_num) + "/" + str(len(remove_sizes.keys())) + " ====")
#     print("==== " + str(total_remove_size) + " ====")
#     print("==== " + str(total_remove_size * 200) + " ====")
#     print("==== " + str(total_remove_size * 200 * 13) + "Gwei ==== 20220515")
#     print("==== " + str(total_remove_size * 200 * 13 / (10**9)) + "ETH")

