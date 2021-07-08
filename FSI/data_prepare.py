import logging
import os
import pickle
import sys
import time
import psutil
import re
import utils.common as common
import utils.config as config

folder = os.path.dirname(__file__)
sys.path.append(folder + "/..")

from multiprocessing import Process, SimpleQueue, Manager, Event


JOBS_NUM = 30
TIMEOUT_SECS = 120000
FLUSH_PERIOD = 3
debug = True

log_level = logging.INFO + 1
log = lambda msg: logging.log(logging.INFO + 1, msg)
logging.basicConfig(format='%(message)s', level=log_level)


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


# put the result data into result_queue
def prepare_data(job_index, index, contract_address, contract_dir, output_dir, result_queue):
    try:
        temp_b = []
        temp_t = []
        temp_b_instr = []
        files = os.listdir(os.path.join(contract_dir, contract_address))
        boundary_files = [filename for filename in files if re.match(".*\.boundary", filename)]
        runtime_files = [filename for filename in files if re.match(".*\.bin-runtime", filename)]
        assert len(boundary_files) == 1 and len(runtime_files) == 1

        runtime_code_path = os.path.join(contract_dir, contract_address, runtime_files[0])
        function_boundaries_path = os.path.join(contract_dir, contract_address, boundary_files[0])
        with open(runtime_code_path, 'r') as f:
            runtime_code = f.read()
            code_blocks = common.split_blocks(runtime_code)# a tuple
        with open(function_boundaries_path, 'rb') as f:
            function_boundaries = pickle.load(f)

        boundary, tag_to_pc = function_boundaries

        func_boundary = boundary[0]
        public = boundary[2]
        private = boundary[1]
        fallback = boundary[3]
        public_body_entry_addrs = set()
        for entry, _ in func_boundary[1].items():
            public_body_entry_addrs.add(tag_to_pc[entry])

        private_entry_addrs = set()
        for entry, _ in func_boundary[2].items():
            private_entry_addrs.add(tag_to_pc[entry])

        fallback_entry_addrs = set()
        for entry, _ in func_boundary[3].items():
            fallback_entry_addrs.add(tag_to_pc[entry])

        for addr, code_block in code_blocks.items():
            temp_b.append(code_block[0])
            temp_b_instr.append(code_block[1])
            if addr in private_entry_addrs | public_body_entry_addrs | fallback_entry_addrs:
                temp_t.append('S')
            else:
                temp_t.append('NS')

        assert len(temp_b) == len(temp_b_instr) == len(temp_t)

        with open(output_dir + os.sep + contract_address, 'wb') as f:
            pickle.dump((temp_b, temp_b_instr, temp_t, list(code_blocks.keys())), f)
        result_queue.put((contract_address, [], {}))
        log("{}: {} completed".format(index, contract_address))
    except Exception as e:
        log("{}: {} exception: {:20}..".format(index, contract_address, str(e)))
        result_queue.put((contract_address, ["{:.20}..".format(str(e))], {}))


def _multi_read_tags(contract_dir, output_dir, addresses):
    log("Setting up workers.")
    manager = Manager()
    res_list = manager.list()
    res_queue = SimpleQueue()

    run_signal = Event()
    run_signal.set()
    flush_proc = Process(target=flush_queue, args=(FLUSH_PERIOD, run_signal, res_queue, res_list))

    flush_proc.start()

    workers = []

    to_process = addresses
    avail_jobs = list(range(JOBS_NUM))
    contract_iter = enumerate(to_process)
    contract_exhausted = False

    log("Perparing data...")
    job_start_time = time.time()
    try:
        while not contract_exhausted:
            while not contract_exhausted and len(avail_jobs) > 0:
                try:
                    index, fname = next(contract_iter)
                    job_index = avail_jobs.pop()
                    proc = Process(target=prepare_data, args=(job_index, index, fname, contract_dir, output_dir, res_queue))
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
        log("Finishing...")
        run_signal.clear()
        flush_proc.join(FLUSH_PERIOD + 1)

        total_flagged = 0
        for contract, meta, analytics in res_list:
            rlist = meta
            if len(rlist) > 0:
                 total_flagged += 1

        total = len(res_list)
        log("{} of {} contracts flagged.".format(total_flagged, total))

        end_time = time.time()
        log("jobs time:{:.2f}sec".format(end_time-job_start_time))

    except Exception as e:
        import traceback
        traceback.print_exc()
        flush_proc.terminate()


if __name__ == "__main__":
    addresses = os.listdir(config.contracts_dir)    
    _multi_read_tags(config.contracts_dir, config.data_dir, addresses)

    trainning_addresses, others = common.split_list(addresses, config.training_ratio, True)
    val_addresses, test_addresses = common.split_list(others, config.val_ratio / (config.val_ratio + config.test_ratio), True)

    with open(config.address_path, "wb") as f:
        pickle.dump((trainning_addresses, val_addresses, test_addresses), f)




