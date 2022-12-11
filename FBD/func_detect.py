import time

import torch
import torch.nn.functional as F

from data_flow_analysis import global_data_flow_analysis
from jump_annotation_recognizer import rconginze_call_sites
from fbdconfig import debug

def decode(crf_score, length, tag_map, threshold=0.5, not_start=None):
    if not_start is None:
        not_start = set()
    tagset_size = len(tag_map)
    start_tag = tag_map['<start>']
    end_tag = tag_map['<end>']
    func_s_tag = tag_map['S']
    func_ns_tag = tag_map['NS']

    scores_upto_t = torch.zeros(tagset_size).to("cpu")
    backpointer = torch.ones((length, tagset_size), dtype=torch.long) * end_tag

    for t in range(length):
        if t == 0:
            scores_upto_t = crf_score[t, start_tag, :]
            backpointer[t, :] = torch.ones(tagset_size, dtype=torch.long) * start_tag
        else:
            scores = crf_score[t, :, :] + scores_upto_t.unsqueeze(1) # (3,3)
            _score = F.softmax(scores, dim=0)
            Sp = _score[func_s_tag, :] / (_score[func_s_tag, :] + _score[func_ns_tag, :]) #(3)

            results = Sp.ge(threshold) #(3)
            absolute_inds = torch.tensor([i+(func_s_tag*tagset_size) if (r and t not in not_start) else i+(func_ns_tag*tagset_size) for i, r in enumerate(results)])
            backpointer[t, :] = torch.tensor([func_s_tag if (r and t not in not_start) else func_ns_tag for i, r in enumerate(results)]) #(3)
            scores_upto_t = torch.take(scores, index=absolute_inds) #(3)

    decoded = torch.zeros(backpointer.size(0), dtype=torch.long)
    pointer = torch.ones(1, dtype=torch.long) * end_tag

    for t in list(reversed(range(backpointer.size(0)))):
        decoded[t] = torch.gather(backpointer[t, :], 0, pointer).squeeze(0)
        pointer = decoded[t].unsqueeze(0)  # (batch_size, 1)

    assert torch.equal(decoded[0], torch.tensor(start_tag))
    decoded = torch.cat([decoded[1:], torch.tensor([end_tag])])

    return decoded


def construct_start_pcs(instruction_sequence, basic_blocks, body_tags, fallback_tag, tag_id_to_pc, tag_map, fsi_results,
                        threshold=0.5, not_starts=None):
    init_starts = set()

    for body_tag in body_tags:
        init_starts.add(tag_id_to_pc[body_tag])

    if len(fallback_tag) != 0:
        init_starts.add(tag_id_to_pc[list(fallback_tag)[0]])

    decoded = decode(fsi_results[0], fsi_results[1], tag_map, threshold, not_starts)
    decoded = decoded.to("cpu").numpy().tolist()

    pred_tag_list = decoded[:fsi_results[1]-1]
    start_tag = tag_map['S']
    for ind, tag_id in enumerate(pred_tag_list):
        if tag_id == start_tag and ind in tag_id_to_pc:
            pc = tag_id_to_pc[ind]
            init_starts.add(pc)
    # possible_calls = rconginze_call_sites(instruction_sequence, basic_blocks, init_starts, body_tags, tag_id_to_pc)
    return init_starts #, possible_calls


def detect_func(instruction_sequence, basic_blocks, pc_to_instruction_index, tag_id_to_pc,
                external_function_entry_tag_to_body_tag, fallback_tag,
                fsi_results, tag_map, threshold1=0.5, threshold2=0.3, delay=0.05):

    invalid_calls = set()
    body_tags = external_function_entry_tag_to_body_tag.values()
    start = time.time()
    func_starts = construct_start_pcs(instruction_sequence, basic_blocks, body_tags, fallback_tag, tag_id_to_pc, tag_map, fsi_results, threshold1)
    removed_time = time.time() - start

    possible_calls = {}
    wait_for_exporation = func_starts
    not_starts = set()
    fbs = {}
    call_graph = {} # entry -> call_site_index -> (tgt_func, tag_context)

    while len(wait_for_exporation):
        delay_flag = False
        _wait_for_exporation = set()
        for entry_pc in wait_for_exporation:
            fb = set()
            _call_graph = {}
            missing_flag, invalid_flag, _invalid_calls = global_data_flow_analysis(instruction_sequence,
                                                                                   pc_to_instruction_index,
                                                                                   entry_pc, func_starts,
                                                                                   possible_calls, invalid_calls, fb,
                                                                                   _call_graph, threshold1,
                                                                                   threshold2, fbs.keys())
            if (not missing_flag) and (not invalid_flag):
                fbs[entry_pc] = fb
                call_graph[entry_pc] = _call_graph
            else:
                if len(_invalid_calls) > 0 and debug:
                    print("find the invalid calls at {}".format(_invalid_calls))
                _wait_for_exporation.add(entry_pc)
                delay_flag = delay_flag or missing_flag
                invalid_calls.update(_invalid_calls)
                for call_index, target in _invalid_calls.items():
                    if target in possible_calls and call_index in possible_calls[target]:
                        # assert call[1] in possible_calls
                        possible_calls[target].remove(call_index)
                        pass

        # for target, call_site in possible_calls.items():
        #     if len(call_site) == 0 and target in fbs:
        #         not_starts.add(target)
        #         fbs.pop(target)
        #         if debug:
        #             print("function start with " + str(target) + " have been removed")

        _fbs = {}
        new_call_graph = {}
        for start in fbs.keys():
            start_tag = instruction_sequence[pc_to_instruction_index[start]].tag_id
            if start_tag in body_tags or start_tag in fallback_tag:
                _fbs[start] = fbs[start]
                new_call_graph[start] = call_graph[start]
            elif start not in possible_calls or len(possible_calls[start]) == 0:
                not_starts.add(start)
                if debug:
                    print("function start with " + str(start) + " have been removed")
            else:
                _fbs[start] = fbs[start]
                new_call_graph[start] = call_graph[start]
        fbs = _fbs
        call_graph = new_call_graph

        func_starts -= not_starts
        _wait_for_exporation -= not_starts

        if delay_flag and threshold1 >= threshold2:
            if debug:
                print("the threshold1 have been reduce {}, current threshold is {}".format(delay_flag, threshold1))
            threshold1 -= delay
            _func_starts = construct_start_pcs(instruction_sequence, basic_blocks, body_tags, fallback_tag,
                                               tag_id_to_pc, tag_map, fsi_results, threshold=threshold1,
                                               not_starts=not_starts)
            new_func_starts = set(_func_starts) - set(func_starts)
            if len(new_func_starts) > 0 and debug:
                print("explore more functions {}".format(new_func_starts))
            _wait_for_exporation |= set(_func_starts) - set(func_starts)
            func_starts = _func_starts

        wait_for_exporation = _wait_for_exporation

    return fbs, call_graph, removed_time


# if __name__ == "__main__":
#     import pickle, os
#
#     dir = "/home/dapp/ssd/personal/neural-FIBD/results/fsi"
#
#     # SOLC_VERSION = ["0.5.17", "d19bba13"]
#     SOLC_VERSION = ["0.4.25", "59dbf8f1"]
#     opt = False
#     optimzied = "-optimized" if opt else "-unoptimized"
#
#     contract_dir = os.path.join(dir, SOLC_VERSION[0] + optimzied)
#
#     files = os.listdir(contract_dir)[:1]
#
#     # files = ['1202']
#
#     error_addrs = []
#
#     for file in files:
#         print(file)
#         with open(os.path.join(contract_dir, file), 'rb') as f:
#             addrs, crf_scores, bmap_lengths_sorted, decoded_time, tag_map = pickle.load(f)
#             crf_scores = crf_scores.to("cpu")
#             bmap_lengths_sorted = bmap_lengths_sorted.to("cpu")
#             for i, addr in enumerate(addrs):
#                 gloden = decode(crf_scores[i], bmap_lengths_sorted[i], tag_map)[:bmap_lengths_sorted[i] - 1]
#                 fb, time = detect_func()
#                 # gloden = _decodeds[i][:bmap_lengths_sorted[i]-1]
#                 flag = gloden.equal(_decoded)
#                 flag2 = gloden.equal(_decodeds[i][:bmap_lengths_sorted[i] - 1])
#                 if not (flag and flag2):
#                     error_addrs.append(addr)
#                 print(addr+" "+str(flag and flag2))
#
#     print(len(error_addrs))
#     print(error_addrs)


