import os
import re
import copy
import sys
import signal

import func_timeout.exceptions

folder = os.path.dirname(__file__)
sys.path.append(folder + "/../..")

from application.cfg.acyclic_paths import *
from copy import deepcopy
from func_timeout import func_set_timeout

def read_annotation(annotation_str):
    annotation_list = annotation_str.split("====\n")[1:]
    source_items = annotation_list[0][:-1].split("\n")
    private_function_entrys = []
    if len(annotation_list[1]) > 0:
        private_function_entrys = {int(entry) for entry in annotation_list[1][:-1].split("\n")}

    public_function_entrys = []
    if len(annotation_list[2]) > 0:
        public_function_entrys = annotation_list[2][:-1].split("\n")
    public = {}
    for e in public_function_entrys:
        tmp = e.split('\t')
        public[int(tmp[0])] = int(tmp[1])

    fallback = annotation_list[3][:-1].split("\n")
    assert len(fallback) == 1
    fallback = int(fallback[0])

    private_function_entrys = list(private_function_entrys - set(public.values()) - {fallback})

    jump_target_strs = annotation_list[4][:-1].split("\n")
    jump_targets = {}
    for jump_target in jump_target_strs:
        tmp = jump_target.split(' ')
        jump_targets[int(tmp[0])] = int(tmp[1])

    optimise = []
    for optimize_steps in annotation_list[5].split("===\n")[1:]:
        optimise_tmp = []
        for optimize_steps1 in optimize_steps.split("==\n")[1:]:
            data = optimize_steps1.split("=\n")
            operator_str = data[0][:-1].split(" ")
            operator = (int(operator_str[0]), operator_str[1], int(operator_str[2]), int(operator_str[3]))
            replace_instr = []
            if len(data) > 1:
                replace_instr = data[1][:-1].split("\n")
            optimise_tmp.append((operator, replace_instr))
        optimise.append(optimise_tmp)

    optimized_items = annotation_list[6][:-1].split("\n")

    return source_items, private_function_entrys, public, fallback, jump_targets, optimise, optimized_items



def split_basic_block(source_items):
    basic_blocks = []
    tag_to_block_id = {}
    current_block_start = 0
    for index in range(0, len(source_items)+1):
        if index == len(source_items):
            if index-1 >= current_block_start:
                basic_blocks.append((current_block_start, index-1))
        elif re.match(r"tag_\d+:", source_items[index]) and current_block_start != index:
            basic_blocks.append((current_block_start, index-1))
            current_block_start = index
        elif source_items[index] in ["revert", "return", "stop", "invalid", "selfdestruct"] or source_items[index].startswith("jump"):
            basic_blocks.append((current_block_start, index))
            current_block_start = index + 1

    for id, bb in enumerate(basic_blocks):
        if re.match(r"tag_\d+:", source_items[bb[0]]):
            tagid = int(source_items[bb[0]][4:-1])
            tag_to_block_id[tagid] = id

    return basic_blocks, tag_to_block_id


def build_cfg(source_items, basic_blocks, function_entry, jump_targets, tag_to_block_id):
    entry_block_id = tag_to_block_id[function_entry]
    queue = [entry_block_id]
    visited = []
    _function_edges = []
    while len(queue) != 0:
        current_block_id = queue.pop()
        if current_block_id in visited:
            continue
        visited.append(current_block_id)
        if source_items[basic_blocks[current_block_id][1]] == 'jump' or source_items[basic_blocks[current_block_id][1]] == 'jump\t// in':
            target_tag = jump_targets[basic_blocks[current_block_id][1]]
            succ_blocks = [tag_to_block_id[target_tag]]
        elif source_items[basic_blocks[current_block_id][1]] == 'jumpi':
            target_tag = jump_targets[basic_blocks[current_block_id][1]]
            succ_blocks = [tag_to_block_id[target_tag]]
            succ_blocks.append(current_block_id+1)
        elif source_items[basic_blocks[current_block_id][1]] in ["return", "revert", "invalid", "selfdestruct", "stop", "jump\t// out"]:
            succ_blocks = []
        else:
            succ_blocks = [current_block_id+1]

        for succ in succ_blocks:
            _function_edges.append((current_block_id, succ))
            queue.append(succ)

    function_nodes = visited
    function_edges = []
    block_id_to_node_id = {}
    for node_id, block_id in enumerate(visited):
        block_id_to_node_id[block_id] = node_id
    for edge in _function_edges:
        source_block_id = edge[0]
        tgt_block_id = edge[1]
        function_edges.append((block_id_to_node_id[source_block_id], block_id_to_node_id[tgt_block_id]))
    return function_nodes, function_edges


def extract_source_path(function_node, function_edges, func_entry_index):
    acyclic_paths = get_function_acyclic_path(function_node, function_edges, func_entry_index)
    return acyclic_paths


def combine_basic_block(basic_blocks, source_items):
    block_id = 0
    combine = []
    _combine = []
    while block_id < len(basic_blocks.keys()):

        basic_block = basic_blocks[block_id]
        _combine.append(block_id)
        _items = source_items[basic_block[0]:basic_block[1]+1]
        if len(_items) > 0:
            if _items[-1].startswith('jump') or _items[-1] in ["revert", "return", "stop", "invalid", "selfdestruct"]:
                combine.append(_combine)
                _combine = []
            elif basic_blocks[block_id][1] + 1 < len(source_items) and re.match(r"tag_\d+:", source_items[basic_blocks[block_id][1]+1]):
                combine.append(_combine)
                _combine = []
            elif block_id + 1 == len(basic_blocks.keys()):
                combine.append(_combine)
                _combine = []

        elif len(_combine) == 1:
            combine.append(_combine)
            _combine = []
        block_id += 1

    _basic_blocks = {}
    for c in combine:
        start = basic_blocks[c[0]][0]
        end = basic_blocks[c[-1]][1]
        _basic_blocks[c[0]] = (start, end)
        index = 1
        while index < len(c):
            _basic_blocks[c[index]] = (-1, -1)
            index += 1

    assert len(basic_blocks) == len(_basic_blocks)

    return _basic_blocks


def remove_instr(source_items, removed_tags, basic_blocks):
    new_basic_block = {}
    start_index_to_block_id = {}
    for block_id, block in basic_blocks.items():
        if block[0] != -1:
            start_index_to_block_id[block[0]] = block_id
        elif block[0] == block[1] == -1:
            new_basic_block[block_id] = (-1, -1)

    removed_tags_map = {}
    for r in removed_tags:
        removed_tags_map[r[0][2]] = r

    tgt_items = []
    index = 0
    current_block_id = 0
    start_index = 0
    while index < len(source_items) + 1:
        if index == len(source_items):
            if start_index > len(tgt_items) - 1:
                new_basic_block[current_block_id] = (-1, -1)
            else:
                new_basic_block[current_block_id] = (start_index, len(tgt_items)-1)
            break

        if index in start_index_to_block_id and index != 0:
            if start_index > len(tgt_items) - 1:
                new_basic_block[current_block_id] = (-1, -1)
            else:
                new_basic_block[current_block_id] = (start_index, len(tgt_items) - 1)
            current_block_id = start_index_to_block_id[index]
            start_index = len(tgt_items)

        if index in removed_tags_map:
            index += 1
            continue
        tgt_items.append(source_items[index])

        index += 1

    new_basic_block = combine_basic_block(new_basic_block, tgt_items)

    return tgt_items, new_basic_block


def is_optimized_tag(source_items, tgt_items):
    if len(tgt_items) > 0 and re.match(r"tag_\d+:", tgt_items[-1]) and re.match(r"tag_\d+:", source_items[-1]):
            return True
    return False


def _is_optimized_unreachcode(tgt_item):
    if ((tgt_item.startswith("jump") and (not tgt_item.startswith(
            "jumpi"))) or tgt_item == "return" or tgt_item == "stop" or tgt_item == "invalid" or tgt_item == "selfdestruct" or tgt_item == "revert"):
        return True
    return False


def is_optimized_unreachcode(source_items, tgt_items):
    if len(tgt_items) == 1 and _is_optimized_unreachcode(tgt_items[0]) and len(
            source_items) > 1 and _is_optimized_unreachcode(source_items[0]):
        return True
    return False


def get_replacement_type(source_items, tgt_items):
    if is_optimized_tag(source_items, tgt_items):
        return 0
    elif is_optimized_unreachcode(source_items, tgt_items):
        return 1
    elif len(tgt_items) == 0:
        return 2
    else:
        assert False


def check(source_items):
    bb, _ = split_basic_block(source_items)
    return len(bb)


def replace_instr(source_items, replacement, basic_blocks):
    new_basic_block = {}
    start_index_to_block_id = {}
    for block_id, block in basic_blocks.items():
        if block[0] != -1:
            start_index_to_block_id[block[0]] = block_id
        elif block[0] == block[1] == -1:
            new_basic_block[block_id] = (-1, -1)

    replacement_map = {} # start_index -> replacement
    for r in replacement:
        replacement_map[r[0][2]] = r

    current_block_id = 0

    tgt_items = []
    index = 0
    start_index = 0
    while index < len(source_items)+1:
        if index == len(source_items):
            new_basic_block[current_block_id] = (start_index, len(tgt_items)-1)
            break

        if index in start_index_to_block_id and index != 0:
            if start_index > len(tgt_items) - 1:
                new_basic_block[current_block_id] = (-1, -1)
            else:
                new_basic_block[current_block_id] = (start_index, len(tgt_items) - 1)
            current_block_id = start_index_to_block_id[index]
            start_index = len(tgt_items)

        if index in replacement_map:
            end_basic_block_id = current_block_id
            while basic_blocks[end_basic_block_id][1] < replacement_map[index][0][3]:
                end_basic_block_id += 1

            if current_block_id != end_basic_block_id:
                replacement_type = get_replacement_type(
                    source_items[replacement_map[index][0][2]:replacement_map[index][0][3] + 1],
                    replacement_map[index][1])
                if replacement_type == 0:
                    source_bb_num = check(source_items[replacement_map[index][0][2]:replacement_map[index][0][3] + 1])
                    tgt_bb_num = check(replacement_map[index][1])
                    assert source_bb_num <= 2 and tgt_bb_num <= 2
                    if source_bb_num == tgt_bb_num == 2:
                        new_basic_block[current_block_id] = (start_index, len(tgt_items)+len(replacement_map[index][1])-2)
                        start_index = len(tgt_items)+len(replacement_map[index][1]) - 1
                        current_block_id = start_index_to_block_id[replacement_map[index][0][3]]
                    elif source_bb_num == 2 and tgt_bb_num == 1:
                        new_basic_block[current_block_id] = (start_index, len(tgt_items)+len(replacement_map[index][1])-2)
                        start_index = len(tgt_items)+len(replacement_map[index][1]) - 1
                        current_block_id = start_index_to_block_id[replacement_map[index][0][3]]
                    else:
                        assert False
                elif replacement_type == 1:
                    new_basic_block[current_block_id] = (start_index, len(tgt_items)+len(replacement_map[index][1])-1)
                    _block_id = current_block_id+1
                    while _block_id <= end_basic_block_id:
                        new_basic_block[_block_id] = (-1, -1)
                        _block_id += 1

                elif replacement_type == 2:
                    new_basic_block[current_block_id] = (start_index, len(tgt_items)-1)
                else:
                    assert False

            tgt_items += replacement_map[index][1]
            index = replacement_map[index][0][3] + 1

        else:
            tgt_items.append(source_items[index])
            index += 1

    _new_basic_block = {}
    for k, v in new_basic_block.items():
        if v[0] > v[1]:
            _new_basic_block[k] = (-1, -1)
        else:
            _new_basic_block[k] = v

    assert len(_new_basic_block) == len(basic_blocks)

    _new_basic_block = combine_basic_block(_new_basic_block, tgt_items)
    return tgt_items, _new_basic_block


def replace_push_tag(source_items, replacement, basic_blocks, acyclic_paths, jump_target, unoptimized_itmes, unoptimized_blocks):
    start_index_to_block_id = {}
    for block_id, block in basic_blocks.items():
        if block[0] != -1:
            start_index_to_block_id[block[0]] = block_id

    replacement_map = {}  # start_index -> replacement

    old_tag_to_new_tag = {}
    for r in replacement:
        replacement_map[r[0][2]] = r
        assert len(r[1]) == 1 and r[0][3] == r[0][2]
        old_tag = int(source_items[r[0][3]][4:])
        new_tag = int(r[1][0][4:])
        old_tag_to_new_tag[old_tag] = new_tag

    tag_to_block_id = {}
    for id, bb in basic_blocks.items():
        if re.match(r"tag_\d+:", source_items[bb[0]]):
            tagid = int(source_items[bb[0]][4:-1])
            tag_to_block_id[tagid] = id

    for old_tag, new_tag in old_tag_to_new_tag.items():
        replaced_blocks_map = get_replace_blocks(old_tag, new_tag, tag_to_block_id, basic_blocks, start_index_to_block_id, source_items, jump_target, unoptimized_itmes, unoptimized_blocks)
        replace_acyclic_paths(acyclic_paths, replaced_blocks_map,  basic_blocks, source_items)

    for index, item in enumerate(source_items):
        if index in replacement_map:
            source_items[index] = replacement_map[index][1][0]

    return source_items


def replace_acyclic_paths(acyclic_paths, replaced_blocks, basic_blocks, source_items):
    for id, acyclic_path in enumerate(acyclic_paths):
        flag, _acyclic_path = _replace_acyclic_paths(acyclic_path, replaced_blocks, basic_blocks, source_items)
        if flag:
            acyclic_paths[id] = _acyclic_path


def check_pred_block(acyclic_path, current_index, basic_blocks, source_items):
    index = current_index - 1
    while index >= 0:
        current_block_id = acyclic_path[index]
        if basic_blocks[current_block_id][0] != -1 and basic_blocks[current_block_id][1] != -1:
            if source_items[basic_blocks[current_block_id][1]].startswith('jump'):
                return True
            else:
                return False
        index -= 1
    return True


def _replace_acyclic_paths(acyclic_path, replaced_blocks, basic_blocks, source_items):
    start_block = replaced_blocks[0]
    index = 0
    # for index, block_id in enumerate(acyclic_path):
    changed = False
    while index < len(acyclic_path):
        block_id = acyclic_path[index]
        if block_id == start_block and check_pred_block(acyclic_path, index, basic_blocks, source_items):
            max_len = 0
            for length in sorted(replaced_blocks[1].keys()):
                replace = replaced_blocks[1][length]
                if acyclic_path[index:index+length] == replace[0]:
                    max_len = length

            if max_len != 0:
                acyclic_path = acyclic_path[:index]+replaced_blocks[1][max_len][1]+acyclic_path[index+max_len:]
                index = index+max_len
                changed = True
        index += 1
    return changed, acyclic_path


def get_replace_blocks(old_tag, new_tag, tag_to_block_id, basic_blocks, start_index_to_block_id, source_items, jump_target, unoptimized_itmes, unoptimized_blocks):
    source_start_block_id = tag_to_block_id[old_tag]
    replaced_start_block_id = tag_to_block_id[new_tag]

    source_tag_index = basic_blocks[source_start_block_id][0]
    replaced_tag_index = basic_blocks[replaced_start_block_id][0]

    source_blocks = findallblocks(source_tag_index, source_items, start_index_to_block_id)
    replaced_blocks = findallblocks(replaced_tag_index, source_items, start_index_to_block_id)

    source_blocks_to_replaced_blocks = map_blocks(source_blocks, replaced_blocks, basic_blocks, old_tag, new_tag, source_items, jump_target, unoptimized_itmes, unoptimized_blocks)

    return source_start_block_id, source_blocks_to_replaced_blocks


def findallblocks(tag_index, source_items, start_index_to_block):
    assert re.match('tag_\d+:', source_items[tag_index])
    index = tag_index
    start_block_id = start_index_to_block[tag_index]
    end_block_id = start_index_to_block
    while index < len(source_items):
        if index in start_index_to_block:
            end_block_id = start_index_to_block[index]
        item = source_items[index]
        if item in ["revert", "return", "invalid", "stop","selfdestruct"] or (
                    item.startswith("jump") and not item.startswith("jumpi")):
            break
        index += 1

    return range(start_block_id, end_block_id+1)


def remove_tag_and_selfpush(items, self_push_tag):
    _items = []
    for item in items:
        if re.match(r"tag_\d+:", item):
            continue
        elif item == "tag_"+str(self_push_tag):
            _items.append("tag_self")
        else:
            _items.append(item)
    return _items


def compare_items(items1, items2, self_push_tag1, self_push_tag2):
    _items1 = remove_tag_and_selfpush(items1, self_push_tag1)
    _items2 = remove_tag_and_selfpush(items2, self_push_tag2)

    if len(_items1) != len(_items2):
        return False
    index = 0
    while index < len(_items1):
        _item1 = _items1[index]
        _item2 = _items2[index]
        if _item1 != _item2:
            if (_item1.startswith("jump") and (not _item1.startswith("jumpi"))) and (_item2.startswith("jump") and (not _item2.startswith("jumpi"))):
                index += 1
                continue
            return False
        index += 1

    return True


def get_all_path(sorted_source_blocks, jump_target, unoptimized_items, unoptimized_blocks):

    self_tag_block_id = {}
    for block in sorted_source_blocks:
        first_item = unoptimized_items[unoptimized_blocks[block][0]]
        if re.match(r'tag_\d+:', first_item):
            self_tag_block_id[int(first_item[4:-1])] = block

    edges = []
    nodes = []
    block_to_node_id = {}
    exit = set()
    for block in sorted_source_blocks:
        block_to_node_id[block] = len(nodes)
        nodes.append(block)
        items = unoptimized_items[unoptimized_blocks[block][0]:unoptimized_blocks[block][1] + 1]
        if items[-1].startswith('jumpi'):
            target_tag = jump_target[unoptimized_blocks[block][1]]
            if target_tag in self_tag_block_id:
                edges.append((block, self_tag_block_id[target_tag]))
            else:
                exit.add(block)
            if block + 1 in sorted_source_blocks:
                edges.append((block, block+1))

        elif items[-1].startswith('jump') and items[-1] != 'jump\t// out':
            target_tag = jump_target[unoptimized_blocks[block][1]]
            if target_tag in self_tag_block_id:
                edges.append((block, self_tag_block_id[target_tag]))
            else:
                exit.add(block)

        elif items[-1] in ["revert", "return", "stop", "invalid", "selfdestruct"]:
            exit.add(block)

        else:
            if block + 1 in sorted_source_blocks:
                edges.append((block, block+1))

    _edges = []
    for edge in edges:
        _edges.append((block_to_node_id[edge[0]], block_to_node_id[edge[1]]))

    # _exit = set()
    # for e in exit:
    #     _exit.add(block_to_node_id[e])
    # todo: the bugs?
    path = get_acyclic_path(nodes, _edges, 0)

    return path


def get_items(paths, source_items, basic_blocks):
    path_items = []
    for index, path1 in enumerate(paths):
        s_items = []
        for block_id in path1:
            s_items += source_items[basic_blocks[block_id][0]:basic_blocks[block_id][1]+1]
        path_items.append(s_items)
    return path_items


def map_blocks(source_blocks, replaced_blocks, basic_blocks, self_push_tag1, self_push_tag2, source_items, jump_target, unoptimized_itmes, unoptimized_blocks):
    sorted_source_blocks = sorted(source_blocks)
    sorted_replaced_blocks = sorted(replaced_blocks)

    paths1 = get_all_path(sorted_source_blocks, jump_target, unoptimized_itmes, unoptimized_blocks)
    paths2 = get_all_path(sorted_replaced_blocks, jump_target, unoptimized_itmes, unoptimized_blocks)

    # assert len(paths1) == len(paths2)
    assert len(paths1) > 0

    path_items1 = get_items(paths1, source_items, basic_blocks)
    path_items2 = get_items(paths2, source_items, basic_blocks)

    replaced_map = {}
    for i, _path_items1 in enumerate(path_items1):
        for j, _path_items2 in enumerate(path_items2):
            if compare_items(_path_items1, _path_items2, self_push_tag1, self_push_tag2):
                replaced_map[len(paths1[i])] = (paths1[i], paths2[j])

    return replaced_map


def optimise_contract(source_items, optimise_step, basic_blocks, acyclic_paths, jump_target, unoptimized_itmes, unoptimized_blocks):
    optimise_type = optimise_step[0][0][0]

    if optimise_type == 0:
        tgt_items, basic_blocks = remove_instr(source_items, optimise_step, basic_blocks)

    elif optimise_type == 1:
        tgt_items, basic_blocks = replace_instr(source_items, optimise_step, basic_blocks)

    elif optimise_type == 2:
        tgt_items = replace_push_tag(source_items, optimise_step, basic_blocks, acyclic_paths, jump_target, unoptimized_itmes, unoptimized_blocks)

    elif optimise_type == 3:
        tgt_items, basic_blocks = replace_instr(source_items, optimise_step, basic_blocks)

    elif optimise_type == 4:
        tgt_items, basic_blocks = replace_instr(source_items, optimise_step, basic_blocks)

    else:
        assert False

    return tgt_items, basic_blocks


def print_bb(basic_blocks, source_items):
    s = ""
    for i, bb in basic_blocks.items():
        s += '==='+str(i)+'===\n'
        s += '\n'.join(source_items[bb[0]:bb[1]+1])
        s += '\n======\n'
    s += '\n'
    return s


def check_basic_block(basic_blocks):
    current_index = 0
    for id in sorted(basic_blocks.keys()):
        bb = basic_blocks[id]
        if bb[0] == bb[1] == -1:
            continue
        assert bb[0] == current_index
        current_index = bb[1] + 1


def extract_optimized_acyclic_paths(annotation_path, runtime_bin_path):
    annotation_str = open(annotation_path).read()
    runtime_bin = open(runtime_bin_path).read()

    if len(runtime_bin) == 0 and len(annotation_str) == 0:
        return True, {}, None, None, None
    elif len(runtime_bin) > 0 and len(annotation_str) > 0:
        source_items, private_function_entrys, public, fallback, jump_targets, optimise, optimized_items = read_annotation(annotation_str)
        unoptimized_items = deepcopy(source_items)
        basic_blocks, tag_to_block_id = split_basic_block(source_items)
        basic_blocks = {k: v for k, v in enumerate(basic_blocks)}
        unoptimized_basic_blocks = deepcopy(basic_blocks)
        function_entrys = [body_entry for _, body_entry in public.items()] + private_function_entrys
        contract_acyclic_paths = []
        for function_entry in function_entrys:
            function_node, function_edges = build_cfg(source_items, basic_blocks, function_entry, jump_targets, tag_to_block_id)
            try:
                acyclic_paths = extract_source_path(function_node, function_edges, tag_to_block_id[function_entry])
            except func_timeout.exceptions.FunctionTimedOut as e:
                continue
            contract_acyclic_paths += acyclic_paths

        fallback_node, fallback_edges = build_cfg(source_items, basic_blocks, fallback, jump_targets, tag_to_block_id)
        try:
            acyclic_paths = extract_source_path(fallback_node, fallback_edges, tag_to_block_id[fallback])
        except func_timeout.exceptions.FunctionTimedOut as e:
            acyclic_paths = []
        contract_acyclic_paths += acyclic_paths

        check_basic_block(basic_blocks)

        for optimise_step in optimise:
            source_items, basic_blocks = optimise_contract(source_items, optimise_step, basic_blocks,
                                                           contract_acyclic_paths, jump_targets, unoptimized_items,
                                                           unoptimized_basic_blocks)
            check_basic_block(basic_blocks)

        paths = []
        for acyclic_path in contract_acyclic_paths:
            path = []
            for b in acyclic_path:
                if basic_blocks[b][0] == basic_blocks[b][1] == -1:
                    continue
                block_entry = basic_blocks[b][0]
                path.append(block_entry)
            paths.append(path)

        return source_items == optimized_items, paths, basic_blocks, optimized_items

    else:
        return False, [], None, None



# def test(solc_dir):
#     instrumented_solc_path = "/home/dapp/ssd/personal/oueru/experiment/projects/instrumented_solidity/build/solc/solc"
#     tmp_path = "/home/dapp/personal/oueru/experiment/tmp/"
#     infos = open(solc_dir + '/' + 'info').read()
#     contract_name = infos.split('\n')[0]
#     instrumented_tmp_path = tmp_path+'instrument/'
#     os.system(
#         instrumented_solc_path + ' ' + solc_dir + '/code.sol' + ' --bin-runtime --cfg-annotation --optimize -o ' + instrumented_tmp_path + ' > ' + instrumented_tmp_path + 'null 2>&1')
#
#     annotation_path = instrumented_tmp_path + contract_name + '.cfg_annotation'
#     runtime_path = instrumented_tmp_path + contract_name + '.bin-runtime'
#
#     r, contract_acyclic_paths, basic_blocks, optimized_items = extract_optimized_acyclic_paths(annotation_path)
#
#     with open(instrumented_tmp_path + contract_name+'.acyclic_path', 'wb') as f:
#         pickle.dump((contract_acyclic_paths, basic_blocks, optimized_items), f)
#
#     for i, path in enumerate(contract_acyclic_paths):
#         str_r = 'path:'+str(i) + '\n'
#         for bb in path:
#             if basic_blocks[bb][0] == basic_blocks[bb][1] == -1:
#                 continue
#             str_r += '===='+str(bb)+'====\n'
#             str_r += '\n'.join(optimized_items[basic_blocks[bb][0]:basic_blocks[bb][1]+1])
#             str_r += '\n'
#         print(str_r)
#
#     print('=======')
#     for p in contract_acyclic_paths:
#         print([b for b in p if basic_blocks[b][0]!=-1])


# test("/home/dapp/ssd/tmp/test/2/")


# if __name__ == '__main__':
#     passed_address_path = "/home/dapp/ssd/personal/oueru/experiment/result/cfg_annotations/result/passed_address"
#     contract_dir = "/home/dapp/ssd/personal/oueru/experiment/result/cfg_annotations/data/"
#     passed_addresses = open(passed_address_path).read().split('\n')
#     output_dir = "/home/dapp/ssd/personal/oueru/experiment/result/cfg_annotations/acyclic_paths/"
#     # passed_addresses = ["0xa28aed076ee69fc20b3fa1917aa0928291cfdeee"]
#     for id, contract_address in enumerate(passed_addresses):
#         if os.path.exists(contract_dir+contract_address+'/info'):
#             print(str(id) + " " + contract_address, end='')
#             try:
#             # if True:
#                 sys.stdout.flush()
#                 infos = open(contract_dir + contract_address + '/' + 'info').read()
#                 contract_name = infos.split('\n')[0]
#                 with Timeout(sec=60):
#                 # if True:
#                     r, contract_acyclic_paths, basic_blocks, optimized_items = extract_optimized_acyclic_paths(contract_dir+contract_address+'/'+contract_name+'.cfg_annotation')
#                     # for i, path in enumerate(contract_acyclic_paths):
#                     #     str_r = 'path:' + str(i) + '\n'
#                     #     for bb in path:
#                     #         if basic_blocks[bb][0] == basic_blocks[bb][1] == -1:
#                     #             continue
#                     #         str_r += '====' + str(bb) + '====\n'
#                     #         str_r += '\n'.join(optimized_items[basic_blocks[bb][0]:basic_blocks[bb][1] + 1])
#                     #         str_r += '\n'
#                     #     print(str_r)
#                     #
#                     # print('=======')
#                     # print(contract_acyclic_paths)
#                 if r:
#                     with open(output_dir+'data/'+contract_address, 'wb') as f:
#                         pickle.dump((contract_acyclic_paths, basic_blocks, optimized_items), f)
#                     print(".")
#                 else:
#                     print("-")
#             except TimeoutError:
#                 print('timeout')
#                 with open(output_dir+'timeout', 'a+') as f:
#                     f.write(contract_address+'\n')
#             except Exception as e:
#                 print('unkonwn error')
#                 with open(output_dir+'except', 'a+') as f:
#                     f.write(contract_address+'\n')
#                     f.write(str(e))
#                     f.write('========='+'\n')
#         else:
#             print('*')
#         sys.stdout.flush()
#
