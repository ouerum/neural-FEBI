import os, sys, copy, re

folder = os.path.dirname(__file__)
sys.path.append(folder + "/..")

from disassembly.evmdasm import EvmBytecode
from disassembly.evmdasm import utils


# read the annotation file from instrumented solidity compiler
# output the function entrys, source instructions before optimization,
# instructions after optimized, and the optimized steps
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


# check the "push tag" if push an entry address to perform internal call
def is_internal_call(source_items, item_id):
    # do not perform runtime context check
    if item_id + 1 < len(source_items) and source_items[item_id + 1].startswith('jump\t// in'):
        return True
    # perform runtime check
    elif item_id + 3 < len(source_items) and source_items[item_id + 3].startswith('jump\t// in') and source_items[
        item_id + 2] == 'and':
        return True
    elif item_id + 2 < len(source_items) and source_items[item_id + 2].startswith('jump\t// in') and source_items[
        item_id + 1] == 'and':
        return True
    return False


# find the reachable tags from a start tag
def find_related_tags(tag, source_items, related_tags=None):
    if related_tags is None:
        related_tags = []
    index = 0
    for i, source_item in enumerate(source_items):
        if source_item == "tag_" + str(tag) + ":":
            index = i
    assert index != 0
    while index < len(source_items):
        item = source_items[index]
        _index = index
        index += 1
        # stop explore when the control flow terminate
        if item in ["revert", "return", "invalid", "stop", "selfdestruct"] or \
                (item.startswith("jump") and not item.startswith("jumpi")):
            break
        # fall through to a jumpdest
        if re.match(r"tag_+\d+:", item):
            related_tags.append(int(item[4:-1]))
    return list(set(related_tags))


def safe_check(source_items, old_tag, new_tag):
    index1 = 0
    index2 = 0
    for i, items in enumerate(source_items):
        if items == 'tag_' + str(old_tag) + ":":
            index1 = i
        if items == 'tag_' + str(new_tag) + ":":
            index2 = i
    last_item1 = None
    last_item2 = None
    while index1 < len(source_items):
        item = source_items[index1]
        if item in ["revert", "return", "invalid", "stop", "selfdestruct"] or (
                item.startswith("jump") and not item.startswith("jumpi")):
            last_item1 = item
        index1 += 1
    while index2 < len(source_items):
        item = source_items[index2]
        if item in ["revert", "return", "invalid", "stop", "selfdestruct"] or (
                item.startswith("jump") and not item.startswith("jumpi")):
            last_item2 = item
        index2 += 1
    return last_item2 == last_item1


def find_fall_through_tags(tag, source_items):
    index = 0
    for i, source_item in enumerate(source_items):
        if source_item == "tag_" + str(tag) + ":":
            index = i
    assert index != 0
    related_tags = []
    index = index + 1
    while index < len(source_items):
        item = source_items[index]
        _index = index
        index += 1
        # stop explore when the control flow terminate
        if item in ["revert", "return", "invalid", "stop", "selfdestruct"] or \
                (item.startswith("jump") and not item.startswith("jumpi")):
            break
        # fall through to a jumpdest
        if re.match(r"tag_+\d+:", item):
            related_tags.append(int(item[4:-1]))
    return related_tags


# reconstruct the function boundaries when tag replacement
def replace_push_tag(source_items, replacement, function_boundaries):
    replacement_map = {}  # start_index -> replacement
    old_tag_to_new_tag = {}

    for r in replacement:
        replacement_map[r[0][2]] = r
        assert len(r[1]) == 1 and r[0][3] == r[0][2]
        old_tag = int(source_items[r[0][3]][4:])
        new_tag = int(r[1][0][4:])
        old_tag_to_new_tag[old_tag] = new_tag

    for old_tag, new_tag in old_tag_to_new_tag.items():
        if old_tag == 192:
            a = 111
        assert safe_check(source_items, old_tag, new_tag)
        if old_tag in function_boundaries:
            if new_tag not in function_boundaries:
                function_boundaries[new_tag] = function_boundaries[old_tag]
                function_boundaries.pop(old_tag)

        for entry, boundary in function_boundaries.items():
            if old_tag in boundary:
                jump_number = boundary[old_tag][0]
                # if the old tag can be visited by jumping, we replace the jumping target
                if jump_number > 0:
                    if new_tag in boundary:
                        boundary[new_tag][0] += jump_number
                    else:
                        boundary[new_tag] = [jump_number, False]
                    # the tags which can be visited by fall through from new tag record as part of functions
                    fall_through_tags = find_fall_through_tags(new_tag, source_items)
                    for tag in fall_through_tags:
                        if tag in boundary:
                            function_boundaries[entry][tag][1] = True
                        else:
                            function_boundaries[entry][tag] = [0, True]

                if not boundary[old_tag][1]:
                    function_boundaries[entry].pop(old_tag)
                else:
                    function_boundaries[entry][old_tag][0] = 0
                # delete the old tag if it can not be visited by fall through
                old_fall_through_tags = find_fall_through_tags(old_tag, source_items)
                previous_tag = old_tag
                for tag in old_fall_through_tags:
                    if previous_tag in function_boundaries[entry] and \
                            (not boundary[previous_tag][1] or boundary[previous_tag][0] > 0) and \
                            tag in function_boundaries[entry]:
                        function_boundaries[entry][tag][1] = False
                        if function_boundaries[entry][tag][0] == 0 and not function_boundaries[entry][tag][1]:
                            function_boundaries[entry].pop(tag)
                    previous_tag = tag


    for index, item in enumerate(source_items):
        if index in replacement_map:
            source_items[index] = replacement_map[index][1][0]

    return source_items, function_boundaries


def is_jump2next(source_items, replace_items):
    if (re.match("tag_\d+", source_items[0]) and not re.match("tag_\d+:", source_items[0])
            and re.match("jump", source_items[1]) and source_items[2] == source_items[0] + ":"):
        if len(replace_items) == 1 and replace_items[0] == source_items[2]:
            return int(source_items[0][4:])
    return None


def reconstruct_tag_information(source_items):
    unfall_through_tags = set()
    for i, item in enumerate(source_items):
        if re.match("tag_\d+:", item) and i - 1 > 0 and \
                (source_items[i - 1] in ["revert", "return", "invalid", "stop", "selfdestruct"] or \
                 (source_items[i - 1].startswith("jump") and not source_items[i - 1].startswith("jumpi"))):
            unfall_through_tags.add(int(source_items[i][4:-1]))
    return unfall_through_tags


# peephole: jump2next optimizer
def replace_instr(source_items, replacement, function_boundaries):
    replacement_map = {}  # start_index -> replacement
    for r in replacement:
        replacement_map[r[0][2]] = r

    tgt_items = []
    index = 0
    while index < len(source_items):
        if index in replacement_map:
            start_index = replacement_map[index][0][2]
            end_index = replacement_map[index][0][3]
            tag = is_jump2next(source_items[start_index:end_index + 1], replacement_map[index][1])
            if tag is not None:
                for entry, boundary in function_boundaries.items():
                    if tag in boundary:
                        assert boundary[tag][0] > 0 and not boundary[tag][1]
                        boundary[tag][0] -= 1
                        boundary[tag][1] = True
            tgt_items += replacement_map[index][1]
            index = replacement_map[index][0][3] + 1
        else:
            tgt_items.append(source_items[index])
            index += 1

    unfall_through_tags = reconstruct_tag_information(tgt_items)

    for tag in unfall_through_tags:
        for entry in function_boundaries.keys():
            boundary = function_boundaries[entry]
            if tag in boundary:
                boundary[tag][1] = False
                if boundary[tag][0] == 0:
                    function_boundaries[entry].pop(tag)

    return tgt_items, function_boundaries


# remove the jumpdest in the assembly items
def remove_instr(source_items, removed_tags, function_boundaries):
    removed_tags_map = {}
    removed_tag_ids = set()
    for r in removed_tags:
        removed_tags_map[r[0][2]] = r
        assert re.match("tag_\d+:", source_items[r[0][2]])
        tag_id = source_items[r[0][2]][4:-1]
        removed_tag_ids.add(int(tag_id))

    tgt_items = []
    index = 0
    while index < len(source_items):
        if index in removed_tags_map:
            index += 1
            continue
        tgt_items.append(source_items[index])
        index += 1

    for tag in removed_tag_ids:
        if tag in function_boundaries:
            function_boundaries.pop(tag)

    for entry, boundary in function_boundaries.items():
        for tag in list(boundary.keys()):
            if tag in removed_tag_ids:
                function_boundaries[entry].pop(tag)

    return tgt_items, function_boundaries


def optimise(source_items, optimise_step, function_boundaries):
    optimise_type = optimise_step[0][0][0]
    if optimise_type == 0:  # JUMPDEST REMOVE: remove the tag_id in function boundaries
        source_items, function_boundaries = remove_instr(source_items, optimise_step, function_boundaries)

    elif optimise_type == 1:  # Peephole: induce the number of jump if using jumpToNext
        source_items, function_boundaries = replace_instr(source_items, optimise_step, function_boundaries)

    elif optimise_type == 2:  # Block deduplication: set the number of jump if the tag id in replacement
        source_items, function_boundaries = replace_push_tag(source_items, optimise_step, function_boundaries)

    elif optimise_type == 3:  # CSE: do nothing
        source_items, function_boundaries = replace_instr(source_items, optimise_step, function_boundaries)

    elif optimise_type == 4:  # constant optimizer: do nothing
        source_items, function_boundaries = replace_instr(source_items, optimise_step, function_boundaries)

    return source_items, function_boundaries


def check_jumpdest(source_items, jump_targets):
    for id, item in enumerate(source_items):
        if item.startswith("jump") and item != "jump\t// out" and id not in jump_targets:
            return False
    return True


def compare(asm, source_item):
    if source_item.startswith('data_') or source_item.startswith('dataOffset(sub_') or source_item.startswith(
            'dataSize(sub_') or source_item.startswith('bytecodeSize') or source_item.startswith(
        'linkerSymbol(') or source_item.startswith('deployTimeAddress()'):
        return asm.name.startswith("PUSH")

    elif asm.name.startswith('PUSH'):
        if re.match(r'tag_\d+', source_item) and (not re.match(r"tag_\d+:", source_item)):
            return True
        else:
            try:
                a = int(utils.bytes_to_str(asm.operand_bytes), 16)
                b = int(source_item, 16)
                return a == b
            except:
                return False
            # return int(utils.bytes_to_str(asm.operand_bytes), 16) == int(source_item, 16)

    elif asm.name == 'JUMPDEST' and re.match(r"tag_\d+:", source_item):
        return True

    elif source_item.startswith('jump') and (not source_item.startswith('jumpi')):
        return asm.name == 'JUMP'

    elif source_item == 'selfbalance' and asm.opcode == 71:
        return True

    elif source_item == 'chainid' and asm.opcode == 70:
        return True

    elif asm.name.startswith('UNKNOWN'):
        return source_item == 'invalid'

    elif asm.name.upper() == source_item.upper():
        return True

    elif asm.opcode == 32 and (source_item == 'keccak256' or source_item == 'sha3'):
        return True

    return False


def check_equal(source_items, runtime_bin):
    tag_id_to_pc = {}
    runtime_bytecode = EvmBytecode(runtime_bin)
    runtime_disassembly = runtime_bytecode.disassemble()
    for i, source_item in enumerate(source_items):
        flag = compare(runtime_disassembly[i], source_items[i])
        if flag is False:
            return False
        if re.match(r"tag_\d+:", source_item):
            tag_id = source_item[4:-1]
            pc = runtime_disassembly[i].address
            tag_id_to_pc[int(tag_id)] = pc
    return True, tag_id_to_pc


def split_basic_block(source_items):
    basic_blocks = []
    tag_to_block_id = {}
    current_block_start = 0
    for index, item in enumerate(source_items):
        if index == len(source_items):
            if index - 1 >= current_block_start:
                basic_blocks.append((current_block_start, index - 1))
        elif re.match(r"tag_\d+:", item) and current_block_start != index:
            basic_blocks.append((current_block_start, index - 1))
            current_block_start = index
        elif item in ["revert", "return", "invalid", "selfdestruct", "stop"] or item.startswith("jump"):
            basic_blocks.append((current_block_start, index))
            current_block_start = index + 1

    for id, bb in enumerate(basic_blocks):
        if re.match(r"tag_\d+:", source_items[bb[0]]):
            tagid = int(source_items[bb[0]][4:-1])
            tag_to_block_id[tagid] = id

    return basic_blocks, tag_to_block_id


def append_record(tag, record, t=True):
    if tag not in record:
        record[tag] = [0, False]
    if t:
        record[tag][0] += 1
    else:
        record[tag][1] = True


def compare_source_and_optimized(source_items, optimized_items):
    for s, o in zip(source_items, optimized_items):
        if s == o:
            continue
        elif s == "jump\t// in*" and o == "jump":
            continue
        else:
            return False
    return True


def modify_interface_dispatcher(source_items, public_interfaces, jump_targets, basic_blocks, tag_to_block_id):
    for entry in public_interfaces.keys():
        entry_block_id = tag_to_block_id[entry]
        queue = [entry_block_id]
        visited = []
        while len(queue) != 0:
            block_id = queue.pop()
            if block_id in visited:
                continue
            visited.append(block_id)

            if source_items[basic_blocks[block_id][1]] == 'jump' and \
                    basic_blocks[block_id][1] + 1 < len(source_items) and \
                    re.match("tag_\d+:", source_items[basic_blocks[block_id][1]+1]) and \
                    jump_targets[basic_blocks[block_id][1]] == public_interfaces[entry]:
                source_items[basic_blocks[block_id][1]] = 'jump\t// in*'
                target_tag = int(source_items[basic_blocks[block_id][1]+1][4:-1])
                jump_targets[basic_blocks[block_id][1]] = target_tag
                succ_blocks = [tag_to_block_id[target_tag]]

            elif source_items[basic_blocks[block_id][1]] == 'jump' or source_items[
                basic_blocks[block_id][1]] == 'jump\t// in':
                target_tag = jump_targets[basic_blocks[block_id][1]]
                succ_blocks = [tag_to_block_id[target_tag]]

            elif source_items[basic_blocks[block_id][1]] == 'jumpi':
                target_tag = jump_targets[basic_blocks[block_id][1]]
                succ_blocks = [tag_to_block_id[target_tag], block_id + 1]
            elif source_items[basic_blocks[block_id][1]] in ["return", "revert", "invalid", "jump\t// out",
                                                             "selfdestruct", "stop"]:
                succ_blocks = []
            else:
                assert block_id + 1 < len(basic_blocks)
                succ_blocks = [block_id + 1]

            for succ in succ_blocks:
                queue.append(succ)


# the control flow and function boundaries is clear in unoptimized source items
def detect_fb_unoptimized(source_items, function_entries, jump_targets, basic_blocks, tag_to_block_id):
    function_boundaries = {}
    function_blocks = {}
    for entry in function_entries:
        entry_block_id = tag_to_block_id[entry]
        queue = [entry_block_id]
        visited = []
        function_boundary = {}
        while len(queue) != 0:
            block_id = queue.pop()
            if block_id in visited:
                continue
            visited.append(block_id)

            if source_items[basic_blocks[block_id][1]] == 'jump' or \
                    source_items[basic_blocks[block_id][1]].startswith('jump\t// in'):
                target_tag = jump_targets[basic_blocks[block_id][1]]
                succ_blocks = [tag_to_block_id[target_tag]]
                append_record(target_tag, function_boundary, True)
            elif source_items[basic_blocks[block_id][1]] == 'jumpi':
                target_tag = jump_targets[basic_blocks[block_id][1]]
                succ_blocks = [tag_to_block_id[target_tag], block_id + 1]
                append_record(target_tag, function_boundary, True)
                if re.match("tag_\d+:", source_items[basic_blocks[block_id + 1][0]]):
                    fall_trough_tag = source_items[basic_blocks[block_id + 1][0]][4:-1]
                    append_record(int(fall_trough_tag), function_boundary, False)
            elif source_items[basic_blocks[block_id][1]] in ["return", "revert", "invalid", "jump\t// out",
                                                             "selfdestruct", "stop"]:
                succ_blocks = []
            else:
                assert block_id + 1 < len(basic_blocks)
                succ_blocks = [block_id + 1]
                if re.match("tag_\d+:", source_items[basic_blocks[block_id + 1][0]]):
                    fall_trough_tag = source_items[basic_blocks[block_id + 1][0]][4:-1]
                    append_record(int(fall_trough_tag), function_boundary, False)

            for succ in succ_blocks:
                queue.append(succ)
        function_boundaries[entry] = function_boundary
        function_blocks[entry] = visited
    return function_boundaries, function_blocks


# if function return or not
def is_return(source_items, basic_blocks, function_blocks):
    for block in function_blocks:
        if source_items[basic_blocks[block][1]] == 'jump\t// out':
            return True
    return False


# remove the no-return tags
def reconstruct_function_boundary(source_items, entry, tag_to_block_id, jump_targets, basic_blocks, ret_tag):
    entry_block_id = tag_to_block_id[entry]
    queue = [entry_block_id]
    visited = []
    boundary = {}
    while len(queue) != 0:
        block_id = queue.pop()
        if block_id in visited:
            continue
        visited.append(block_id)
        succ_blocks = []
        if source_items[basic_blocks[block_id][1]] == 'jump' or \
                source_items[basic_blocks[block_id][1]].startswith('jump\t// in'):
            target_tag = jump_targets[basic_blocks[block_id][1]]
            if source_items[basic_blocks[block_id][1]].startswith('jump\t// in') and target_tag != ret_tag:
                succ_blocks = [tag_to_block_id[target_tag]]
                append_record(target_tag, boundary, True)
        elif source_items[basic_blocks[block_id][1]] == 'jumpi':
            target_tag = jump_targets[basic_blocks[block_id][1]]
            succ_blocks = [tag_to_block_id[target_tag], block_id + 1]
            append_record(target_tag, boundary, True)
            if re.match("tag_\d+:", source_items[basic_blocks[block_id + 1][0]]):
                fall_through_tag = source_items[basic_blocks[block_id + 1][0]][4:-1]
                append_record(int(fall_through_tag), boundary, False)
        elif source_items[basic_blocks[block_id][1]] in ["return", "revert", "invalid", "jump\t// out", "selfdestruct",
                                                         "stop"]:
            succ_blocks = []
        else:
            assert block_id + 1 < len(basic_blocks)
            succ_blocks = [block_id + 1]
            if re.match("tag_\d+:", source_items[basic_blocks[block_id + 1][0]]):
                fall_through_tag = source_items[basic_blocks[block_id + 1][0]][4:-1]
                append_record(int(fall_through_tag), boundary, False)

        for succ in succ_blocks:
            queue.append(succ)

    return boundary, visited


# remove the unreached code caused by no returns
def remove_no_returns(source_items, basic_blocks, function_boundaries, function_blocks, tag_to_block_id,
                      jump_targets, fallback):
    call_sites = {}
    # collect return call site
    for entry, blocks in function_blocks.items():
        for block in blocks:
            for id, item in enumerate(source_items[basic_blocks[block][0]:basic_blocks[block][1] + 1]):
                if re.match(r"tag_\d+", item) and (not re.match(r"tag_\d+:", item)) \
                        and is_internal_call(source_items[basic_blocks[block][0]:basic_blocks[block][1] + 1], id):
                    return_tag = jump_targets[basic_blocks[block][1]]
                    tag_id = int(item[4:])
                    if item not in call_sites:
                        call_sites[tag_id] = [(entry, return_tag)]
                    else:
                        call_sites[tag_id].append((entry, return_tag))
    # remove the return site when calling a no-return function
    change = True
    while change:
        wait_for_reconstructing = []
        change = False
        for entry, boundary in function_boundaries.items():
            if entry == fallback:
                continue
            function_block = function_blocks[entry]
            if not is_return(source_items, basic_blocks, function_block) and entry in call_sites:
                wait_for_reconstructing += call_sites[entry]

        for entry, return_tag in wait_for_reconstructing:
            if return_tag in function_boundaries[entry]:
                change = True
                function_boundary, function_block = reconstruct_function_boundary(source_items, entry, tag_to_block_id,
                                                                                  jump_targets, basic_blocks,
                                                                                  return_tag)
                function_blocks[entry] = function_block
                function_boundaries[entry] = function_boundary

    return function_boundaries


# main function for calling
def _analysis(annotation_path, runtime_bin_path, flag=True):
    annotation_str = open(annotation_path).read()
    runtime_bin = open(runtime_bin_path).read()

    if len(runtime_bin) == 0 and len(annotation_str) == 0:
        return True, True, True, {}, None
    elif len(runtime_bin) > 0 and len(annotation_str) > 0:
        source_items, private_function_entrys, public_function_entrys, fallback, jump_targets, opts, optimized_items = read_annotation(
            annotation_str)
        j_flag = check_jumpdest(source_items, jump_targets)

        basic_blocks, tag_to_block_id = split_basic_block(source_items)

        if flag:
            modify_interface_dispatcher(source_items, public_function_entrys, jump_targets, basic_blocks, tag_to_block_id)

        function_boundaries, function_blocks = detect_fb_unoptimized(source_items, private_function_entrys +
                                                                     list(public_function_entrys.values()) +
                                                                     [fallback] +
                                                                     list(public_function_entrys.keys()),
                                                                     jump_targets, basic_blocks, tag_to_block_id)
        # function_boundaries, function_blocks = detect_fb_unoptimized(source_items, public_function_entrys.keys(),
        #                                                              jump_targets, basic_blocks, tag_to_block_id)

        function_boundaries = remove_no_returns(source_items, basic_blocks, function_boundaries, function_blocks,
                                                tag_to_block_id, jump_targets, fallback)
        for _id, optimise_step in enumerate(opts):
            source_items, function_boundaries = optimise(source_items, optimise_step, function_boundaries)

        _function_boundaries = {}
        for entry, boundary in function_boundaries.items():
            _function_boundaries[entry] = [entry] + list(boundary.keys())

        e_flag, tag_id_to_address = check_equal(source_items, runtime_bin)

        public_body = {}
        public_interface = {}
        private_body = {}
        fallback_body = {}

        for entry, fb in _function_boundaries.items():
            if entry in public_function_entrys.keys():
                public_interface[entry] = fb
            elif entry in public_function_entrys.values():
                public_body[entry] = fb
            elif entry in private_function_entrys:
                private_body[entry] = fb
            elif entry == fallback:
                fallback_body[entry] = fb
        _function_boundaries = [public_interface, public_body, private_body, fallback_body]

        # add to new
        _function_boundaries = (_function_boundaries, private_function_entrys, public_function_entrys, fallback)

        return compare_source_and_optimized(source_items, optimized_items), j_flag, e_flag, \
               _function_boundaries, tag_id_to_address

    else:
        return False, False, False, None, None
