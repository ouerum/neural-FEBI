#!/usr/local/bin/python3
#
# This file contains control flow analysis functions.    
#
# Author: Dr. Wang
# 
import sys, os  # @UnusedImport
from queue import Queue

import func_timeout.exceptions
from func_timeout import func_set_timeout

from FBD.tag_recognize import global_data_flow_analysis, recognize_tag, find_omission

folder = os.path.dirname(__file__)
sys.path.append(os.path.normpath(folder + "/.."))
from data_flow_analysis import backward_local_dataflow_analysis
from application.cfg.acyclic_paths import get_function_acyclic_path


def tag_stack_analyse(disassembly, _tag_stack):
    #assume: 1.only push tag and jump could change the tag_stack
    #2.the push 0x...ffff and could not change the tag_stack

    # analyse block tag_stack and assume each node just have only one tag_stack
    import copy
    tag_stack = copy.deepcopy(_tag_stack)

    for i in range(len(disassembly)):
        if disassembly[i].tag_id != None and disassembly[i].name.startswith("PUSH"):
            tag_stack.append(disassembly[i].tag_id)
        else:
            if disassembly[i].name in ['REVERT', 'RETURN', 'STOP']:
                # assert len(tag_stack) == 0
                return []
            elif disassembly[i].name in ['JUMP', 'JUMPI']:
                assert len(tag_stack) > 0
                tag_stack.pop()
                if disassembly[i].annotation == '[in]':
                    assert len(tag_stack) > 0
                    tag_stack.pop()
                elif disassembly[i].annotation == '[out]':
                    # assert len(tag_stack) == 0
                    pass
            elif disassembly[i].annotation == '*[in]':
                assert len(tag_stack) > 0
                tag_stack.pop()
            elif disassembly[i].name.startswith('DUP'):
                pc_stack = backward_local_dataflow_analysis(disassembly, i, True)
                dup_data = pc_stack[int(disassembly[i].name[3:])-1]
                if  dup_data != None and disassembly[dup_data[1]].tag_id != None:
                    tag_stack.append(disassembly[-1*dup_data[1]].tag_id)

    return tag_stack


# Get the basic blocks
def get_all_basic_blocks(instruction_sequences):
    basic_blocks = []
    current_block_start = 0
    for i in range(0, len(instruction_sequences) + 1):

        if i == len(instruction_sequences):
            if i - 1 >= current_block_start:
                basic_blocks.append((current_block_start, i - 1))

        elif instruction_sequences[i].name == "JUMPDEST" and not current_block_start == i:

            assert (current_block_start <= i - 1)
            basic_blocks.append((current_block_start, i - 1))
            current_block_start = i

        elif instruction_sequences[i].name in ["JUMP", "JUMPI", "STOP", "REVERT", "RETURN",
                                               "INVALID", "SELFDESTRUCT"]:
            assert (current_block_start <= i)
            basic_blocks.append((current_block_start, i))
            current_block_start = i + 1

    return basic_blocks


# This function enumerates all acyclic paths in the current cfg that ends with a specific node_id
# For each acyclic path, we apply the path_func on it. 
def enumerate_acyclic_paths(current_node_id, target_node_id, cfg_nodes, cfg_edges, current_path, path_func,
                            path_func_params):
    # Add the current node to the current_path
    current_path.append(current_node_id)

    if current_node_id == target_node_id:
        # End of acyclic path.
        result = path_func(current_path, cfg_nodes, cfg_edges, path_func_params)
        return result

    result = True
    for t in cfg_edges[current_node_id]:
        next_node_id = t[0]

        if next_node_id in current_path:
            # This is a back-edge
            continue

        new_path = list(current_path)
        result = enumerate_acyclic_paths(next_node_id, target_node_id, cfg_nodes, cfg_edges, new_path, path_func,
                                         path_func_params)
        if not result:
            break

    return result


# Collect the return sites
def collect_return_site(current_path, cfg_nodes, cfg_edges, path_func_params):  # @UnusedVariable
    # print("=============")
    assert (len(current_path) > 0 and current_path[0] == 0)

    return_sites = path_func_params[0]
    basic_blocks = path_func_params[1]
    instruction_sequence = path_func_params[2]
    pc_to_instruction_index = path_func_params[3]
    instruction_index_to_block_id = path_func_params[4]

    target_node_id = current_path[-1]
    target_basic_block_id = cfg_nodes[target_node_id]
    block_end = basic_blocks[target_basic_block_id][1]

    pc_stack = []
    instr = []
    for k in range(0, len(current_path)):
        node_id = current_path[k]
        basic_block_id = cfg_nodes[node_id]
        block_start = basic_blocks[basic_block_id][0]
        block_end = basic_blocks[basic_block_id][1]

        for i in range(block_start, block_end + 1):
            # print(str(instruction_sequence[i])+ " "+str(pc_stack)+" "+str(instruction_sequence[i].src_range))
            if instruction_sequence[i].name in ["JUMP", "JUMPI"]:
                pc_stack.pop(0)
                if instruction_sequence[i].annotation == "[in]" and k != len(current_path) - 1:
                    # One additional pop for the return address of function call
                    pc_stack.pop(0)
            elif instruction_sequence[i].name != "JUMPDEST" and instruction_sequence[i].tag_id != None:
                assert (instruction_sequence[i].name.startswith("PUSH"))
                pc_stack.insert(0, int(instruction_sequence[i].operand, 16))
            elif instruction_sequence[i].name.startswith("DUP"):
                tmp_stack = backward_local_dataflow_analysis(instruction_sequence, i, True)
                dup_item = int(instruction_sequence[i].name[3:])
                dup_data = tmp_stack[dup_item - 1]
                if dup_data != None and instruction_sequence[dup_data[1]].tag_id != None:
                    pc_stack.insert(0, int(instruction_sequence[dup_data[1]].operand, 16))
        instr += instruction_sequence[block_start:block_end+1]

    # pc_stack[0]  will be the return site

    if len(pc_stack) > 0:
        pc = pc_stack[0]
        idx = pc_to_instruction_index[pc]
        return_sites.add(instruction_index_to_block_id[idx])

    # Find one is enough
    return False


# Add a new node into the current cfg. Handle the case of block deduplication
def add_new_node(instruction_sequence, basic_blocks, current_node_id, target_block_id, cfg_nodes, cfg_edges,
                 cfg_node_to_tag_stack, edge_label=None):
    node_ids = []
    for i in range(0, len(cfg_nodes)):
        if cfg_nodes[i] == target_block_id:
            node_ids.append(i)

    current_tag_stack = cfg_node_to_tag_stack[current_node_id]
    current_node_block_start = basic_blocks[cfg_nodes[current_node_id]][0]
    current_node_block_end = basic_blocks[cfg_nodes[current_node_id]][1]
    # analyse the entry tag_info of the new tag
    new_tag_stack = tag_stack_analyse(instruction_sequence[current_node_block_start:current_node_block_end + 1],
                                      current_tag_stack)

    changed = False
    if len(node_ids) == 0:

        # target_block_id has not been explored. Create a new node
        new_node_id = len(cfg_nodes)
        cfg_nodes.append(target_block_id)
        cfg_edges[current_node_id].append((new_node_id, edge_label))
        cfg_edges[new_node_id] = []
        cfg_node_to_tag_stack.append(new_tag_stack)
        changed = True

    else:

        # There already exists more than one node(s) with target_block_id.
        # For each existing node, we need to find whether it is an deduplicated block instance.
        duplicate_flag = True
        i = 0
        for index, node_id in enumerate(node_ids):
            tag_stack = cfg_node_to_tag_stack[node_id]
            i = index
            if new_tag_stack == tag_stack:
                """may cycle"""
                duplicate_flag = False
                break

        """new node's entry tag_info is different with before, not cycle, duplicate the block"""
        if duplicate_flag:
            # assert False
            new_node_id = len(cfg_nodes)
            new_tag_stack = tag_stack_analyse(instruction_sequence[current_node_block_start:current_node_block_end + 1],
                                              current_tag_stack)
            cfg_nodes.append(target_block_id)
            cfg_edges[current_node_id].append((new_node_id, edge_label))
            cfg_edges[new_node_id] = []
            cfg_node_to_tag_stack.append(new_tag_stack)
            changed = True
            return changed

        found = False
        for edge in cfg_edges[current_node_id]:
            if edge[0] == node_ids[i]:
                # assert(edge[1]==edge_label)
                found = True
                break
        if not found:
            cfg_edges[current_node_id].append((node_ids[i], edge_label))
            assert node_ids[i] < len(cfg_nodes)
            changed = True

    return changed


# Whether instruction_sequence[i] is a direct jump
def is_direct_jump(instruction_sequence, i):
    # TODO: contain bug? we must backward analysis all basicblock to decide if it's indirect jum
    assert (instruction_sequence[i].name == "JUMP")
    if instruction_sequence[i - 1].name.startswith("PUSH") and instruction_sequence[i - 1].tag_id != None:
        return True
    if instruction_sequence[i - 1].name == "AND" and instruction_sequence[i - 2].name.startswith("PUSH"):
        return True

    return False


# Collect the pc stack top at the end of target_node_id
def collect_last_jump(current_path, cfg_nodes, cfg_edges, path_func_params):  # @UnusedVariable

    assert (len(current_path) > 0 and current_path[0] == 0)

    last_jumps = path_func_params[0]
    basic_blocks = path_func_params[1]
    instruction_sequence = path_func_params[2]
    pc_to_instruction_index = path_func_params[3]
    instruction_index_to_block_id = path_func_params[4]

    target_node_id = current_path[-1]
    target_basic_block_id = cfg_nodes[target_node_id]
    block_end = basic_blocks[target_basic_block_id][1]
    assert not is_direct_jump(instruction_sequence, block_end)

    last_jump = None
    pc_stack = []
    for k in range(0, len(current_path)):
        node_id = current_path[k]
        basic_block_id = cfg_nodes[node_id]
        block_start = basic_blocks[basic_block_id][0]
        block_end = basic_blocks[basic_block_id][1]

        for i in range(block_start, block_end + 1):

            if instruction_sequence[i].name in ["JUMP", "JUMPI"]:

                if instruction_sequence[i].annotation == "[out]" and k == len(current_path) - 1:
                    if len(pc_stack) > 0:
                        pc = pc_stack[0]
                        idx = pc_to_instruction_index[pc]
                        last_jump = instruction_index_to_block_id[idx]

                if len(pc_stack) > 0:
                    pc_stack.pop(0)

                if instruction_sequence[i].annotation == "[in]" and k != len(current_path) - 1:
                    # One additional pop for the return address of function call
                    pc_stack.pop(0)
            elif instruction_sequence[i].annotation == '*[in]':
                pc_stack.pop(0)

            elif instruction_sequence[i].name.startswith("PUSH") and instruction_sequence[i].tag_id != None:
                pc_stack.insert(0, int(instruction_sequence[i].operand, 16))

            elif instruction_sequence[i].name.startswith("DUP"):
                tmp_stack = backward_local_dataflow_analysis(instruction_sequence, i, True)
                dup_item = int(instruction_sequence[i].name[3:])
                dup_data = tmp_stack[dup_item - 1]
                if dup_data != None and instruction_sequence[dup_data[1]].tag_id != None:
                    pc_stack.insert(0, int(instruction_sequence[dup_data[1]].operand, 16))

    if (last_jump != None):
        last_jumps.add(last_jump)

    return False


@func_set_timeout(30)
def construct_cfg(instruction_seq, basic_blocks, entry_pc, pc_to_instruction_index,
                  instruction_index_to_block_id):
    entry_instruction_index = pc_to_instruction_index[entry_pc]

    # for tag_config in tag_configs:

    # entry_instruction_index = tag_config[0]
    # tag_id = tag_config[1]

    # Each cfg node contains a basic block id
    cfg_nodes = []
    cfg_nodes.append(instruction_index_to_block_id[entry_instruction_index])

    cfg_node_to_tag_stack = [[]]

    # Map each cfg node id to a list of tuples (target, condition), where target is the target
    # cfg node id and condition is True/False/None.
    # If the target is None, then this represents a jump to error tag.
    cfg_edges = {}

    # print("=============================="+str(tag_id))

    # Iteratively expand the control flow graph until there is no node/edge to expand
    changed = True
    while changed:
        changed = expand_control_flow_graphs(instruction_seq, basic_blocks, pc_to_instruction_index,
                                             instruction_index_to_block_id, cfg_nodes, cfg_edges,
                                             cfg_node_to_tag_stack)

    _cfg_nodes = []
    for block in cfg_nodes:
        _cfg_nodes.append(basic_blocks[block][0])

    _cfg_edges = []
    for pre, succs in cfg_edges.items():
        for succ in succs:
            _cfg_edges.append((pre, succ[0]))

    paths = get_function_acyclic_path(_cfg_nodes, _cfg_edges, entry_instruction_index)

    return paths


# The main function
# Construct the control flow graph for each entry tag
def construct_control_flow_graphs(instruction_sequence, basic_blocks, call_graph, pc_to_instruction_index, pc_to_tag_id, tag_id_to_pc):
    # Map each instruction to the basic block it belongs to.
    instruction_index_to_block_id = {}
    for basic_block_id in range(0, len(basic_blocks)):
        basic_block = basic_blocks[basic_block_id]
        for idx in range(basic_block[0], basic_block[1] + 1):
            instruction_index_to_block_id[idx] = basic_block_id

    tags_that_has_been_pushed = set()
    definitely_not_tag_pushing_instruction_indices = set()

    push_index_to_use_indices, global_cfg = global_data_flow_analysis(instruction_sequence, pc_to_instruction_index)

    for i in range(0, len(instruction_sequence)):

        if instruction_sequence[i].name.startswith("PUSH"):
            push_constant = int(instruction_sequence[i].operand, 16)

            if i+1 < len(instruction_sequence) and instruction_sequence[i + 1].name in ["JUMP", "JUMPI"]:
                if push_constant < 5:
                    tag = 0
                else:
                    if not (push_constant in pc_to_tag_id.keys()):
                        print("pc_to_tag_id keys:"+str(list(pc_to_tag_id.keys())))
                        for k in range(min(pc_to_instruction_index[push_constant], max(0, i - 10)), min(i + 20, len(instruction_sequence))):
                            if k == i:
                                print(str(k) + " " + str(instruction_sequence[k])+"<==============")
                            else:
                                print(str(k) + " " + str(instruction_sequence[k]))
                        assert (False)
                    tag = pc_to_tag_id[push_constant]

                instruction_sequence[i].tag_id = tag
                tags_that_has_been_pushed.add(tag)

            elif push_constant in pc_to_tag_id.keys() and push_constant>5:

                # The push constant matches the pc of a certain JUMPDEST. However, we are not sure
                # whether this is an address or an operand by coincidence.
                is_tag = recognize_tag(instruction_sequence, i, pc_to_tag_id, pc_to_instruction_index, push_index_to_use_indices, definitely_not_tag_pushing_instruction_indices)

                if is_tag:
                    instruction_sequence[i].tag_id = pc_to_tag_id[push_constant]
                    tags_that_has_been_pushed.add(pc_to_tag_id[push_constant])
            else:

                # push_constant not in pc_to_tag_id. Impossible to be a tag
                definitely_not_tag_pushing_instruction_indices.add(idx)

    # Try one more time to find tag-pushing instructions.
    find_omission(instruction_sequence, tag_id_to_pc, pc_to_instruction_index, tags_that_has_been_pushed, definitely_not_tag_pushing_instruction_indices)


    for entry_pc, call_sites_map in call_graph.items():
        for index, call_sites in call_sites_map.items():
            instruction_sequence[index].annotation = '[in]'

    # Map pc to the corresponding instruction index
    pc_to_instruction_index = {}
    for i in range(0, len(instruction_sequence)):
        pc_to_instruction_index[instruction_sequence[i].address] = i

    paths = []

    for entry_pc, _ in call_graph.items():
        try:
            intra_paths = construct_cfg(instruction_sequence, basic_blocks, entry_pc, pc_to_instruction_index,
                                        instruction_index_to_block_id)
        except func_timeout.exceptions.FunctionTimedOut:
            intra_paths = []
        except Exception:
            intra_paths = []
        paths += intra_paths

    return paths


# The key function for control flow graph construction
# We assume that the tag_id of every PUSH is complete and correct. However, we don't assume that the annotation of JUMP is complete. The annotation information
# can be iteratively filled in.
# Other assumption:
#    1) function call is always implemented as a direct jump (the jump target is pushed in the same basic block. can be retrieved using local backward dataflow analysis)
#    2) function return is always implemented as a indirect jump (the jump target is pushed in a different basic block)
#    3) basic block deduplication can only happen across function
#
def expand_control_flow_graphs(instruction_sequence, basic_blocks, pc_to_instruction_index,
                               instruction_index_to_block_id, cfg_nodes, cfg_edges, cfg_node_to_tag_stack):
    q = Queue()
    for node_id in range(0, len(cfg_nodes)):
        q.put(node_id)

    # Whether we have changed the control flow graphs in this call instance
    changed = False

    # Iteratively change the control flow graph
    while not q.empty():

        current_node_id = q.get()
        basic_block_id = cfg_nodes[current_node_id]
        block_start = basic_blocks[basic_block_id][0]  # @UnusedVariable
        block_end = basic_blocks[basic_block_id][1]

        #         print("----------------------"+str(basic_block_id)+" "+str(q.queue)+" "+str(changed))
        #         for i in range(0, len(cfg_nodes)):
        #             sys.stdout.write(str(cfg_nodes[i]))
        #             if i in cfg_edges:
        #                 sys.stdout.write(": ")
        #                 for j in range(0, len(cfg_edges[i])):
        #                     t = cfg_edges[i][j]
        #                     sys.stdout.write(str(cfg_nodes[t[0]]))
        #                     if t[1]!=None:
        #                         sys.stdout.write("("+t[1]+") ")
        #             print()

        if not current_node_id in cfg_edges:
            cfg_edges[current_node_id] = []

        if instruction_sequence[block_end].name == "JUMP":

            # There are totally 7 different cases for the next block
            if instruction_sequence[block_end].annotation == "[out]":

                # --- Case 1: jump [out]
                # There are two cases: 
                # Case 1: This is a function return to the caller function.
                # Case 2: This is the return from external function body to its entry skeleton
                # The difference between these two cases is whether the return address is available in the current tag stack top in the current cfg.

                if not current_node_id in cfg_edges or len(cfg_edges[current_node_id]) == 0:

                    last_jumps = set()
                    path_func_params = (last_jumps, basic_blocks, instruction_sequence, pc_to_instruction_index,
                                        instruction_index_to_block_id)
                    enumerate_acyclic_paths(0, current_node_id, cfg_nodes, cfg_edges, [], collect_last_jump,
                                            path_func_params)

                    # if len(last_jumps) > 0:
                    #     # len(last_jumps)>0 means that this is case 2
                    #     assert len(last_jumps) == 1
                    #     for basic_block_id in last_jumps:
                    #         if add_new_node(instruction_sequence, basic_blocks, current_node_id, basic_block_id,
                    #                         cfg_nodes, cfg_edges, cfg_node_to_tag_stack, "ext-body-ret"):
                    #             changed = True
                else:

                    # Can only have one ext body return site
                    assert len(cfg_edges[current_node_id]) == 1
                    # assert cfg_edges[current_node_id][0][1] == "ext-body-ret"


            # elif instruction_sequence[block_end].annotation == "[error]":
            #     # This is a jump to error
            #     continue

            elif instruction_sequence[block_end].annotation == "[in]":

                # --- Case 2: jump [in]
                # This is an function call. Function call is always through direct jump
                # There are three possible cases of callee: external function, internal function, auto function.
                # We don't trace into the callee. However, we need to know the return site and link it with the current node.
                # auto function will be inlined into the caller function's CFG latter. But for now we don't differentiate it
                # from external/internal functions yet.

                if not current_node_id in cfg_edges or len(cfg_edges[current_node_id]) == 0:

                    return_sites = set()
                    path_func_params = (return_sites, basic_blocks, instruction_sequence, pc_to_instruction_index,
                                        instruction_index_to_block_id)
                    enumerate_acyclic_paths(0, current_node_id, cfg_nodes, cfg_edges, [], collect_return_site,
                                            path_func_params)

                    if len(return_sites) == 1:
                        assert len(return_sites) == 1

                        for basic_block_id in return_sites:
                            if add_new_node(instruction_sequence, basic_blocks, current_node_id, basic_block_id, cfg_nodes,
                                            cfg_edges, cfg_node_to_tag_stack, "call-ret"):
                                changed = True
                    # else:
                    #     instruction_sequence[block_end].annotation = ''
                    #     opstack = backward_local_dataflow_analysis(instruction_sequence, block_end, True)
                    #     assert opstack[0]
                    #     changed = True
                else:

                    # Can only have one return site
                    assert len(cfg_edges[current_node_id]) == 1
                    # assert cfg_edges[current_node_id][0][1] == "call-ret"

            else:

                # Only consider instructions in the current block, don't backtrace into previous blocks
                opstack = backward_local_dataflow_analysis(instruction_sequence, block_end, True)

                # Normally, this must be a direct jump. If this is an indirect jump, then the annotation must be "[out]" and handled in "Case 1"
                if opstack[0] == None:
                    # However, sometimes solidity does forget to add the annotation [out]!
                    assert not is_direct_jump(instruction_sequence, block_end)
                    instruction_sequence[block_end].annotation = "[out]"
                    changed = True
                    continue

                pc = opstack[0][0]
                idx = opstack[0][1]

                if instruction_sequence[idx].tag_id == 0:
                    # --- Case 3: jump error tag
                    # This is a jump to error tag. Don't need to create node/edge
                    instruction_sequence[block_end].annotation = "[error]"
                    changed = True
                    continue

                else:

                    assert pc in pc_to_instruction_index and pc_to_instruction_index[
                        pc] in instruction_index_to_block_id
                    target_block_id = instruction_index_to_block_id[pc_to_instruction_index[pc]]
                    if add_new_node(instruction_sequence, basic_blocks, current_node_id, target_block_id, cfg_nodes,
                                    cfg_edges, cfg_node_to_tag_stack):
                        changed = True

        elif instruction_sequence[block_end].name == "JUMPI":

            # Conduct a backward data flow analysis to get the jump destination 
            opstack = backward_local_dataflow_analysis(instruction_sequence, block_end)

            assert opstack[0] != None
            pc = opstack[0][0]
            idx = opstack[0][1]

            if instruction_sequence[idx].tag_id == 0:
                # This is a jump to error tag. Don't need to create node/edge
                instruction_sequence[block_end].annotation = "[error]"

                # The false/else branch
                following_block_id = instruction_index_to_block_id[block_end + 1]
                assert (following_block_id < len(basic_blocks))
                if add_new_node(instruction_sequence, basic_blocks, current_node_id, following_block_id, cfg_nodes,
                                cfg_edges, cfg_node_to_tag_stack, "false"):
                    changed = True

                continue

            else:

                assert pc in pc_to_instruction_index and pc_to_instruction_index[pc] in instruction_index_to_block_id

                # The true/then branch
                target_block_id = instruction_index_to_block_id[pc_to_instruction_index[pc]]
                assert (target_block_id < len(basic_blocks))
                if add_new_node(instruction_sequence, basic_blocks, current_node_id, target_block_id, cfg_nodes,
                                cfg_edges, cfg_node_to_tag_stack, "true"):
                    changed = True

                # The false/else branch
                following_block_id = instruction_index_to_block_id[block_end + 1]
                assert (following_block_id < len(basic_blocks))
                if add_new_node(instruction_sequence, basic_blocks, current_node_id, following_block_id, cfg_nodes,
                                cfg_edges, cfg_node_to_tag_stack, "false"):
                    changed = True

        # elif instruction_sequence[block_end].name in ["CALL", "DELEGATECALL", "STATICCALL"]:
        #
        #     following_block_id = instruction_index_to_block_id[block_end + 1]
        #     assert (following_block_id < len(basic_blocks))
        #
        #     # Find the nodes with following_block_id
        #     if add_new_node(instruction_sequence, basic_blocks, current_node_id, following_block_id, cfg_nodes,
        #                     cfg_edges, cfg_node_to_tag_stack, "ext-call-ret"):
        #         changed = True

        elif instruction_sequence[block_end].name in ["STOP", "REVERT", "RETURN", "INVALID", "SELFDESTRUCT"]:

            # The end of block
            continue

        elif instruction_sequence[block_end].name not in ['JUMP', 'STOP', 'REVERT', 'RETURN', 'SELFDESTRUCT'] and \
                instruction_sequence[block_end].annotation == '[in]':
            if not current_node_id in cfg_edges or len(cfg_edges[current_node_id]) == 0:
                return_sites = set()
                path_func_params = (return_sites, basic_blocks, instruction_sequence, pc_to_instruction_index,
                                    instruction_index_to_block_id)
                enumerate_acyclic_paths(0, current_node_id, cfg_nodes, cfg_edges, [], collect_return_site,
                                        path_func_params)
                # assert len(return_sites) == 1
                if len(return_sites) == 1:

                    for basic_block_id in return_sites:
                        if add_new_node(instruction_sequence, basic_blocks, current_node_id, basic_block_id, cfg_nodes,
                                        cfg_edges, cfg_node_to_tag_stack, "call-ret"):
                            changed = True
            else:

                # Can only have one return site
                assert len(cfg_edges[current_node_id]) == 1
                # assert cfg_edges[current_node_id][0][1] == "call-ret"

        else:

            # Follow through
            if block_end + 1 < len(instruction_sequence):

                assert (instruction_sequence[block_end + 1].name == "JUMPDEST")

                following_block_id = instruction_index_to_block_id[block_end + 1]
                assert (following_block_id < len(basic_blocks))

                # Find the nodes with following_block_id
                if add_new_node(instruction_sequence, basic_blocks, current_node_id, following_block_id, cfg_nodes,
                                cfg_edges, cfg_node_to_tag_stack):
                    changed = True

    return changed


# Get all the blocks that are reachable in the cfg
def get_basic_blocks_in_cfg(cfg):
    cfg_nodes = cfg[0]
    cfg_edges = cfg[1]

    visited = set()
    blocks = set()
    _get_basic_blocks_in_cfg(0, cfg_nodes, cfg_edges, visited, blocks)
    return blocks


def _get_basic_blocks_in_cfg(current_node_id, cfg_nodes, cfg_edges, visited, blocks):
    if current_node_id in visited:
        # This block has already been traversed
        return

    blocks.add(cfg_nodes[current_node_id])
    visited.add(current_node_id)

    # For all the next blocks
    for t in cfg_edges[current_node_id]:
        next_node_id = t[0]
        if next_node_id == None:
            # This occurs if the edge is jumping to error_tag ("0")
            continue
        assert (next_node_id < len(cfg_nodes))
        _get_basic_blocks_in_cfg(next_node_id, cfg_nodes, cfg_edges, visited, blocks)

    return
