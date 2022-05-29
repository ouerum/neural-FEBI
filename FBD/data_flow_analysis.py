import os, sys

folder = os.path.dirname(__file__)
sys.path.append(os.path.normpath(folder + "/.."))

from disassembly.evmdasm.registry import INSTRUCTIONS_BY_NAME
from disassembly.evm_utils import mask_set
from fbdconfig import visited_max_times as max_times, debug, init_stack_heigth


def context(op_stacks, push_index_to_use_indices):
    result = ""
    #     none_accumulator = 0
    #     for i in range(0, min(len(op_stacks), 50)):
    #         if op_stacks[i] != None:
    #             if none_accumulator == 0:
    #                 result += (" " + str(op_stacks[i][0]))
    #             else:
    #                 result += ("*" + str(none_accumulator) + " " + str(op_stacks[i][0]))
    #                 none_accumulator = 0
    #         else:
    #             none_accumulator += 1
    #     if none_accumulator != 0:
    #         result += ("*" + str(none_accumulator))

    added = set()
    for i in range(0, len(op_stacks)):
        if op_stacks[i] == None:
            continue
        pc = op_stacks[i][0]
        push_idx = op_stacks[i][1]

        # Get the (non-recursive) tag stack
        if push_idx in push_index_to_use_indices and len(push_index_to_use_indices[push_idx][1])==0 and not pc in added:
            result += str(pc)+" "
            added.add(pc)

    return result


def add_call_graph(call_graph, call_site_index, tgt_func, tag_ctx):
    if call_site_index not in call_graph:
        call_graph[call_site_index] = [(tgt_func, tag_ctx)]
    else:
        index = 0
        while index < len(call_graph[call_site_index]):
            if call_graph[call_site_index][index][1] == tag_ctx and tgt_func == call_graph[call_site_index][index][0]:
                break
            index += 1
        if index == len(call_graph[call_site_index]):
            call_graph[call_site_index].append((tgt_func, tag_ctx))


def _global_data_flow_analysis(disassembly, start, pc_to_instruction_index, op_stacks, visited, visited_times,
                               push_index_to_use_indices, depth, fb, call_graph, ctx, func_starts, possible_calls, invalid_call,
                               curent_threshold, threshold, identified_funcs, existing_non_func=False):
    _invalid_call = {}
    missing_flag = False
    invalid_flag = False
    i = start
    while (i < len(disassembly)):
        if disassembly[i].name.startswith("SWAP"):
            swap_item = int(disassembly[i].name[4:])
            temp = op_stacks[swap_item]
            op_stacks[swap_item] = op_stacks[0]
            op_stacks[0] = temp

        elif disassembly[i].name.startswith("DUP"):

            dup_item = int(disassembly[i].name[3:])
            op_stacks.insert(0, op_stacks[dup_item - 1])

        elif disassembly[i].name.startswith("PUSH"):

            if not i in push_index_to_use_indices.keys():
                push_index_to_use_indices[i] = (
                    set(), set())  # The first list contains jump/jumpi use, the second list contain other uses.
            pc = int(disassembly[i].operand, 16)

            if pc in pc_to_instruction_index and \
                    disassembly[pc_to_instruction_index[pc]].name == "JUMPDEST" or \
                    pc in mask_set:

                op_stacks.insert(0, (pc, i))
            else:
                op_stacks.insert(0, None)

        elif disassembly[i].name == "AND":

            # and an pc address with "ffffffff" will not change the result
            if op_stacks[0] is not None and op_stacks[0][1] != -1 and op_stacks[0][0] in mask_set:

                push_index_to_use_indices[op_stacks[0][1]][1].add(i)  # fffff.. is used for non jump/jumpi
                op_stacks = op_stacks[1:]

            elif op_stacks[1] is not None and op_stacks[1][1] != -1 and op_stacks[1][0] in mask_set:

                push_index_to_use_indices[op_stacks[1][1]][1].add(i)  # fffff.. is used for non jump/jumpi
                top = op_stacks[0]
                op_stacks = op_stacks[2:]
                op_stacks.insert(0, top)

            else:

                if op_stacks[0] is not None and op_stacks[0][1] != -1:
                    push_index_to_use_indices[op_stacks[0][1]][1].add(i)
                if op_stacks[1] is not None and op_stacks[1][1] != -1:
                    push_index_to_use_indices[op_stacks[1][1]][1].add(i)

                op_stacks = op_stacks[2:]
                op_stacks.insert(0, None)

        elif disassembly[i].name == "POP":

            if op_stacks[0] is not None and op_stacks[0][1] != -1:
                pc = op_stacks[0][0]
                push_idx = op_stacks[0][1]
                push_index_to_use_indices[push_idx][1].add(i)
            op_stacks = op_stacks[1:]

        elif disassembly[i].name == "JUMP":
            if op_stacks[0] is None:
                return missing_flag, invalid_flag, _invalid_call

            pc = op_stacks[0][0]
            push_idx = op_stacks[0][1]
            op_stacks = op_stacks[1:]

            if disassembly[i].annotation and disassembly[i].annotation == '[out]':
                if ctx[0][0] == -1 and isinstance(pc, int):
                    if curent_threshold >= threshold:
                        return True, invalid_flag, _invalid_call
                elif (isinstance(pc,str) and pc == '*') and ctx[0][0] != -1:
                    if not existing_non_func:
                        _invalid_call[ctx[0][0]] = ctx[0][1]
                    # _invalid_call[ctx[0][0]] = ctx[0][1]
                    return missing_flag, True, _invalid_call
                elif isinstance(pc, str) and pc == "*" and ctx[0][0] == -1:
                    return missing_flag, invalid_flag, _invalid_call
                else:
                    current_context = ctx[0]
                    ctx = ctx[1:]
                    if current_context[1] not in identified_funcs:
                        existing_non_func = True

            if pc < 5:
                # error tag. treat it like INVALID
                return missing_flag, invalid_flag, _invalid_call

            push_index_to_use_indices[push_idx][0].add(i)
            assert len(push_index_to_use_indices[push_idx][1]) == 0
            assert disassembly[pc_to_instruction_index[pc]].name == "JUMPDEST"

            config = str(pc_to_instruction_index[pc]) + ":" + context(op_stacks, push_index_to_use_indices)
            if config in visited:
                return missing_flag, invalid_flag, _invalid_call

            if pc in func_starts and i not in invalid_call and disassembly[i].annotation != '[out]':
                if pc not in possible_calls:
                    possible_calls[pc] = set()
                possible_calls[pc].add(i)
                if ctx[0][0] == -1:
                    tag_ctx = context(op_stacks, push_index_to_use_indices)
                    add_call_graph(call_graph, i, pc, tag_ctx)
                ctx.insert(0, (i, pc))

            i = pc_to_instruction_index[pc]
            assert (disassembly[i].address == pc)
            continue

        elif disassembly[i].name == "JUMPI":

            if op_stacks[0] != None:
                pc = op_stacks[0][0]
                push_idx = op_stacks[0][1]
                op_stacks = op_stacks[2:]

                if pc >= 5:
                    assert disassembly[pc_to_instruction_index[pc]].name == "JUMPDEST"
                    push_index_to_use_indices[push_idx][0].add(i)
                    assert (len(push_index_to_use_indices[push_idx][1]) == 0)

                    # # If the address can be jumped to...
                    # if pc in func_starts and i not in invalid_call:
                    #     if pc not in possible_calls:
                    #         possible_calls[pc] = set()
                    #     possible_calls[pc].add(i)
                    #     ctx.insert(0, (i, pc))

                    config = str(pc_to_instruction_index[pc]) + ":" + context(op_stacks, push_index_to_use_indices)
                    if not config in visited:
                        _missing_flag, _invalid_flag, new_invalid_calls = \
                            _global_data_flow_analysis(disassembly, pc_to_instruction_index[pc],
                                                       pc_to_instruction_index, list(op_stacks), visited, visited_times,
                                                       push_index_to_use_indices, depth + 1, fb, call_graph, list(ctx),
                                                       func_starts, possible_calls, invalid_call, curent_threshold,
                                                       threshold, identified_funcs, existing_non_func)
                        missing_flag = _missing_flag or missing_flag
                        invalid_flag = _invalid_flag or invalid_flag
                        _invalid_call.update(new_invalid_calls)
                        if missing_flag or invalid_flag:
                            return missing_flag, invalid_flag, _invalid_call

            else:
                op_stacks = op_stacks[2:]
                # Continue to the follow branch

        elif disassembly[i].name == "JUMPDEST":
            # print("******"+str(i) + ":" + context(op_stacks, push_index_to_use_indices))
            visited.add(str(i) + ":" + context(op_stacks, push_index_to_use_indices))
            if i not in visited_times:
                visited_times[i] = 0
            visited_times[i] += 1
            if visited_times[i] > max_times:
                return missing_flag, invalid_flag, _invalid_call
            assert len(ctx) > 0
            if ctx[0][0] == -1:
                fb.add(disassembly[i].address)
        elif disassembly[i].name in ["STOP", "RETURN", "INVALID", "REVERT", "SELFDESTRUCT"]:
            return missing_flag, invalid_flag, _invalid_call
        elif INSTRUCTIONS_BY_NAME.get(disassembly[i].name) is None:
            return missing_flag, invalid_flag, _invalid_call
        else:

            instruction = INSTRUCTIONS_BY_NAME.get(disassembly[i].name)

            # For all the other instructions, imply check whether their consumption
            for k in range(0, instruction._pops):
                if op_stacks[0] is not None and op_stacks[0][1] != -1:
                    push_index_to_use_indices[op_stacks[0][1]][1].add(i)
                    assert (len(push_index_to_use_indices[op_stacks[0][1]][0]) == 0)
                op_stacks = op_stacks[1:]

            for k in range(0, instruction._pushes):
                op_stacks.insert(0, None)

        if i+1<len(disassembly) and disassembly[i+1].address in func_starts and i not in invalid_call:
            pc = disassembly[i+1].address
            if pc not in possible_calls:
                possible_calls[pc] = set()
            possible_calls[pc].add(i)
            if ctx[0][0] == -1:
                tag_ctx = context(op_stacks, push_index_to_use_indices)
                add_call_graph(call_graph, i, pc, tag_ctx)
            ctx.insert(0, (i, pc))

        i = i + 1
    return missing_flag, invalid_flag, _invalid_call


# func_starts is a set stored the pc of function starts identified
# invalid_call is a set of index which presented the location of invalid calls
# fbs is a map start_index -> set(tag_index)
# start is the star of a function wait for exploration
def global_data_flow_analysis(disassembly, pc_to_instruction_index, start, func_starts, possible_calls, invalid_call, fb,
                              call_graph, current_threshold, threshold, identified_funcs):

    start_index = pc_to_instruction_index[start]
    push_index_to_use_indices = {}
    op_stack = [("*", -1)] * init_stack_heigth
    ctx_stack = [(-1, start_index)] # the first element is index of callsite, the second element is the index of entry
    visited_times = {}
    missing_flag, invalid_flag, _invalid_call = _global_data_flow_analysis(disassembly, start_index, pc_to_instruction_index, op_stack, set(),
                                                                           visited_times, push_index_to_use_indices, 0, fb, call_graph, ctx_stack,
                                                                           func_starts, possible_calls, invalid_call, current_threshold,
                                                                           threshold, identified_funcs, False)
    return missing_flag, invalid_flag, _invalid_call


# Trace the instruction sequence backward. The objectives is to find the opstack at disassembly[i].
# This is a local analysis, as it will stop at JUMPDEST. We have no idea from where this JUMPDEST is reached.
def backward_local_dataflow_analysis(disassembly, i, within_current_basic_block=False):
    start_idx = 0
    for k in range(i - 1, -1, -1):
        if disassembly[k].name in ["JUMP", "STOP", "RETURN", "INVALID", "REVERT", "SELFDESTRUCT"]:
            # Impossible to reach k+1 from k
            start_idx = k + 1
            break

        if within_current_basic_block and disassembly[k].name in ["JUMPDEST", "JUMPI"]:
            start_idx = k + 1
            break

    op_stacks = []
    for k in range(0, 100):
        op_stacks.append(None)

    for k in range(start_idx, i):

        assert not disassembly[k].name in ["JUMP", "STOP", "RETURN", "INVALID", "REVERT", "SELFDESTRUCT"]
        if disassembly[k].name.startswith("PUSH"):

            assert disassembly[k].operand != None
            op_stacks.insert(0, (int(disassembly[k].operand, 16), k))

        elif disassembly[k].name.startswith("DUP"):
            dup_item = int(disassembly[k].name[3:])
            op_stacks.insert(0, op_stacks[dup_item - 1])

        elif disassembly[k].name.startswith("SWAP"):
            swap_item = int(disassembly[k].name[4:])
            temp = op_stacks[swap_item]
            op_stacks[swap_item] = op_stacks[0]
            op_stacks[0] = temp

        elif disassembly[k].name == "AND":

            # and with "ffffffff" will not change the result
            if op_stacks[0] is not None and op_stacks[0][0] in mask_set:
                op_stacks = op_stacks[1:]
            elif op_stacks[1] is not None and op_stacks[1][0] in mask_set:
                top = op_stacks[0]
                op_stacks = op_stacks[2:]
                op_stacks.insert(0, top)
            else:
                op_stacks = op_stacks[2:]
                op_stacks.insert(0, None)

        elif not disassembly[k].name in ["INVALID", "UNKNOWN_0xfe"]:

            instruction = INSTRUCTIONS_BY_NAME.get(disassembly[k].name)
            if instruction is None:
                if debug:
                    print(disassembly[k])
                return op_stacks
                # assert (False)
            for k in range(0, instruction._pops):
                op_stacks = op_stacks[1:]
            for k in range(0, instruction._pushes):
                op_stacks.insert(0, None)

    return op_stacks