import os, sys

from FBD.data_flow_analysis import backward_local_dataflow_analysis

folder = os.path.dirname(__file__)
sys.path.append(os.path.normpath(folder + "/.."))

from disassembly.evmdasm.registry import INSTRUCTIONS_BY_NAME
from disassembly.evm_utils import mask_set


def forward_dataflow_analysis(disassembly, idx, pc_to_instruction_index):
    assert (disassembly[idx].name.startswith("PUSH"))
    push_constant = int(disassembly[idx].operand, 16)

    # trace backward in this basic block
    _op_stacks = backward_local_dataflow_analysis(disassembly, idx)

    op_stacks = []
    for item in _op_stacks:
        if item == None:
            op_stacks.append(None)
        else:
            op_stacks.append(item[0])

    op_stacks.insert(0, push_constant)

    # None represents unknown value.
    for k in range(0, 20):  # @UnusedVariable
        op_stacks.append(None)

    visited = set()
    locations = [0]
    return _forward_dataflow_analysis(disassembly, idx + 1, idx, pc_to_instruction_index, op_stacks, locations,
                                      push_constant, visited, 0)


# Generate the stack context descriptor
def forward_dataflow_analysis_context(op_stacks):
    result = ""
    none_accumulator = 0
    for i in range(0, min(len(op_stacks), 50)):
        if op_stacks[i] is not None:
            if none_accumulator == 0:
                result += (" " + str(op_stacks[i]))
            else:
                result += ("*" + str(none_accumulator) + " " + str(op_stacks[i]))
                none_accumulator = 0
        else:
            none_accumulator += 1
    if none_accumulator != 0:
        result += ("*" + str(none_accumulator))
    return result


def _forward_dataflow_analysis(disassembly, start, idx, pc_to_instruction_index, op_stacks, locations, push_constant,
                               visited, depth):
    # The locations of push_constant (can have multiple positions because push_constant could be duplicated1)
    i = start
    while i < len(disassembly):
        for k in range(0, len(locations)):
            assert (locations[k] < 500)
            assert (op_stacks[locations[k]] == push_constant)

        if disassembly[i].name.startswith("SWAP"):
            swap_item = int(disassembly[i].name[4:])
            temp = op_stacks[swap_item]
            op_stacks[swap_item] = op_stacks[0]
            op_stacks[0] = temp
            for k in range(0, len(locations)):
                if locations[k] == 0:
                    locations[k] = swap_item
                elif locations[k] == swap_item:
                    locations[k] = 0

        elif disassembly[i].name.startswith("DUP"):
            dup_item = int(disassembly[i].name[3:])
            op_stacks.insert(0, op_stacks[dup_item - 1])

            found = False
            for k in range(0, len(locations)):
                if locations[k] == dup_item - 1:
                    found = True
                locations[k] += 1
            if found:
                locations.append(0)

        elif disassembly[i].name.startswith("PUSH"):
            for k in range(0, len(locations)):
                locations[k] += 1
            op_stacks.insert(0, int(disassembly[i].operand, 16))


        elif disassembly[i].name == "AND":

            # and with "ffffffff" will not change the result
            if op_stacks[0] != None and op_stacks[0] in mask_set:
                op_stacks = op_stacks[1:]
                for p in range(0, len(locations)):
                    locations[p] -= 1

            elif op_stacks[1] != None and op_stacks[1] in mask_set:

                top = op_stacks[0]
                op_stacks = op_stacks[2:]
                op_stacks.insert(0, top)
                for p in range(0, len(locations)):
                    if locations[p] != 0:
                        locations[p] -= 1
            else:
                for p in range(0, len(locations)):
                    if locations[p] <= 1:
                        return i

                op_stacks = op_stacks[2:]
                op_stacks.insert(0, None)
                for p in range(0, len(locations)):
                    locations[p] -= 1

        elif disassembly[i].name == "POP":

            if 0 in set(locations):
                return i
                # if len(locations) == 1:
                #    return None
                # else:
                #    locations.remove(0)

            op_stacks = op_stacks[1:]
            for k in range(0, len(locations)):
                locations[k] -= 1

        elif disassembly[i].name == "JUMP":

            if 0 in set(locations):
                return i
            pc = op_stacks[0]
            op_stacks = op_stacks[1:]
            if pc == None or pc < 5:
                # unknown address
                return None

            assert disassembly[pc_to_instruction_index[pc]].name == "JUMPDEST"
            config = str(pc_to_instruction_index[pc]) + ":" + forward_dataflow_analysis_context(op_stacks)
            if config in visited:
                return None

            i = pc_to_instruction_index[pc]
            assert (disassembly[i].address == pc)
            for k in range(0, len(locations)):
                locations[k] -= 1
            continue

        elif disassembly[i].name == "JUMPI":

            if 0 in locations:
                return i

            for item in locations:
                assert (item != 0)

            pc = op_stacks[0]
            op_stacks = op_stacks[2:]

            for k in range(0, len(locations)):
                locations[k] -= 2

            # If the address can be jumped to...
            if pc != None and not pc < 5:

                assert disassembly[pc_to_instruction_index[pc]].name == "JUMPDEST"
                config = str(pc_to_instruction_index[pc]) + ":" + forward_dataflow_analysis_context(op_stacks)
                if not config in visited:
                    k = _forward_dataflow_analysis(disassembly, pc_to_instruction_index[pc], idx,
                                                   pc_to_instruction_index, list(op_stacks), list(locations),
                                                   push_constant, visited, depth + 1)
                    if k != None:
                        return k

            # Continue to the follow branch

        elif disassembly[i].name == "JUMPDEST":

            visited.add(str(i) + ":" + forward_dataflow_analysis_context(op_stacks))

        elif disassembly[i].name in ["STOP", "RETURN", "INVALID", "REVERT", "SELFDESTRUCT"]:

            return None

        else:

            instruction = INSTRUCTIONS_BY_NAME.get(disassembly[i].name)

            # For all the other instructions, imply check whether their consumption
            for k in range(0, instruction._pops):
                if 0 in locations:
                    if len(locations) == 1:
                        return i
                    else:
                        locations.remove(0)
                op_stacks = op_stacks[1:]

                for p in range(0, len(locations)):
                    locations[p] -= 1

            for k in range(0, instruction._pushes):
                op_stacks.insert(0, None)

                for p in range(0, len(locations)):
                    locations[p] += 1

        i = i + 1

    return None


# Recognize whether the constant is a tag
def recognize_tag(instruction_sequence, idx, pc_to_tag_id, pc_to_instruction_index, push_index_to_use_indices,
                  definitely_not_tag_pushing_instruction_indices):
    push_constant = int(instruction_sequence[idx].operand, 16)
    assert push_constant in pc_to_tag_id

    # Know from global control flow analysis this is/is not a tag
    if idx in push_index_to_use_indices:

        if len(push_index_to_use_indices[idx][0]) != 0:
            # Used by jump/jumpi instructions
            if (len(push_index_to_use_indices[idx][1]) != 0):
                print(instruction_sequence[push_index_to_use_indices[idx][1][0]])
                assert (False)

            return True

        if len(push_index_to_use_indices[idx][1]) != 0:
            # Used by non-jump/jumpi instructions
            assert (len(push_index_to_use_indices[idx][0]) == 0)
            return False

    if not instruction_sequence[idx].name in ["PUSH1", "PUSH2", "PUSH3"]:
        # Solc never use PUSH4 to push address
        return False

    elif instruction_sequence[idx].name == "PUSH1" and instruction_sequence[idx].address > 200:
        # Use push1 to push tag is only possible at the first several tens of instructions
        return False

    # Find where this push_constant is used
    i = forward_dataflow_analysis(instruction_sequence, idx, pc_to_instruction_index)

    if i == None:

        # Don't know where this push constant is used....
        if instruction_sequence[idx - 1].name == "JUMPDEST" and instruction_sequence[idx + 1].name == "DUP2" and \
                instruction_sequence[idx + 2].name == "JUMP":
            # In this special case, we know that this is not a tag
            # JUMPDEST PUSH2 DUP2 JUMP
            return False
        return True

    else:
        if instruction_sequence[i].name in ["JUMP", "JUMPI"]:
            return True
        else:
            definitely_not_tag_pushing_instruction_indices.add(idx)
            return False


# Trace the control flow of the whole program and record at which instruction a pushed constant is being used
def global_data_flow_analysis(disassembly, pc_to_instruction_index):

    # map a candidate push-pc instruction to two lists:
    #    the first list contains all of the jump/jumpi instructions that use the pc.
    #    the second list contains all of the non jump/jumpi instructions that use the pc.
    # The assumption is that these two lists are mutually-exclusive. So, if the second list is non-empty, the
    # push constant is definitely not a tag

    push_index_to_use_indices = {}
    global_cfg = {}
    _global_data_flow_analysis(disassembly, 0, pc_to_instruction_index, [], set(), push_index_to_use_indices, 0, global_cfg)
    return push_index_to_use_indices, global_cfg


# Generate the stack context descriptor
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
        if push_idx in push_index_to_use_indices and len \
                (push_index_to_use_indices[push_idx][1] ) == 0 and not pc in added:
            result += str(pc ) +" "
            added.add(pc)

    return result


def _global_data_flow_analysis(disassembly, start, pc_to_instruction_index, op_stacks, visited,
                               push_index_to_use_indices, depth, global_cfg):
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
            if op_stacks[0] != None and op_stacks[0][0] in mask_set:

                push_index_to_use_indices[op_stacks[0][1]][1].add(i)  # fffff.. is used for non jump/jumpi
                op_stacks = op_stacks[1:]

            elif op_stacks[1] != None and op_stacks[1][0] in mask_set:

                push_index_to_use_indices[op_stacks[1][1]][1].add(i)  # fffff.. is used for non jump/jumpi
                top = op_stacks[0]
                op_stacks = op_stacks[2:]
                op_stacks.insert(0, top)

            else:

                if op_stacks[0] != None:
                    push_index_to_use_indices[op_stacks[0][1]][1].add(i)
                if op_stacks[1] != None:
                    push_index_to_use_indices[op_stacks[1][1]][1].add(i)

                op_stacks = op_stacks[2:]
                op_stacks.insert(0, None)

        elif disassembly[i].name == "POP":

            if op_stacks[0] != None:
                pc = op_stacks[0][0]
                push_idx = op_stacks[0][1]
                push_index_to_use_indices[push_idx][1].add(i)
            op_stacks = op_stacks[1:]

        elif disassembly[i].name == "JUMP":

            if op_stacks[0] == None:
                return

            pc = op_stacks[0][0]
            push_idx = op_stacks[0][1]
            op_stacks = op_stacks[1:]
            if pc < 5:
                # error tag. treat it like INVALID
                return

            push_index_to_use_indices[push_idx][0].add(i)
            assert len(push_index_to_use_indices[push_idx][1]) == 0
            assert disassembly[pc_to_instruction_index[pc]].name == "JUMPDEST"

            if disassembly[i].address not in global_cfg:
                global_cfg[disassembly[i].address] = set()
            global_cfg[disassembly[i].address].add(pc)

            config = str(pc_to_instruction_index[pc]) + ":" + context(op_stacks, push_index_to_use_indices)
            if config in visited:
                return

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

                    if disassembly[i].address not in global_cfg:
                        global_cfg[disassembly[i].address] = set()
                    global_cfg[disassembly[i].address].add(pc)

                    # If the address can be jumped to...
                    config = str(pc_to_instruction_index[pc]) + ":" + context(op_stacks, push_index_to_use_indices)
                    if not config in visited:
                        _global_data_flow_analysis(disassembly, pc_to_instruction_index[pc], pc_to_instruction_index,
                                                   list(op_stacks), visited, push_index_to_use_indices, depth + 1, global_cfg)

            else:
                op_stacks = op_stacks[2:]
                # Continue to the follow branch

        elif disassembly[i].name == "JUMPDEST":
            # print("******"+str(i) + ":" + context(op_stacks, push_index_to_use_indices))
            visited.add(str(i) + ":" + context(op_stacks, push_index_to_use_indices))

        elif disassembly[i].name in ["STOP", "RETURN", "INVALID", "REVERT", "SELFDESTRUCT"]:
            return

        else:

            instruction = INSTRUCTIONS_BY_NAME.get(disassembly[i].name)

            # For all the other instructions, imply check whether their consumption
            if instruction is None:
                a = 11
            for k in range(0, instruction._pops):
                if op_stacks[0] != None:
                    push_index_to_use_indices[op_stacks[0][1]][1].add(i)
                    assert (len(push_index_to_use_indices[op_stacks[0][1]][0]) == 0)
                op_stacks = op_stacks[1:]

            for k in range(0, instruction._pushes):
                op_stacks.insert(0, None)

        i = i + 1
    return


# Try one more time to find tag-pushing instructions.
# If a tag has no corresponding push instruction, then it can be a possible candidate
def find_omission(instruction_sequence, tag_id_to_pc, pc_to_instruction_index, tags_that_has_been_pushed,
                  definitely_not_tag_pushing_instruction_indices):
    # For every tag in the program, there must be at least one push instruction to visit this tag.
    for tag in tag_id_to_pc.keys():
        if tag in tags_that_has_been_pushed:
            continue

        # Try to find the push instruction that matches the pc
        candidates = []
        for i in range(0, len(instruction_sequence)):
            if not instruction_sequence[i].name.startswith("PUSH"):
                continue

            operand = int(instruction_sequence[i].operand, 16)
            if operand == tag_id_to_pc[tag] and not i in definitely_not_tag_pushing_instruction_indices:
                assert (instruction_sequence[i].tag_id == None)
                candidates.append(i)

        for i in range(0, len(candidates)):
            idx = forward_dataflow_analysis(instruction_sequence, candidates[i], pc_to_instruction_index)
            if not (idx != None and not instruction_sequence[idx].name in ["JUMP", "JUMPI"]):
                pc = int(instruction_sequence[candidates[i]].operand, 16)
                instruction_sequence[candidates[i]].tag_id = pc_to_instruction_index[pc]
