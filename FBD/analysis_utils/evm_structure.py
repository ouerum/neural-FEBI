#!/usr/local/bin/python3

# Routines to analyze evm binary code structure  
#
# Author: Dr. Wang 
import sys, os

folder = os.path.dirname(__file__)
sys.path.append(os.path.normpath(folder + "/.."))
from analysis_utils.evm_utils import canon_signature_hash


# Analyze the function selector and retrieve all the external tags and their associated signature hashes
# Note that functions with different signature hashes can share the same external tag.
def recognize_external_functions(runtime_instructions, pc_to_tag_id):
    # Get all the external/public function entries
    fallback_tag_info = None
    external_function_entry_tag_to_hash_list = {}  # Map the entry tag to signature hashes
    external_function_entry_tag_to_body_tag = {}  # Map the entry tag to the body tag

    tag_to_instruction_index = {}
    for i in range(0, len(runtime_instructions)):
        if runtime_instructions[i].name == "JUMPDEST":
            assert runtime_instructions[i].tag_id != None
            tag_to_instruction_index[runtime_instructions[i].tag_id] = i

    # Search the function selector to find all external tags and the fallback tag
    start = None
    check_value = True
    for i in range(0, len(runtime_instructions)):
        if runtime_instructions[i].name in ["CALLDATALOAD"]:
            start = i
            break
        if runtime_instructions[i].name == "CALLVALUE":
            check_value = True
        if runtime_instructions[i].name == "JUMPDEST":
            if check_value:
                check_value = True
                continue
            break

    if start is None:
        # There is no function selector because the contact only has the fallback function.
        # e.g. 0x330ac902cc4cb12e02249358dcfe3f60785e3439 0x2346c6d59c3278729fbb3d472b6b901d2defe1bd
        for k in range(0, len(runtime_instructions)):
            if runtime_instructions[k].name == "MSTORE":
                fall_back_entry_idx = k + 1
                break

        if runtime_instructions[fall_back_entry_idx].name == "JUMPDEST":
            fallback_tag_info = (fall_back_entry_idx, runtime_instructions[fall_back_entry_idx].tag_id)
        else:
            fallback_tag_info = (fall_back_entry_idx, None)

    else:
        fallback_tag_info = _recognize_external_functions(runtime_instructions, start, tag_to_instruction_index,
                                                          pc_to_tag_id, external_function_entry_tag_to_hash_list,
                                                          external_function_entry_tag_to_body_tag, fallback_tag_info,
                                                          False)

    return external_function_entry_tag_to_hash_list, external_function_entry_tag_to_body_tag, fallback_tag_info


def _recognize_external_functions(runtime_instructions, start, tag_to_instruction_index, pc_to_tag_id,
                                  external_function_entry_tag_to_hash_list, external_function_entry_tag_to_body_tag,
                                  fallback_tag_info, type):
    i = start
    while i < len(runtime_instructions):

        if runtime_instructions[i].name == "JUMPDEST":
            # jump form GT
            if type and i == start:
                i += 1
                continue

            # The fall back tag must be the last entry
            if runtime_instructions[i - 1].name == "JUMPI":
                # runtime_instructions[i] is the entry into the fallback function
                fallback_tag_info = (i, runtime_instructions[i].tag_id)

            else:
                # runtime_instructions[i] is not the entry into the fallback function
                # the fallback function does not have a tag_id
                # Find the last JUMPI
                k = i - 1
                while runtime_instructions[k].name != "JUMPI":
                    k = k - 1
                assert runtime_instructions[k + 1].name != "JUMPDEST"
                fallback_tag_info = (k + 1, None)
            break

        elif runtime_instructions[i - 1].name == "JUMPI" and \
                runtime_instructions[i].name.startswith("PUSH") and \
                runtime_instructions[i + 1].name == "JUMP" and \
                runtime_instructions[i + 2].name == "JUMPDEST":

            # Special case: jump to fallback at the end of the function selector
            # assert (runtime_instructions[i].tag_id != None)
            # tag_id = runtime_instructions[i].tag_id
            assert (int(runtime_instructions[i].operand, 16) in pc_to_tag_id)
            tag_id = pc_to_tag_id[int(runtime_instructions[i].operand, 16)]
            fallback_tag_info = (tag_to_instruction_index[tag_id], tag_id)
            break

        # elif runtime_instructions[i].name.startswith("PUSH") and runtime_instructions[i].tag_id != None:
        elif runtime_instructions[i].name.startswith("PUSH") and int(runtime_instructions[i].operand, 16) in pc_to_tag_id:

            # entry_tag = runtime_instructions[i].tag_id
            tag_hash = None
            entry_tag = pc_to_tag_id[int(runtime_instructions[i].operand, 16)]

            if runtime_instructions[i - 2].name.startswith("PUSH"):
                # Case 1: DUP1 PUSH3/4 0x15DACBEA EQ PUSH2 0x117 JUMPI
                # This occurs in unoptimized modes
                if runtime_instructions[i-1].name == 'EQ':
                    # assert (len(runtime_instructions[i-2].operand) == 10)
                    assert (runtime_instructions[i - 2].operand.startswith("0x"))
                    tag_hash = runtime_instructions[i - 2].operand.lower()
                    i += 2
                elif runtime_instructions[i-1].name == 'GT':
                    index = tag_to_instruction_index[entry_tag]
                    fallback_tag_info = _recognize_external_functions(runtime_instructions,
                                                                      index,
                                                                      tag_to_instruction_index,
                                                                      pc_to_tag_id,
                                                                      external_function_entry_tag_to_hash_list,
                                                                      external_function_entry_tag_to_body_tag,
                                                                      fallback_tag_info,
                                                                      True)
                    i += 2
                    continue

            else:

                # Case 2: AND PUSH4/PUSH3 0x15dacbea DUP2 EQ PUSH2 0x0114 JUMPI
                # This only occurs in optimized mode for the first function tag

                assert (runtime_instructions[i - 3].name in ["PUSH4", "PUSH3"])
                assert (runtime_instructions[i - 2].name == "DUP2")
                assert (runtime_instructions[i - 1].name == "EQ")
                tag_hash = runtime_instructions[i - 3].operand.lower()
                i += 2

            if tag_hash is not None:
                if not entry_tag in external_function_entry_tag_to_hash_list:
                    external_function_entry_tag_to_hash_list[entry_tag] = []
                external_function_entry_tag_to_hash_list[entry_tag].append(canon_signature_hash(tag_hash))

                # Find the body tag of the external function
                # print("========")
                body_tag = get_body_tag(tag_to_instruction_index[entry_tag], runtime_instructions,
                                        tag_to_instruction_index, pc_to_tag_id, set())

                # It is possible that some external functions do not have body tag
                assert (body_tag != 0)
                external_function_entry_tag_to_body_tag[entry_tag] = body_tag
                continue
        i += 1

    return fallback_tag_info


# Given the extry tag of an external function, get its body tag
def get_body_tag(current_idx, runtime_instructions, tag_to_instruction_index, pc_to_tag_id, visited, tag_stack=None,
                 is_jump=True):
    k = current_idx
    if tag_stack is None:
        tag_stack = []
    while k < len(runtime_instructions):
        # print(str(runtime_instructions[k])+" "+str(tag_stack))
        visited.add(k)
        if runtime_instructions[k].name in ["JUMP", "JUMPI"]:
            if runtime_instructions[k - 1].name.startswith("DUP"):
                tag_stack.insert(0, tag_stack[0])
            tag_id = tag_stack.pop(0)
            if len(tag_stack) > 0 and tag_id != 0 and runtime_instructions[k].name == "JUMP":
                # The return address has been pushed onto the tag stack, the jump destination (tag_id) is the body tag
                return tag_id

            if tag_id != 0 and not tag_to_instruction_index[tag_id] in visited:
                assert runtime_instructions[tag_to_instruction_index[tag_id]].name == "JUMPDEST"
                body_tag = get_body_tag(tag_to_instruction_index[tag_id], runtime_instructions,
                                        tag_to_instruction_index, pc_to_tag_id, visited, tag_stack)
                if body_tag is not None:
                    assert (body_tag != 0)
                    return body_tag

            if runtime_instructions[k].name == "JUMP":
                return None

        if runtime_instructions[k].name == "JUMPDEST" and not is_jump:

            if len(tag_stack) > 0 and tag_stack[0] != 0:
                # This is considered the body tag because when this block jump at the end it will return to the current tag stack top
                return tag_stack[0]

        if runtime_instructions[k].name.startswith("PUSH") and int(runtime_instructions[k].operand, 16) in pc_to_tag_id:
            tag_id = pc_to_tag_id[int(runtime_instructions[k].operand, 16)]
            tag_stack.insert(0, tag_id)

        if runtime_instructions[k].name in ["STOP", "REVERT", "RETURN", "INVALID"]:
            return None

        # if runtime_instructions[k].name in ["CALLDATALOAD"]:
        #     if runtime_instructions[k + 1].name == "JUMPDEST":
        #         return runtime_instructions[k + 1].tag_id
        k = k + 1
        is_jump = False

    return None
