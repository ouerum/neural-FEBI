import pickle
import sys, os
import re
import ntpath
import tempfile
import time

import fbdconfig as config

from analysis_utils.control_flow_analysis import get_all_basic_blocks
from data_flow_analysis import backward_local_dataflow_analysis
from analysis_utils.evm_structure import recognize_external_functions
from analysis_utils.evm_utils import *
from analysis_utils.tools import *
from disassembly.evmdasm import EvmBytecode
from func_detect import detect_func
from jump_annotation_recognizer import recognize_jump_out


def function_boundary_detection(binary_full_path, fsi_results, tag_map):
    contract_name = ntpath.basename(binary_full_path)
    idx = contract_name.rfind(".")
    contract_name = contract_name[:idx]

    if not os.path.exists(binary_full_path):
        print("The binary code does not exists! " + binary_full_path)
        sys.exit()



    f = open(binary_full_path, "r")
    b = f.read()
    f.close()
    b = replace_evm_stub(b)

    assert (binary_full_path.endswith(".bin-runtime"))
    runtime_bin = b

    aux_start_idx = runtime_bin.rfind("a165627a7a72305820")
    if (aux_start_idx != -1):
        aux_bin = runtime_bin[aux_start_idx:]
        runtime_bin = runtime_bin[:aux_start_idx]
    else:
        aux_start_idx = runtime_bin.rfind("a265627a7a72305820")
        if (aux_start_idx != -1):
            aux_bin = runtime_bin[aux_start_idx:]
            runtime_bin = runtime_bin[:aux_start_idx]
        else:
            aux_bin = ""

        # Find the data section in bin
    code_copy_sections = []
    temp_runtime_bytecode = EvmBytecode(runtime_bin)
    temp_runtime_disassembly = temp_runtime_bytecode.disassemble()
    for i in range(0, len(temp_runtime_disassembly)):

        end_of_code = False
        for code_copy_section in code_copy_sections:
            if temp_runtime_disassembly[i].address*2 > code_copy_section:
                end_of_code = True
                break
        if end_of_code:
            break

        if temp_runtime_disassembly[i].name == "CODECOPY":

            # conduct a local stack analysis to search for the three arguments of CODECOPY
            op_stacks = backward_local_dataflow_analysis(temp_runtime_disassembly, i)

            if op_stacks[1]!=None:
                start_idx = op_stacks[1][0]
            else:
                start_idx = None

            if start_idx != None and temp_runtime_disassembly[i].address < start_idx:
                code_copy_sections.append(start_idx*2)

    embedded_data_start_idx = None
    for code_copy_section in code_copy_sections:
        start_idx = code_copy_section
        if embedded_data_start_idx == None or start_idx<embedded_data_start_idx:
            embedded_data_start_idx = start_idx

    if embedded_data_start_idx!=None:
        runtime_data_bin = runtime_bin[embedded_data_start_idx:]
        runtime_bin = runtime_bin[:embedded_data_start_idx]
    else:
        runtime_data_bin = ""

    bytecode = EvmBytecode(runtime_bin)
    disassembly = bytecode.disassemble()
    nerrors = len(disassembly.errors)
    if nerrors != 0:
        print(disassembly.as_string)
        assert (False)

    instruction_sequence = []
    for i in range(0, len(disassembly)):

        opname = disassembly[i].name.replace("UNKNOWN_0xfe", "INVALID")
        inst = EVMInstruction(name=opname, operand="0x"+disassembly[i].operand, address=disassembly[i].address, tag_id=None, annotation=None, bin_range=None, src_range=None)
        instruction_sequence.append(inst)

    pc_to_instruction_index = {}
    for i in range(0, len(instruction_sequence)):
        pc_to_instruction_index[instruction_sequence[i].address] = i

    assert (b.startswith(runtime_bin))
    assert (b.startswith(runtime_bin + runtime_data_bin))
    assert (b.startswith(runtime_bin + runtime_data_bin + aux_bin))

    # Part II: Extract basic blocks and collect all the tags
    pc_to_tag_id = {}
    tag_id_to_pc = {}
    tag_id_to_instructions_index = {}

    # Tag 0 represents the error_tag
    tag_id_to_pc[0] = None

    for i in range(0, len(instruction_sequence)):
        if instruction_sequence[i].name == "JUMPDEST":
            addr = instruction_sequence[i].address
            new_tag_id = len(tag_id_to_pc)
            pc_to_tag_id[addr] = new_tag_id
            tag_id_to_pc[new_tag_id] = addr
            instruction_sequence[i].tag_id = new_tag_id
            tag_id_to_instructions_index[new_tag_id] = i

    # Get the basic blocks
    basic_blocks = get_all_basic_blocks(instruction_sequence)

    start_time = time.time()

    # ================================================================================================
    # tmp Part: Recognize jump [out] annotation
    recognize_jump_out(instruction_sequence, basic_blocks)

    # ================================================================================================
    # Part IV: Recognize the external functions/variable getters
    external_function_entry_tag_to_hash_list, external_function_entry_tag_to_body_tag, fallback_entry_info = \
        recognize_external_functions(instruction_sequence, pc_to_tag_id)


    # for testing
    if config.debug:
        for ind, instr in enumerate(instruction_sequence):
            print(str(ind) + ":" + str(instr) + " " + hex(instr.address))

    # Get the internal function entry tags
    fallback_tag = set() if fallback_entry_info[1] is None else {fallback_entry_info[1]}
    funcs_boundary, removed_time = detect_func(instruction_sequence, basic_blocks, pc_to_instruction_index, tag_id_to_pc,
                                 external_function_entry_tag_to_body_tag, fallback_tag,
                                 fsi_results, tag_map, config.current_threshold,
                                 config.low_bounder_threshold, config.delay)
    end_time = time.time() - start_time - removed_time
    body_pc = [tag_id_to_pc[tag] for tag in external_function_entry_tag_to_body_tag.values()]

    return funcs_boundary, body_pc, end_time




if __name__ == "__main__":
    # files = os.listdir(config.fsi_result_path)[:100]
    files = ['355']
    for file in files:
        print(file)
        with open(os.path.join(config.fsi_result_path, file), 'rb') as f:
            addrs, crf_scores, bmap_lengths_sorted, decoded_time, tag_map = pickle.load(f)
            crf_scores = crf_scores.to("cpu")
            bmap_lengths_sorted = bmap_lengths_sorted.to("cpu")
            for i, addr in enumerate(addrs):
                # if i == 0:
                    print(addr)
                    ground_path = os.path.join(config.contracts_dir, addr)
                    files = os.listdir(ground_path)
                    runtime_files = [filename for filename in files if re.match(".*\.bin-runtime", filename)]
                    assert len(runtime_files) == 1
                    binary_full_path = os.path.join(ground_path, runtime_files[0])
                    start_time = time.time()
                    function_boundary_detection(os.path.join(config.fsi_result_path, addr), binary_full_path,
                                                (crf_scores[i], bmap_lengths_sorted[i]), tag_map, config.debug)
                    print(time.time() -  start_time)





