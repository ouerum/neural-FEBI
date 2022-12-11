import pickle
import sys, os
import re
import ntpath
import tempfile
import time

import func_timeout.exceptions

import fbdconfig as config

from analysis_utils.basic_blocks import get_all_basic_blocks
from application.call_graph.acyclic_paths import get_cg_acyclic_path
from application.cfg.acyclic_paths import get_function_acyclic_path
from cfg import construct_control_flow_graphs
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
            if temp_runtime_disassembly[i].address * 2 > code_copy_section:
                end_of_code = True
                break
        if end_of_code:
            break

        if temp_runtime_disassembly[i].name == "CODECOPY":

            # conduct a local stack analysis to search for the three arguments of CODECOPY
            op_stacks = backward_local_dataflow_analysis(temp_runtime_disassembly, i)

            if op_stacks[1] != None:
                start_idx = op_stacks[1][0]
            else:
                start_idx = None

            if start_idx != None and temp_runtime_disassembly[i].address < start_idx:
                code_copy_sections.append(start_idx * 2)

    embedded_data_start_idx = None
    for code_copy_section in code_copy_sections:
        start_idx = code_copy_section
        if embedded_data_start_idx == None or start_idx < embedded_data_start_idx:
            embedded_data_start_idx = start_idx

    if embedded_data_start_idx != None:
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
        inst = EVMInstruction(name=opname, operand="0x" + disassembly[i].operand, address=disassembly[i].address,
                              tag_id=None, annotation=None, bin_range=None, src_range=None)
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

    # ================================================================================================
    # Part VI: Generate the function CFG for every external tag

    # for testing
    if config.debug:
        for ind, instr in enumerate(instruction_sequence):
            print(str(ind) + ":" + str(instr) + " " + hex(instr.address))

    # Get the internal function entry tags
    fallback_tag = set() if fallback_entry_info[1] is None else {fallback_entry_info[1]}
    funcs_boundary, call_graph, removed_time = detect_func(instruction_sequence, basic_blocks, pc_to_instruction_index,
                                                           tag_id_to_pc,
                                                           external_function_entry_tag_to_body_tag, fallback_tag,
                                                           fsi_results, tag_map, config.current_threshold,
                                                           config.low_bounder_threshold, config.delay)
    end_time = time.time() - start_time - removed_time

    body_pc_to_public_pc = {}
    for public_tag, body_tag in external_function_entry_tag_to_body_tag.items():
       body_pc_to_public_pc[tag_id_to_pc[body_tag]] = tag_id_to_pc[public_tag]

    funcs_boundary_ret = {}
    for entry_pc, fb in funcs_boundary.items():
        if entry_pc in body_pc_to_public_pc:
            funcs_boundary_ret[body_pc_to_public_pc[entry_pc]] = fb
        else:
            funcs_boundary_ret[entry_pc] = fb

    start_pcs = funcs_boundary.keys()
    #
    # if fallback_entry_info is not None and fallback_entry_info[1] is not None:
    #     start_pcs = start_pcs - {tag_id_to_pc[fallback_entry_info[1]]}

    # ================================================================================================
    # convert call-graph into ctx_string
    # call_graph = {} # entry -> call_site_index -> (tgt_func, tag_context)

    call_graph_edegs = []
    call_graph_nodes = []
    for entry_pc, call_site in call_graph.items():
        call_graph_nodes.append(entry_pc)
        for index, _call_sites in call_site.items():
            for called_func_entry, _ in _call_sites:
                call_graph_edegs.append((entry_pc, called_func_entry))
    # pc_to_cnode_id = {}
    # cnode_count = 0
    # for entry_pc, call_site in call_graph.items():
    #     for index, _call_sites in call_site.items():
    #         for called_func_entry, _ in _call_sites:
    #             if entry_pc not in pc_to_cnode_id:
    #                 pc_to_cnode_id[entry_pc] = cnode_count
    #                 cnode_count += 1
    #             if called_func_entry not in pc_to_cnode_id:
    #                 pc_to_cnode_id[called_func_entry] = cnode_count
    #                 cnode_count += 1
    #             call_graph_edegs.append((pc_to_cnode_id[entry_pc], pc_to_cnode_id[called_func_entry]))

    fallback_entry_pc = set()
    if fallback_entry_info is not None and fallback_entry_info[1] is not None:
        fallback_entry_pc.add(tag_id_to_pc[fallback_entry_info[1]])

    body_pc = [tag_id_to_pc[tag] for tag in external_function_entry_tag_to_body_tag.values()]
    ctx_strs = get_cg_acyclic_path(call_graph_nodes, call_graph_edegs, set(body_pc) | fallback_entry_pc)

    # ================================================================================================
    # build intra-procedural cfg
    if config.is_cfg:
        paths = construct_control_flow_graphs(instruction_sequence, basic_blocks, call_graph, pc_to_instruction_index,
                                          pc_to_tag_id, tag_id_to_pc)
    else:
        paths = []

    # ================================================================================================
    # Part VII: Dump outputs

    # f = open(output_path+os.sep+contract_name+".funcs", "wb")
    # pickle.dump((funcs_boundary, basic_blocks), f)
    # f.close()

    # if debug:
    #     # print("time: {} sec".format(funcs_boundary[1]))
    #     # print(funcs_boundary[0])
    #     body_entry_pc = [tag_id_to_pc[tag] for tag in  external_function_entry_tag_to_body_tag.values()]
    #     golden = load_ground_truth(ground_path)
    #     # print(golden[1])
    #     results = compare_fb(golden[1], funcs_boundary)
    #     print(results)
    #     print(compare_fs(golden[0][0], set(body_entry_pc)))

    return funcs_boundary_ret, start_pcs, instruction_sequence, ctx_strs, paths, end_time


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
                print(time.time() - start_time)
