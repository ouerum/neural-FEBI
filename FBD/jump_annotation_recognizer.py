from data_flow_analysis import *


def recognize_jump_out(instruction_sequence, basic_blocks):
    for bb in basic_blocks:
        block_end = bb[1]

        if instruction_sequence[block_end].name == 'JUMP':
            opstack = backward_local_dataflow_analysis(instruction_sequence, block_end, True)
            if opstack[0] == None:
                # assert not is_direct_jump(instruction_sequence, block_end)
                instruction_sequence[block_end].annotation = '[out]'


def rconginze_call_sites(instruction_sequence, basic_blocks, function_entrys, body_tags, tag_id_to_pc):
    body_function_entry = []
    possible_calls = {} # target -> call_site

    for body_tag in body_tags:
        body_function_entry.append(tag_id_to_pc[body_tag])

    for id, bb in enumerate(basic_blocks):
        block_end = bb[1]
        if instruction_sequence[block_end].name == 'JUMP' or instruction_sequence[block_end].name == 'JUMPI':
            opstack = backward_local_dataflow_analysis(instruction_sequence, block_end, True)
            if opstack[0] != None and (opstack[0][0] in function_entrys or opstack[0][0] in body_function_entry):
                # instruction_sequence[block_end].annotation = '[in]'
                if opstack[0][0] not in possible_calls:
                    possible_calls[opstack[0][0]] = set()
                possible_calls[opstack[0][0]].add(block_end)
    return possible_calls

