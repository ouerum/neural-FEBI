import re
import torch
import os
import pickle
import sys
import random

folder = os.path.dirname(__file__)
sys.path.append(folder + "/../..")

from collections import Counter
from disassembly.evmdasm import *

from functools import reduce
import utils.config as config


def split_blocks(runtime_bin):
    basic_blocks = {}
    current_block_start = 0
    runtime_str = ''.join(runtime_bin)
    runtime_bytecode = EvmBytecode(runtime_str)
    runtime_disassembly = runtime_bytecode.disassemble()
    tag_pc_to_id = {}
    tag_id = 0

    for i in range(0, len(runtime_disassembly) + 1):
        if i != len(runtime_disassembly) and runtime_disassembly[i].name == 'JUMPDEST':
            tag_pc_to_id[runtime_disassembly[i].address] = tag_id
            tag_id += 1

        if i == len(runtime_disassembly):
            if i - 1 >= current_block_start:
                basic_blocks[runtime_disassembly[current_block_start].address] = (current_block_start, i - 1)

        elif runtime_disassembly[i].name == "JUMPDEST" and not current_block_start == i:
            assert (current_block_start <= i - 1)
            basic_blocks[runtime_disassembly[current_block_start].address] = (current_block_start, i - 1)
            current_block_start = i

        elif runtime_disassembly[i].name in ["JUMP", "STOP", "REVERT", "RETURN", "SELFDESTRUCT", "INVALID"]:
            assert (current_block_start <= i)
            basic_blocks[runtime_disassembly[current_block_start].address] = (current_block_start, i)
            current_block_start = i + 1

    code = {}
    for pc, bb in basic_blocks.items():
        block_cf = convert_block_cf(runtime_disassembly[bb[0]:bb[1] + 1], tag_pc_to_id)
        block_instr = convert_block_instr(runtime_disassembly[bb[0]:bb[1] + 1], tag_pc_to_id)
        if len(block_cf) > 0:
            code[pc] = (block_cf, block_instr)

    return code


def is_add_to_block(current_ind, length, max_instr_len_s, max_instr_len_e):
    if max_instr_len_s < current_ind or current_ind < length - max_instr_len_e:
        return False
    return True


def convert_block_cf(assembly, tag_pc_to_id, max_instr_len_s=5, max_instr_length_e=5):
    block_cf = []
    for ind, asm in enumerate(assembly):  # may use different method: set the fixed size of 10,
        if asm.name.startswith('PUSH'):
            if int(asm.operand, 16) not in tag_pc_to_id:
                # block.append(str(asm.opcode))
                pass
            else:
                # block.append('t'+str(tag_pc_to_id[int(asm.operand, 16)]))
                block_cf.append("t")
        elif asm.name in ["STOP", "REVERT", "RETURN", "INVALID", "SELFDESTRUCT"]:
            block_cf.append('s')
        elif asm.name == 'JUMPDEST':
            # block.append('t'+str(tag_pc_to_id[asm.address])+":")
            block_cf.append('t')
        elif asm.name == 'JUMP':
            block_cf.append('j')
        elif asm.name == 'JUMPI':
            block_cf.append('i')
        else:
            # block.append(str(asm.opcode))
            pass
    return block_cf


def convert_block_instr(assembly, tag_pc_to_id, max_instr_len_s=15, max_instr_len_e=15):
    block_instr = []
    length = len(assembly)
    max_len = max_instr_len_s + max_instr_len_e
    for ind, asm in enumerate(assembly):
        if length > max_len and (max_instr_len_s <= ind <= length - max_instr_len_e):
            continue
        if asm.name.startswith('PUSH'):
            if int(asm.operand, 16) not in tag_pc_to_id:
                block_instr.append(str(asm.opcode))
            else:
                # block_instr.append('t' + str(tag_pc_to_id[int(asm.operand, 16)]))
                # block_instr.append("t")
                pass
        elif asm.name in ["STOP", "REVERT", "RETURN", "INVALID", "SELFDESTRUCT"]:
            # block_instr.append('s')
            pass
        elif asm.name == 'JUMPDEST':
            # block_instr.append('t' + str(tag_pc_to_id[asm.address]) + ":")
            # block_instr.append('t')
            pass
        else:
            block_instr.append(str(asm.opcode))
    return block_instr


# def read_code_tags(contracts_dir, addresses):
#     blocks = []
#     tags = []
#     for address in addresses:
#         temp_b = []
#         temp_t = []
#
#         files = os.listdir(os.path.join(contracts_dir,address))
#         boundary_files = [filename for filename in files if re.match(".*\.boundary", filename)]
#         runtime_files = [filename for filename in files if re.match(".*\.bin-runtime", filename)]
#         assert len(boundary_files) == 1 and len(runtime_files) == 1
#
#         runtime_code_path = os.path.join(contracts_dir, address, runtime_files[0])
#         function_boundaries_path = os.path.join(contracts_dir, address, boundary_files[0])
#         with open(runtime_code_path, 'r') as f:
#             runtime_code = f.read()
#             code_blocks = split_blocks(runtime_code)
#         with open(function_boundaries_path, 'rb') as f:
#             function_boundaries = pickle.load(f)
#
#         function_boundaries,tag_to_pc = function_boundaries
#         entry_addrs = []
#         for entry, _ in function_boundaries.items():
#             entry_addrs.append(tag_to_pc[entry])
#
#         for addr, code_block in code_blocks.items():
#             # temp_b.append(",".join(code_block))
#             temp_b.append(code_block)
#             if addr in entry_addrs:
#                 temp_t.append('S')
#             else:
#                 temp_t.append('NS')
#         assert len(temp_b) == len(temp_t)
#         blocks.append(temp_b)
#         tags.append(temp_t)
#     return blocks, tags


def create_maps(block_lists, block_instr_lists, tags, min_block_freq=0, min_instr_freq=0):
    block_freq = Counter()
    instr_freq = Counter()
    tag_map = set()

    for block_list, block_instr_list, t in zip(block_lists, block_instr_lists, tags):
        block_freq.update(["".join(b) for b in block_list])
        # block_freq.update(b for b in block_list)
        if len(block_list) != 0:
            instr_freq.update(list(reduce(lambda x, y: list(x) + [' '] + list(y), block_instr_list)))
            tag_map.update(t)

    block_map = {k: v + 1 for v, k in enumerate([b for b in block_freq.keys() if block_freq[b] > min_block_freq])}
    tag_map = {k: v + 1 for v, k in enumerate(tag_map)}
    instr_map = {k: v + 1 for v, k in enumerate([i for i in instr_freq.keys() if instr_freq[i] > min_instr_freq])}

    block_map['<pad>'] = 0
    block_map['<end>'] = len(block_map)
    block_map['<unk>'] = len(block_map)
    tag_map['<pad>'] = 0
    tag_map['<start>'] = len(tag_map)
    tag_map['<end>'] = len(tag_map)
    instr_map['<pad>'] = 0
    instr_map['<end>'] = len(instr_map)
    instr_map['<unk>'] = len(instr_map)

    return block_map, instr_map, tag_map


def create_input_tensors(blocks, tags, block_map, tag_map, addresses, crf=False):
    bmaps = list(
        map(lambda s: list(map(lambda b: block_map.get(''.join(b), block_map['<unk>']), s)) + [block_map['<end>']],
            blocks))
    tmaps = list(map(lambda s: list(map(lambda t: tag_map[t], s)) + [tag_map['<end>']], tags))
    if crf:
        tmaps = list(map(lambda s: [tag_map['<start>'] * len(tag_map) + s[0]] + [s[i - 1] * len(tag_map) + s[i] for i in
                                                                                 range(1, len(s))], tmaps))
    block_pad_len = max(list(map(lambda s: len(s), bmaps)))
    assert block_pad_len == max(list(map(lambda s: len(s), tmaps)))

    padded_bmaps = []
    padded_tmaps = []
    bmap_lengths = []

    for w, t in zip(bmaps, tmaps):
        assert len(w) == len(t)
        padded_bmaps.append(w + [block_map['<pad>']] * (block_pad_len - len(w)))
        padded_tmaps.append(t + [tag_map['<pad>']] * (block_pad_len - len(t)))
        bmap_lengths.append(len(w))

    padded_bmaps = torch.LongTensor(padded_bmaps)
    padded_tmaps = torch.LongTensor(padded_tmaps)

    bmap_lengths = torch.LongTensor(bmap_lengths)

    return padded_bmaps, padded_tmaps, bmap_lengths, addresses


def create_input_tensors_(blocks, blocks_instr, tags, block_map, tag_map, addresses, instr_map):
    bmaps = list(
        map(lambda s: list(map(lambda b: block_map.get(''.join(b), block_map['<unk>']), s)) + [block_map['<end>']],
            blocks))
    instr_f = list(map(lambda s: list(reduce(lambda x, y: list(x) + [' '] + list(y), s)) + [' '], blocks_instr))
    instr_b = list(
        map(lambda s: list(reversed([' '] + list(reduce(lambda x, y: list(x) + [' '] + list(y), s)))), blocks_instr))
    imaps_f = list(
        map(lambda s: list(map(lambda c: instr_map.get(c, instr_map['<unk>']), s)) + [instr_map['<end>']], instr_f))
    imaps_b = list(
        map(lambda s: list(map(lambda c: instr_map.get(c, instr_map['<unk>']), s)) + [instr_map['<end>']], instr_b))
    imarkers_f = list(map(lambda s: [ind for ind in range(len(s)) if s[ind] == instr_map[' ']] + [len(s) - 1], imaps_f))
    imarkers_b = list(
        map(lambda s: list(reversed([ind for ind in range(len(s)) if s[ind] == instr_map[' ']])) + [len(s) - 1],
            imaps_b))
    tmaps = list(map(lambda s: list(map(lambda t: tag_map[t], s)) + [tag_map['<end>']], tags))
    tmaps = list(map(lambda s: [tag_map['<start>'] * len(tag_map) + s[0]] + [s[i - 1] * len(tag_map) + s[i] for i in
                                                                             range(1, len(s))], tmaps))
    block_pad_len = max(list(map(lambda s: len(s), bmaps)))
    instr_pad_len = max(list(map(lambda s: len(s), imaps_f)))
    block_inst_pad_len = max(list(map(lambda s: len(s), bmaps)))

    padded_imaps_f = []
    padded_imaps_b = []
    padded_imakers_f = []
    padded_imakers_b = []

    padded_bmaps = []
    padded_tmaps = []
    bmap_lengths = []
    imap_lengths = []


    for b, instr_f, instr_b, instr_mf, instr_mb, t in zip(bmaps, imaps_f, imaps_b, imarkers_f, imarkers_b, tmaps):
        assert len(b) == len(t) == len(instr_mf) == len(instr_mb)
        assert len(imaps_f) == len(imaps_b)
        padded_bmaps.append(b + [block_map['<pad>']] * (block_pad_len - len(b)))
        padded_tmaps.append(t + [tag_map['<pad>']] * (block_pad_len - len(t)))
        padded_imaps_f.append(instr_f + [instr_map['<pad>']] * (instr_pad_len - len(instr_f)))
        padded_imaps_b.append(instr_b + [instr_map['<pad>']] * (instr_pad_len - len(instr_b)))

        padded_imakers_f.append(instr_mf + [0] * (block_inst_pad_len - len(b)))
        padded_imakers_b.append(instr_mb + [0] * (block_inst_pad_len - len(b)))
        bmap_lengths.append(len(b))
        imap_lengths.append(len(instr_f))

        assert len(padded_bmaps[-1]) == len(padded_tmaps[-1]) == len(padded_imakers_f[-1]) == len(
            padded_imakers_b[-1]) == block_pad_len
        assert len(padded_imaps_f[-1]) == len(padded_imaps_b[-1]) == instr_pad_len

    padded_bmaps = torch.LongTensor(padded_bmaps)
    padded_tmaps = torch.LongTensor(padded_tmaps)

    bmap_lengths = torch.LongTensor(bmap_lengths)

    padded_imaps_f = torch.LongTensor(padded_imaps_f)
    padded_imaps_b = torch.LongTensor(padded_imaps_b)
    padded_imakers_f = torch.LongTensor(padded_imakers_f)
    padded_imakers_b = torch.LongTensor(padded_imakers_b)
    imap_lengths = torch.LongTensor(imap_lengths)

    return padded_bmaps, padded_imaps_f, padded_imaps_b, padded_imakers_f, padded_imakers_b, padded_tmaps, \
           bmap_lengths, imap_lengths, addresses


def save_checkpoint(output, filename, epoch, model, optimizer, val_f1, block_map, instr_map, tag_map, is_best, datas=None):
    state = {'epoch': epoch,
             'f1': val_f1,
             'model': model,
             'optimizer': optimizer,
             'block_map': block_map,
             'tag_map': tag_map,
             'instr_map': instr_map}
    if is_best:
        torch.save(state, os.path.join(output, filename))
    if datas is not None:
        print("for testing")
        with open(os.path.join(output, filename+"_datas"), "wb") as f:
            pickle.dump(datas, f)


class AverageMeter(object):
    """
    Keeps track of most recent, average, sum, and count of a metric.
    """

    def __init__(self):
        self.reset()
        self.values = []
        self.count = 0
        self.sum = 0

    def reset(self):
        self.val = 0
        self.avg = 0
        self.sum = 0
        self.count = 0
        self.values = []

    def update(self, val, n=1):
        self.values.append(val)
        self.val = val
        self.sum += val * n
        self.count += n
        self.avg = self.sum / self.count


def adjust_learning_rate(optimizer, new_lr):
    print("\nDECAYING learning rate.")
    for param_group in optimizer.param_groups:
        param_group['lr'] = new_lr
    print("The new learning rate is %f\n" % (optimizer.param_groups[0]['lr'],))


def log_sum_exp(tensor, dim):
    m, _ = torch.max(tensor, dim)
    m_expanded = m.unsqueeze(dim).expand_as(tensor)
    return m + torch.log(torch.sum(torch.exp(tensor - m_expanded), dim))


def clip_gradient(optimizer, grad_clip):
    """
    Clip gradients computed during backpropagation to prevent gradient explosion.

    :param optimizer: optimized with the gradients to be clipped
    :param grad_clip: gradient clip value
    """
    for group in optimizer.param_groups:
        for param in group['params']:
            if param.grad is not None:
                param.grad.data.clamp_(-grad_clip, grad_clip)


def sort_by_lengths(word_lists, tag_lists):
    pairs = list(zip(word_lists, tag_lists))
    indices = sorted(range(len(pairs)), key=lambda x: len(pairs[x][0]), reverse=True)

    pairs = [pairs[i] for i in indices]
    word_lists, tag_lists = list(zip(*pairs))
    return word_lists, tag_lists, indices


def split_list(full_list, ratio, shuffle=False):
    offset = int(len(full_list) * ratio)
    if len(full_list) == 0 or offset < 1:
        return [], full_list
    if shuffle:
        random.shuffle(full_list)
    list1 = full_list[:offset]
    list2 = full_list[offset:]
    return list1, list2


def get_temp_dir():
    os.system("rm -rf " + config.temp_dir + "*")
    return config.temp_dir


def read_code_tag(temp_dir, addresses):
    blocks = []
    blocks_instr = []
    tags = []
    addrs = []
    pcs = {}
    empty_contracts_count = 0
    for addr in addresses:
        addrs.append(addr)
        with open(temp_dir + os.sep + addr, 'rb') as f:
            result = pickle.load(f)
            # print(result)
            if len(result[0]) != 0:
                blocks.append(result[0])
                blocks_instr.append(result[1])
                tags.append(result[2])
                pcs[addr] = result[3]
            else:
                empty_contracts_count += 1

    return addrs, blocks, blocks_instr, tags, pcs, empty_contracts_count
