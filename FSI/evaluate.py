import torch

import bilstm_operator as bilstm
import rnn_operator as birnn
import fsi_operator as fsi


from model.FSI_BILSTM_CRF import FSI_BiLSTM_CRF
from sklearn.metrics import f1_score, precision_score, recall_score

from utils.common import *


def fsi_train_eval(train_inputs, val_inputs, block_map, instr_map, tag_map):
    train_block_lists, train_instr_lists, train_tag_lists, train_addrs = train_inputs
    val_block_lists, val_instr_lists, val_tag_lists, val_addrs = val_inputs
    # test_blocks_lists, test_tag_lists = test_inputs

    instrset_size = len(instr_map)
    blockset_size = len(block_map)
    tagset_size = len(tag_map)
    print("==== for test ====")
    print(blockset_size)
    print(instrset_size)

    fsi_operator = fsi.FSI_operator(instrset_size, blockset_size, tagset_size)
    fsi_operator.train(train_block_lists, train_instr_lists, train_tag_lists, val_block_lists, val_instr_lists,
                       val_tag_lists, block_map, instr_map, tag_map, train_addrs, val_addrs)

