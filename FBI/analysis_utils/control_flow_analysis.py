#!/usr/local/bin/python3
#
# This file contains control flow analysis functions.    
#
# Author: Dr. Wang
# 
import sys, os  # @UnusedImport
from queue import Queue

folder = os.path.dirname(__file__)
sys.path.append(os.path.normpath(folder + "/.."))


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

