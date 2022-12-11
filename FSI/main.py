from utils import config
from evaluate import *

import time
import utils.common as common


def main():
  
    with open(config.address_path, "rb") as f:
        address_lists = pickle.load(f)

    print("loading {0} contracts".format(len(address_lists[0])+len(address_lists[1])+len(address_lists[2])))
    trainning_addresses, train_blocks, train_instrs, train_tags, _, _ = common.read_code_tag(config.data_dir,
                                                                                           address_lists[0])
    val_addresses, val_blocks, val_instrs, val_tags, _, _ = common.read_code_tag(config.data_dir, address_lists[1])

    fsi_train_eval((train_blocks, train_instrs, train_tags, trainning_addresses),
                                  (val_blocks, val_blocks, val_tags, val_addresses), block_map,
                                  instr_map, tag_map)


if __name__ == "__main__":
    main()
    # test()
