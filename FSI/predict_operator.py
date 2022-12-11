import os
import pickle, json, csv, time
import warnings

from evaluate import *
import sklearn.metrics as metircs

from utils import config
from utils import common

def compare_fs(ground_fs, target_fs):
    ground_fs_set = ground_fs
    target_fs_set = target_fs
    tp = ground_fs_set & target_fs_set
    fp = target_fs_set - ground_fs_set
    fn = ground_fs_set - target_fs_set
    return cal_score(len(tp), len(fp), len(fn))


def precision_score(tp, fp):
    if fp == 0:
        return 1, ""
    # if tp + fp == 0:
    #     return 0, "warn"
    else:
        return tp/(tp+fp), ""


def recall_score(tp, fn):
    if fn == 0:
        return 1, ""
    # if tp + fn == 0:
    #     return 0, "warn"
    else:
        return tp/(fn+tp), ""


def f1_score(p, r):
    if p + r == 0:
        return 0, "warn"
    else:
        return 2*p*r/(p+r), ""


def cal_score(tp, fp, fn):
    p, warn_p = precision_score(tp, fp)

    if warn_p:
        warnings.warn("Precision: Div by Zero")

    r, warn_r = recall_score(tp, fn)
    if warn_r:
        warnings.warn("Recall: Div by Zero")

    f1, warn_f1 = f1_score(p, r)
    if warn_f1:
        warnings.warn("F1-Score: Div by Zero")

    return f1, p, r



def cal_metric(pred_tag_lists, golden_tag_lists, addrs, pcs):
    precisions = AverageMeter()
    recalls = AverageMeter()
    f1s = AverageMeter()

    datas = {}

    for pred_tag_list, golden_tag_list, addr in zip(pred_tag_lists, golden_tag_lists, addrs):
        pred_start_pcs = set()
        files = os.listdir(os.path.join(config.contracts_dir, addr))
        boundary_files = [filename for filename in files if re.match(".*\.boundary", filename)]
        assert len(boundary_files) == 1

        function_boundaries_path = os.path.join(config.contracts_dir, addr, boundary_files[0])
        with open(function_boundaries_path, 'rb') as f:
            fb = pickle.load(f)
        boundary, tag_to_pc = fb

        public_pc_set = set([tag_to_pc[tag_id] for tag_id, _ in boundary[0][1].items()])
        fallback_pc_set = set([tag_to_pc[tag_id] for tag_id, _ in boundary[0][3].items()])
        priv_pc_set = set([tag_to_pc[tag_id] for tag_id, _ in boundary[0][2].items()])

        _pcs = pcs[addr]
        for id, pred_tag in enumerate(pred_tag_list):
            if pred_tag == 'S' and id < len(_pcs):
                pc = _pcs[id]
                pred_start_pcs.add(pc)

        pred_start_pcs = pred_start_pcs - public_pc_set - fallback_pc_set
        f1, precision, recall = compare_fs(priv_pc_set, pred_start_pcs)

        precisions.update(precision)
        recalls.update(recall)
        f1s.update(f1)
        datas[addr] = [f1, precision, recall, ";".join([str(s) for s in list(pred_start_pcs)])]

    return f1s, precisions, recalls, datas




def FSI_biLSTM_test(test_input, pcs):
    test_blocks_lists, test_instrs_lists, test_tag_lists, test_addrs = test_input
    saved_model_path = os.path.join(config.modle_output, config.dtype)
    checkpoint = torch.load(saved_model_path)
    model = checkpoint['model']
    block_map = checkpoint['block_map']
    tag_map = checkpoint['tag_map']
    instr_map = checkpoint['instr_map']
    pred_tag_lists, gloden_tag_lists, test_addrs = fsi.test(model, test_blocks_lists, test_instrs_lists, test_tag_lists,
                                                            test_addrs,
                                                            block_map,
                                                            instr_map, tag_map)
    return cal_metric(pred_tag_lists, test_tag_lists, test_addrs, pcs)


def test():
   
    with open(config.address_path, "rb") as f:
        address_lists = pickle.load(f)

    test_addrs, test_blocks, test_instrs, test_tags, pcs, _ = common.read_code_tag(config.data_dir, address_lists[2])

    start = time.time()
    result = FSI_biLSTM_test((test_blocks, test_instrs, test_tags, test_addrs), pcs)

    end = time.time()
    print(str(end-start) + "sec")


if __name__ == "__main__":
    test()