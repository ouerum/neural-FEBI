import os, pickle, re


def load_ground_truth(ground_path):
    files = os.listdir(ground_path)
    boundary_files = [filename for filename in files if re.match(".*\.boundary", filename)]
    assert len(boundary_files) == 1
    with open(os.path.join(ground_path, boundary_files[0]), "rb") as f:
        boundary = pickle.load(f)

    ground_fb = {}
    func_boundary = boundary[0][0]
    public = boundary[0][2]
    private = boundary[0][1]
    fallback = boundary[0][3]
    tag_id_to_pc = boundary[1]

    public_entry_set = set()
    private_entry_set = set()
    fallback_entry_set = set()

    for private_entry in private:
        if private_entry in func_boundary[2]:
            priv_entry_pc = tag_id_to_pc[private_entry]
            ground_fb[priv_entry_pc] = set([tag_id_to_pc[tag_id] for tag_id in func_boundary[2][private_entry]])
            private_entry_set.add(priv_entry_pc)

    # some tools may recognize body of interface function as private function
    for body_entry in func_boundary[1]:
        priv_entry_pc = tag_id_to_pc[body_entry]
        ground_fb[priv_entry_pc] = set([tag_id_to_pc[tag_id] for tag_id in func_boundary[1][body_entry]])
        public_entry_set.add(priv_entry_pc)

    if fallback in func_boundary[3]:
        fallback_entry_pc = tag_id_to_pc[fallback]
        ground_fb[fallback_entry_pc] = set([tag_id_to_pc[tag_id] for tag_id in func_boundary[3][fallback]])
        fallback_entry_set.add(fallback_entry_pc)

    return (public_entry_set, private_entry_set, fallback_entry_set), ground_fb, len(tag_id_to_pc.keys())


def compare_fs(ground_fs, target_fs):
    ground_fs_set = ground_fs
    target_fs_set = target_fs
    tp = ground_fs_set & target_fs_set
    fp = target_fs_set - ground_fs_set
    fn = ground_fs_set - target_fs_set
    return cal_score(len(tp), len(fp), len(fn))


def _compare_fb(entry, fb, other_fbs):
    if entry not in other_fbs:
        return False
    elif fb != other_fbs[entry]:
        return False
    return True


def compare_fb(ground_fb, target_fb):
    tp = fp = fn = 0
    for entry, fb in ground_fb.items():
        if not _compare_fb(entry, fb, target_fb):
            fn += 1
        else:
            tp += 1

    for entry, fb in target_fb.items():
        if not _compare_fb(entry, fb, ground_fb):
            fp += 1

    return cal_score(tp, fp, fn)


def precision_score(tp, fp):
    if fp == 0:
        return 1, "warn"
    else:
        return tp/(tp+fp), ""


def recall_score(tp, fn):
    if fn == 0:
        return 1, "warn"
    else:
        return tp/(fn+tp), ""


def f1_score(p, r):
    if p + r == 0:
        return 0, "warn"
    else:
        return 2*p*r/(p+r), ""


def cal_score(tp, fp, fn):
    p, warn_p = precision_score(tp, fp)

    # if warn_p:
    #     warnings.warn("Precision: Div by Zero")

    r, warn_r = recall_score(tp, fn)
    # if warn_r:
    #     warnings.warn("Recall: Div by Zero")

    f1, warn_f1 = f1_score(p, r)
    # if warn_f1:
    #     warnings.warn("F1-Score: Div by Zero")

    return f1, p, r