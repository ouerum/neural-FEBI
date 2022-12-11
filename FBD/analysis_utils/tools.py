import os, pickle, re

from application.call_graph.acyclic_paths import get_cg_acyclic_path


def load_ground_truth(ground_path):
    # the target private entry was not a perfect method
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
    call_graph = boundary[2]

    public_entry_set = set()
    body_entry_set = set()
    private_entry_set = set()
    fallback_entry_set = set()

    for public_interface, public_body in public.items():
        if public_interface in func_boundary[0]:
            pub_interface_pc = tag_id_to_pc[public_interface]
            public_entry_set.add(pub_interface_pc)
            # ground_fb[pub_interface_pc] = set([tag_id_to_pc[tag_id] for tag_id in func_boundary[0][public_interface]])

            if public_body in func_boundary[1]:
                public_body_pc = tag_id_to_pc[public_body]
                body_entry_set.add(public_body_pc)
                ground_fb[pub_interface_pc] = set([tag_id_to_pc[tag_id] for tag_id in func_boundary[1][public_body]])

    for private_entry in private:
        if private_entry in func_boundary[2]:
            priv_entry_pc = tag_id_to_pc[private_entry]
            ground_fb[priv_entry_pc] = set([tag_id_to_pc[tag_id] for tag_id in func_boundary[2][private_entry]])
            private_entry_set.add(priv_entry_pc)

    # # some tools may recognize body of interface function as private function
    # for private_entry in target_public_interface_priv:
    #     if private_entry in func_boundary[1][private_entry]:
    #         priv_entry_pc = tag_id_to_pc[private_entry]
    #         ground_fb[priv_entry_pc] = set([tag_id_to_pc[tag_id] for tag_id in func_boundary[1][private_entry]])
    #         private_entry_set.add(priv_entry_pc)

    if fallback in func_boundary[3]:
        fallback_entry_pc = tag_id_to_pc[fallback]
        ground_fb[fallback_entry_pc] = set([tag_id_to_pc[tag_id] for tag_id in func_boundary[3][fallback]])
        fallback_entry_set.add(fallback_entry_pc)

    call_graph_node = []
    for entry_pc in list(body_entry_set | fallback_entry_set | private_entry_set):
        call_graph_node.append(entry_pc)

    call_graph_edge = []
    for e in call_graph[1]:
        if e[0] in public_entry_set:
            continue
        else:
            call_graph_edge.append(e)

    ctx_string = get_cg_acyclic_path(call_graph_node, call_graph_edge, body_entry_set|fallback_entry_set)

    return (public_entry_set, body_entry_set, private_entry_set, fallback_entry_set), ground_fb, len(tag_id_to_pc.keys()), ctx_string


def load_ground_truth_paths(ground_path):
    files = os.listdir(ground_path)
    paths_files = [filename for filename in files if re.match(".*\.path", filename)]
    assert len(paths_files) == 1
    with open(os.path.join(ground_path, paths_files[0]), "rb") as f:
        paths = pickle.load(f)
    return paths[0]


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


def recollect_ctx(ctx_strings):
    ctx_set = set()
    ctx_cal = {}
    for ctx_str in ctx_strings:
        if ctx_str not in ctx_set:
            ctx_set.add(ctx_str)
            ctx_cal[ctx_str] = 1
        else:
            num = ctx_cal[ctx_str]
            additonal_str = ""
            for i in range(num):
                additonal_str += "*"
            ctx_set.add(ctx_str+additonal_str)
            ctx_cal[ctx_str] += 1
    return ctx_set


def compare_ctx_strs(ground_ctx, target_ctx):
    ground_ctx_set = recollect_ctx(ground_ctx)
    target_ctx_set = recollect_ctx(target_ctx)
    return compare_fs(ground_ctx_set, target_ctx_set)


def compare_paths(ground_paths, target_paths):
    ground_path_set = set()
    for path in ground_paths:
        ground_path_set.add(str(path))
    target_path_set = set()
    for path in target_paths:
        target_path_set.add(str(path))
    return compare_fs(ground_path_set, target_path_set)


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