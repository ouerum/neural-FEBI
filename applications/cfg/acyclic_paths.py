from copy import copy, deepcopy
import os
import pickle
from collections import deque
from platform import node
import networkx as nx

from func_timeout import func_set_timeout


def get_succs(v, edges):
    succs = []
    for e in edges:
        if e[0] == v:
            succs.append(e[1])
    return succs


def get_pre(v, edges):
    preds = []
    for e in edges:
        if e[1] == v:
            preds.append(e[0])
    return preds


def df_walk(entry, nodes, edges):
    # nodes: the entry of dg
    # edges: python map that vertex -> the array of succs
    unvisted = set(nodes)
    i = 1
    j = len(nodes)
    pre = {}
    rpost = {}
    unvisted, i, j, pre, rpost = dfw(entry, edges, unvisted, i, j, pre, rpost)
    return pre, rpost


def dfw(x, edges, unvisted, i, j, pre, rpost):
    unvisted.remove(x)
    pre[x] = i
    i = i + 1
    for e in edges:
        if e[0] == x and e[1] in unvisted:
            unvisted, i, j, pre, rpost = dfw(e[1], edges, unvisted, i, j, pre, rpost)
    rpost[x] = j
    j = j - 1
    return unvisted, i, j, pre, rpost


def build_dag(nodes, edges, entry, exit):
    dag_edges = []
    _nodes = [i for i in range(len(nodes))] + [-1, -2]
    pre, rpost = df_walk(entry, _nodes, edges)
    for x, y in edges:
        # if x in pre and y in pre:
        if x not in pre or y not in pre:
            continue
        if pre[x] >= pre[y] and rpost[x] >= rpost[y]:
            # backedge
            dag_edges.append((entry, y))
            dag_edges.append((x, exit))
        else:
            dag_edges.append((x, y))
    return dag_edges


# def find_all_paths(edges, nodes, start, end):
#     visited = {i:False for i in range(len(nodes))}
#     visited[-1] = visited[-2] = False
#     path = []
#     paths = []
#     find_paths(edges, visited, start, end, path, paths)
#     return paths
#
#
# def find_paths(edges, visited, start, end, path, paths):
#     visited[start] = True
#     path.append(start)
#     if start == end:
#         paths.append(deepcopy(path))
#     else:
#         succs = get_succs(start, edges)
#         for succ in succs:
#             if not visited[succ]:
#                 find_paths(edges, visited, succ, end, path, paths)
#
#     path.pop()
#     visited[start] = False


def find_all_paths(edges, nodes, start, end):
    # if path is None:
    #     path = []
    # path = path + [start]
    # if start == end:
    #     return [path]
    #
    # paths = []
    # succs = get_succs(start, edges)
    # for succ in succs:
    #     new_paths = find_paths(edges, succ, end, path)
    #     for new_path in new_paths:
    #         paths.append(new_path)
    # return paths
    dag = nx.DiGraph()
    for edge in edges:
        dag.add_edge(edge[0], edge[1])
    paths = list(nx.all_simple_paths(dag, start, end))
    return paths


@func_set_timeout(30)
def get_function_acyclic_path(function_nodes, function_edges, func_entry):
    entry_node = -1
    exit_node = -2

    for ident, node in enumerate(function_nodes):
        succs = get_succs(ident, function_edges)
        preds = get_pre(ident, function_edges)
        if len(succs) == 0:
            # exit node
            function_edges.append((ident, exit_node))
        if len(preds) == 0 and node:
            function_edges = [(entry_node, ident)] + function_edges

    for ident, node in enumerate(function_nodes):
        if node == func_entry and (-1, ident) not in function_edges:
            function_edges.append((-1, ident))

    if len(function_edges) == 0:
        return []

    dag_edges = build_dag(function_nodes, function_edges, entry_node, exit_node)

    _acyclic_paths = find_all_paths(dag_edges, function_nodes, entry_node, exit_node)

    acyclic_paths = []
    for acyclic_path in _acyclic_paths:
        path = []
        for node in acyclic_path:
            if node != -1 and node != -2:
                path.append(function_nodes[node])
        acyclic_paths.append(path)

    return acyclic_paths


def get_acyclic_path(nodes, edges, entry):
    entry_node = -1
    exit_node = -2

    for ident, node in enumerate(nodes):
        succs = get_succs(ident, edges)
        preds = get_pre(ident, edges)
        if len(succs) == 0:
            # exit node
            edges.append((ident, exit_node))
        if len(preds) == 0:
            edges = [(entry_node, ident)] + edges

    if (-1, entry) not in edges:
        edges.append((-1, entry))

    dag_edges = build_dag(nodes, edges, entry_node, exit_node)

    _acyclic_paths = find_all_paths(dag_edges, edges, entry_node, exit_node)

    acyclic_paths = []
    for acyclic_path in _acyclic_paths:
        path = []
        for node in acyclic_path:
            if node != -1 and node != -2:
                path.append(nodes[node])
        acyclic_paths.append(path)

    return acyclic_paths
