from copy import copy, deepcopy
import networkx as nx


def df_walk(entry, nodes, edges):
    # nodes: the entry of dg
    # edges: python map that vertex -> the array of succs
    visited = set()
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


def build_dag(nodes, edges, entry):
    dag_edges = []
    _nodes = nodes + [-1]
    pre, rpost = df_walk(entry, _nodes, edges)
    for x, y in edges:
        if x not in pre or y not in rpost:
            continue
        if pre[x] >= pre[y] and rpost[x] >= rpost[y]:
            # backedge
            dag_edges.append((entry, y))
        else:
            dag_edges.append((x, y))
    return dag_edges, pre.keys()


def find_paths(nodes, edges, start):
    dag = nx.DiGraph()
    for edge in edges:
        dag.add_edge(edge[0], edge[1])
    ctx_string = {}
    for node in nodes:
        paths = list(nx.all_simple_paths(dag, start, node))
        ctx_string[node] = paths
    return ctx_string


def get_cg_acyclic_path(function_nodes, call_edges, external_entries):
    if len(external_entries) == 0:
        return {}

    entry_node = -1

    for _, node in enumerate(external_entries):
        call_edges.append((entry_node, node))

    if len(call_edges) == 0:
        return {}

    dag_edges, visited = build_dag(function_nodes, call_edges, entry_node)

    func_ctx_strings = find_paths(visited, dag_edges, entry_node)

    return func_ctx_strings
