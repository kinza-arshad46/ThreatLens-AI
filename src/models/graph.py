"""
graph.py
--------
Attack Relationship Graph engine (ThreatLens AI blueprint, Section 7):
builds a NetworkX graph connecting source IPs, destination IPs and
individual flow/session records, so an analyst can see the
suspect-IP -> multiple-targets -> alert chain the blueprint describes,
instead of reading isolated rows one at a time.

Same honesty note as uba.py: this needs `source_ip` / `destination_ip`
columns, which some "cleaned" CICIDS2017 CSV releases strip out. See
`require_ip_columns()` for the exact error message if they're missing.
"""

from __future__ import annotations

import networkx as nx
import pandas as pd

SRC_IP_CANDIDATES = ["source_ip", "src_ip", "sourceip"]
DST_IP_CANDIDATES = ["destination_ip", "dst_ip", "destinationip"]


def _find_column(df: pd.DataFrame, candidates: list[str]) -> str | None:
    for c in candidates:
        if c in df.columns:
            return c
    return None


def require_ip_columns(df: pd.DataFrame) -> tuple[str, str]:
    """Same pattern as uba.require_identity_columns — fail loudly and clearly."""
    src_col = _find_column(df, SRC_IP_CANDIDATES)
    dst_col = _find_column(df, DST_IP_CANDIDATES)
    if src_col is None or dst_col is None:
        raise ValueError(
            "The attack graph needs source_ip and destination_ip columns, which "
            "this dataset doesn't have. Some 'cleaned' CICIDS2017 CSVs strip flow "
            "metadata to keep only numeric ML features. Re-download a version that "
            "keeps IP columns (e.g. 'dhoogla/cicids2017' on Kaggle) if you need the "
            "real relationship graph. Columns found: " + str(list(df.columns))
        )
    return src_col, dst_col


def build_attack_graph(
    df: pd.DataFrame,
    src_col: str,
    dst_col: str,
    attack_col: str = "attack_category",
    max_edges: int = 2000,
) -> nx.DiGraph:
    """
    Builds a directed graph: source_ip -> destination_ip, one edge per
    unique (src, dst) pair seen in ATTACK traffic only (excludes Normal —
    the graph is meant to surface suspicious relationships, not model the
    entire network). Each node is tagged with a `node_type` and each edge
    carries the attack types and flow count observed between that pair,
    which is what lets the dashboard's graph view color-code and label
    nodes/edges meaningfully.

    `max_edges` caps how many attack rows get folded into the graph — with
    millions of rows, building one edge per row would produce an
    unreadable, unusable graph; a cap keeps this notebook (and any future
    live view) responsive.
    """
    attack_rows = df[df[attack_col] != "Normal"].head(max_edges)

    G = nx.DiGraph()
    for _, row in attack_rows.iterrows():
        src, dst, attack = row[src_col], row[dst_col], row[attack_col]

        if not G.has_node(src):
            G.add_node(src, node_type="ip")
        if not G.has_node(dst):
            G.add_node(dst, node_type="ip")

        if G.has_edge(src, dst):
            G[src][dst]["weight"] += 1
            G[src][dst]["attack_types"].add(attack)
        else:
            G.add_edge(src, dst, weight=1, attack_types={attack})

    return G


def rank_suspicious_nodes(G: nx.DiGraph, top_n: int = 10) -> pd.DataFrame:
    """
    Ranks nodes by out-degree — an IP that initiated attack traffic toward
    MANY distinct destinations is the "suspect IP -> multiple users/devices"
    pattern the blueprint calls out explicitly as the target interaction to
    surface. Betweenness centrality is added as a second signal: a node
    that sits on many shortest paths between other suspicious nodes can
    indicate a pivot point, even with modest out-degree alone.
    """
    out_degree = dict(G.out_degree())
    betweenness = nx.betweenness_centrality(G) if G.number_of_nodes() > 1 else {}

    ranked = pd.DataFrame({
        "node": list(out_degree.keys()),
        "out_degree": list(out_degree.values()),
    })
    ranked["betweenness"] = ranked["node"].map(betweenness).fillna(0)
    ranked = ranked.sort_values(["out_degree", "betweenness"], ascending=False)
    return ranked.head(top_n).reset_index(drop=True)


def get_entity_subgraph(G: nx.DiGraph, entity: str, depth: int = 1) -> nx.DiGraph:
    """
    Returns the local neighborhood around one entity (e.g. one suspicious
    IP), out to `depth` hops — this is what powers a "click a node to see
    its connections" investigation view, without having to render the
    entire graph at once.
    """
    if entity not in G:
        return nx.DiGraph()
    nodes = {entity}
    frontier = {entity}
    for _ in range(depth):
        next_frontier = set()
        for n in frontier:
            next_frontier |= set(G.successors(n)) | set(G.predecessors(n))
        nodes |= next_frontier
        frontier = next_frontier
    return G.subgraph(nodes).copy()
