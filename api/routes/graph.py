"""
GET /graph/{entity_id} — the attack relationship graph endpoint (blueprint
Section 9), built live from persisted SecurityEvent + Attack rows rather
than a separately stored graph table — the graph is a *view* over the
existing event/attack data, so it's always in sync with the latest alerts
without needing its own write path.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.database.models import Attack, SecurityEvent
from src.database.session import get_db
from api.schemas.schemas import GraphEdge, GraphNode, GraphResponse

router = APIRouter(tags=["graph"])


@router.get("/graph/{entity_id}", response_model=GraphResponse)
def get_entity_graph(entity_id: str, depth: int = 1, db: Session = Depends(get_db)):
    """
    Returns the local neighborhood around one IP: every attack event where
    this entity was the source, plus (at depth=2) a second hop out from
    each of those destinations — mirroring `get_entity_subgraph()` from
    Notebook 07, but computed against live database rows instead of a
    static parquet file.
    """
    rows = (
        db.query(SecurityEvent.source_ip, SecurityEvent.destination_ip, Attack.attack_category)
        .join(Attack, Attack.event_id == SecurityEvent.id)
        .filter(SecurityEvent.source_ip == entity_id)
        .all()
    )

    frontier_ips = {r.destination_ip for r in rows if r.destination_ip}
    if depth >= 2 and frontier_ips:
        second_hop = (
            db.query(SecurityEvent.source_ip, SecurityEvent.destination_ip, Attack.attack_category)
            .join(Attack, Attack.event_id == SecurityEvent.id)
            .filter(SecurityEvent.source_ip.in_(frontier_ips))
            .all()
        )
        rows = list(rows) + list(second_hop)

    node_ids = {entity_id}
    edge_map: dict[tuple[str, str], dict] = {}
    for r in rows:
        if not r.destination_ip:
            continue
        node_ids.add(r.source_ip)
        node_ids.add(r.destination_ip)
        key = (r.source_ip, r.destination_ip)
        if key not in edge_map:
            edge_map[key] = {"weight": 0, "attack_types": set()}
        edge_map[key]["weight"] += 1
        edge_map[key]["attack_types"].add(r.attack_category)

    out_degree = {n: 0 for n in node_ids}
    for (src, _), data in edge_map.items():
        out_degree[src] = out_degree.get(src, 0) + 1

    nodes = [GraphNode(id=n, node_type="ip", out_degree=out_degree.get(n, 0)) for n in node_ids]
    edges = [
        GraphEdge(source=s, target=t, weight=d["weight"], attack_types=sorted(d["attack_types"]))
        for (s, t), d in edge_map.items()
    ]

    return GraphResponse(entity=entity_id, nodes=nodes, edges=edges)
