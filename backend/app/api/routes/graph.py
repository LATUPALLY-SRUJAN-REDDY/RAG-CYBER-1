"""Graph visualization and neighborhood explorer router."""

from __future__ import annotations

import logging
from typing import Any
from fastapi import APIRouter

from app.core.config import get_settings
from app.db.neo4j_manager import get_neo4j_manager
from app.models.schemas import GraphNeighborhood
from app.services.retrieval.local_kb import LocalKnowledgeBase

logger = logging.getLogger("graphcyrag.api.graph")
router = APIRouter(prefix="/graph", tags=["Graph"])


@router.get("/neighborhood/{node_id}", response_model=GraphNeighborhood)
def get_neighborhood(node_id: str, limit: int = 25) -> GraphNeighborhood:
    """Fetch 1-hop neighborhood of a given node for interactive graph rendering."""
    mgr = get_neo4j_manager()
    cleaned_id = node_id.strip()

    if mgr.is_connected:
        try:
            cypher = """
            MATCH (n {id: $id})
            OPTIONAL MATCH (n)-[r]-(m)
            RETURN properties(n) AS center, labels(n) AS center_labels,
                   collect(DISTINCT {
                       target: properties(m),
                       labels: labels(m),
                       rel_type: type(r),
                       start_id: startNode(r).id,
                       end_id: endNode(r).id
                   })[0..$limit] AS connections
            """
            rows = mgr.run_read(cypher, {"id": cleaned_id, "limit": limit})
            if rows and rows[0].get("center"):
                row = rows[0]
                center_props = row["center"]
                center_props["label"] = row["center_labels"][0] if row.get("center_labels") else "Unknown"

                nodes = [center_props]
                edges = []
                seen_nodes = {cleaned_id}

                for conn in row.get("connections", []):
                    t = conn.get("target")
                    if not t or not t.get("id"):
                        continue
                    tid = t["id"]
                    if tid not in seen_nodes:
                        seen_nodes.add(tid)
                        t["label"] = conn["labels"][0] if conn.get("labels") else "Unknown"
                        nodes.append(t)
                    edges.append({
                        "source": conn.get("start_id"),
                        "target": conn.get("end_id"),
                        "type": conn.get("rel_type"),
                    })

                return GraphNeighborhood(
                    center_node=center_props,
                    nodes=nodes,
                    edges=edges,
                )
        except Exception as e:
            logger.warning("Neo4j neighborhood query failed: %s", e)

    # Fast local KB fallback
    kb = LocalKnowledgeBase.get_instance()
    primary = kb.get_entity(cleaned_id)
    if not primary:
        primary = {"id": cleaned_id, "name": cleaned_id, "entity_type": "CVE", "description": "Entity"}

    center_node = dict(primary)
    nodes = [center_node]
    edges = []
    seen = {cleaned_id.upper()}

    neighbors = kb.get_neighbors(cleaned_id, limit=limit)
    for n in neighbors:
        nid = n.get("id", "").upper()
        if nid and nid not in seen:
            seen.add(nid)
            nodes.append(n)
            edges.append({
                "source": cleaned_id,
                "target": n.get("id"),
                "type": n.get("relationship_type", "RELATED_TO"),
            })

    return GraphNeighborhood(center_node=center_node, nodes=nodes, edges=edges)


@router.get("/sample")
def get_sample_subgraph(limit: int = 40) -> dict[str, Any]:
    """Return a representative sample subgraph for the visual canvas."""
    mgr = get_neo4j_manager()
    if mgr.is_connected:
        try:
            cypher = """
            MATCH (n)-[r]->(m)
            RETURN properties(n) AS source, labels(n)[0] AS s_label,
                   type(r) AS rel,
                   properties(m) AS target, labels(m)[0] AS t_label
            LIMIT $limit
            """
            rows = mgr.run_read(cypher, {"limit": limit})
            nodes_dict = {}
            edges = []
            for r in rows:
                s = r["source"]
                t = r["target"]
                sid = s.get("id")
                tid = t.get("id")
                if sid and tid:
                    s["label"] = r["s_label"]
                    t["label"] = r["t_label"]
                    nodes_dict[sid] = s
                    nodes_dict[tid] = t
                    edges.append({"source": sid, "target": tid, "type": r["rel"]})
            if nodes_dict:
                return {"nodes": list(nodes_dict.values()), "edges": edges}
        except Exception as e:
            logger.warning("Neo4j sample subgraph query failed: %s", e)

    # High-speed local KB sample
    kb = LocalKnowledgeBase.get_instance()
    nodes_dict = {}
    edges = []

    # Pick sample interesting nodes across CVE, CWE, CAPEC, ATTACK
    sample_seed_ids = ["CWE-79", "CWE-89", "CWE-120", "CAPEC-66", "CAPEC-100", "T1190", "T1059"]

    for sid in sample_seed_ids:
        ent = kb.get_entity(sid)
        if ent:
            nodes_dict[ent["id"]] = ent

        neighbors = kb.get_neighbors(sid, limit=4)
        for n in neighbors:
            nid = n.get("id")
            if nid:
                nodes_dict[nid] = n
                edges.append({
                    "source": sid,
                    "target": nid,
                    "type": n.get("relationship_type", "RELATED_TO"),
                })

        if len(edges) >= limit:
            break

    if nodes_dict:
        return {"nodes": list(nodes_dict.values()), "edges": edges}

    # Core Fallback Schema Graph
    return {
        "nodes": [
            {"id": "CVE-2026-1042", "name": "Memory Corruption", "entity_type": "CVE", "description": "Critical vulnerability."},
            {"id": "CWE-120", "name": "Buffer Overflow", "entity_type": "CWE", "description": "Classic buffer overflow weakness."},
            {"id": "CAPEC-100", "name": "Overflow Buffers", "entity_type": "CAPEC", "description": "Memory buffer exploitation pattern."},
            {"id": "T1190", "name": "Exploit Public-Facing App", "entity_type": "ATTACK", "description": "Adversary initial access technique."},
        ],
        "edges": [
            {"source": "CVE-2026-1042", "target": "CWE-120", "type": "CVE_CWE"},
            {"source": "CWE-120", "target": "CAPEC-100", "type": "CWE_CAPEC"},
            {"source": "CAPEC-100", "target": "T1190", "type": "CAPEC_ATTACK"},
        ]
    }
