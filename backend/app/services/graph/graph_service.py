"""Graph service — populates Neo4j from processed entities and relationships."""

from __future__ import annotations

import logging
from typing import Any

from app.db.neo4j_manager import get_neo4j_manager

logger = logging.getLogger("graphcyrag.graph")

# ── Allowed labels and relationship types ───────────────────

ALLOWED_LABELS = {"CVE", "CWE", "CAPEC", "ATTACK"}
ALLOWED_REL_TYPES = {"CVE_CWE", "CWE_CHILD", "CWE_CAPEC", "CAPEC_CHILD", "CAPEC_ATTACK", "SUBTECHNIQUE_OF"}

# Map entity_type → Neo4j label
ENTITY_LABEL_MAP = {
    "CVE": "CVE",
    "CWE": "CWE",
    "CAPEC": "CAPEC",
    "ATTACK": "ATTACK",
}


def ingest_entities(entities: list[dict[str, Any]], batch_size: int = 500) -> int:
    """Ingest parsed entities into Neo4j using MERGE to support incremental updates."""
    mgr = get_neo4j_manager()
    if not mgr.is_connected:
        logger.warning("Neo4j not connected – skipping entity ingestion")
        return 0

    total = 0
    for i in range(0, len(entities), batch_size):
        batch = entities[i : i + batch_size]
        for entity in batch:
            etype = entity.get("entity_type", "")
            label = ENTITY_LABEL_MAP.get(etype)
            if label is None or label not in ALLOWED_LABELS:
                continue

            props = {
                "id": entity["id"],
                "name": entity.get("name", ""),
                "description": (entity.get("description", "") or "")[:5000],
                "source": entity.get("source", ""),
                "source_version": entity.get("source_version", ""),
                "source_url": entity.get("source_url", ""),
                "created": entity.get("created", ""),
                "modified": entity.get("modified", ""),
                "entity_type": etype,
            }
            # Add type-specific extras
            extra = entity.get("extra", {})
            if extra.get("severity"):
                props["severity"] = extra["severity"]
            if extra.get("abstraction"):
                props["abstraction"] = extra["abstraction"]
            if extra.get("tactics"):
                props["tactics"] = extra["tactics"]
            if extra.get("platforms"):
                props["platforms"] = extra["platforms"]

            cypher = f"MERGE (n:{label} {{id: $id}}) SET n += $props"
            try:
                mgr.run_write(cypher, {"id": entity["id"], "props": props})
                total += 1
            except Exception as e:
                logger.warning("Failed to ingest %s: %s", entity["id"], e)

    logger.info("Ingested %d entities into Neo4j", total)
    return total


def ingest_relationships(relationships: list[dict[str, Any]], batch_size: int = 500) -> int:
    """Ingest relationships into Neo4j."""
    mgr = get_neo4j_manager()
    if not mgr.is_connected:
        logger.warning("Neo4j not connected – skipping relationship ingestion")
        return 0

    total = 0
    for i in range(0, len(relationships), batch_size):
        batch = relationships[i : i + batch_size]
        for rel in batch:
            rel_type = rel.get("relationship_type", "")
            if rel_type not in ALLOWED_REL_TYPES:
                continue

            src_id = rel.get("source_id", "")
            tgt_id = rel.get("target_id", "")
            if not src_id or not tgt_id:
                continue

            # Determine labels
            src_label = _infer_label(src_id)
            tgt_label = _infer_label(tgt_id)
            if not src_label or not tgt_label:
                continue

            cypher = (
                f"MATCH (a:{src_label} {{id: $src_id}}) "
                f"MATCH (b:{tgt_label} {{id: $tgt_id}}) "
                f"MERGE (a)-[r:{rel_type}]->(b) "
                f"SET r.source_dataset = $source_dataset, r.provenance = $provenance"
            )
            try:
                mgr.run_write(cypher, {
                    "src_id": src_id,
                    "tgt_id": tgt_id,
                    "source_dataset": rel.get("source_dataset", ""),
                    "provenance": rel.get("provenance", ""),
                })
                total += 1
            except Exception as e:
                logger.debug("Relationship %s→%s failed: %s", src_id, tgt_id, e)

    logger.info("Ingested %d relationships into Neo4j", total)
    return total


def _infer_label(entity_id: str) -> str:
    """Infer Neo4j label from entity ID prefix."""
    eid = entity_id.upper()
    if eid.startswith("CVE-"):
        return "CVE"
    if eid.startswith("CWE-"):
        return "CWE"
    if eid.startswith("CAPEC-"):
        return "CAPEC"
    if eid.startswith("T") and (eid[1:].replace(".", "").isdigit()):
        return "ATTACK"
    return ""


def get_entity(entity_id: str) -> dict[str, Any] | None:
    """Lookup a single entity by ID."""
    mgr = get_neo4j_manager()
    if not mgr.is_connected:
        return None
    label = _infer_label(entity_id)
    if not label:
        return None
    results = mgr.run_read(
        f"MATCH (n:{label} {{id: $id}}) RETURN properties(n) AS props",
        {"id": entity_id},
    )
    return results[0]["props"] if results else None


def get_neighborhood(entity_id: str, depth: int = 1) -> dict[str, Any]:
    """Return the neighborhood of an entity up to a given depth."""
    mgr = get_neo4j_manager()
    if not mgr.is_connected:
        return {"center_node": {}, "nodes": [], "edges": []}

    label = _infer_label(entity_id)
    if not label:
        return {"center_node": {}, "nodes": [], "edges": []}

    from app.core.config import get_settings
    max_depth = min(depth, get_settings().graph_traversal_limit)

    cypher = f"""
    MATCH (center:{label} {{id: $id}})
    OPTIONAL MATCH path = (center)-[*1..{max_depth}]-(neighbor)
    WHERE ANY(lbl IN labels(neighbor) WHERE lbl IN ['CVE','CWE','CAPEC','ATTACK'])
    WITH center, collect(DISTINCT neighbor) AS neighbors,
         collect(DISTINCT relationships(path)) AS all_rels
    RETURN center, neighbors, all_rels
    """
    results = mgr.run_read(cypher, {"id": entity_id})
    if not results:
        return {"center_node": {}, "nodes": [], "edges": []}

    row = results[0]
    center_props = dict(row["center"]) if row.get("center") else {}
    nodes = []
    edges = []
    seen_nodes = {entity_id}

    for n in row.get("neighbors", []) or []:
        if n is None:
            continue
        n_props = dict(n)
        n_id = n_props.get("id", "")
        if n_id and n_id not in seen_nodes:
            seen_nodes.add(n_id)
            nodes.append({
                "id": n_id,
                "label": n_props.get("entity_type", ""),
                "name": n_props.get("name", ""),
                "description": (n_props.get("description", "") or "")[:300],
            })

    for rel_list in row.get("all_rels", []) or []:
        if rel_list is None:
            continue
        for r in rel_list:
            if r is None:
                continue
            edges.append({
                "source": dict(r.start_node).get("id", ""),
                "target": dict(r.end_node).get("id", ""),
                "type": r.type,
            })

    return {
        "center_node": {
            "id": center_props.get("id", entity_id),
            "label": center_props.get("entity_type", ""),
            "name": center_props.get("name", ""),
            "description": (center_props.get("description", "") or "")[:500],
        },
        "nodes": nodes,
        "edges": edges,
    }


def search_entities(query: str, entity_type: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    """Full-text search across entities."""
    mgr = get_neo4j_manager()
    if not mgr.is_connected:
        return []

    cypher = """
    CALL db.index.fulltext.queryNodes('entity_search', $query)
    YIELD node, score
    WHERE score > 0.5
    RETURN properties(node) AS props, score
    ORDER BY score DESC
    LIMIT $limit
    """
    try:
        results = mgr.run_read(cypher, {"query": query, "limit": limit})
        items = []
        for r in results:
            props = r["props"]
            if entity_type and props.get("entity_type") != entity_type:
                continue
            items.append({**props, "score": r["score"], "description": (props.get("description", "") or "")[:500]})
        return items
    except Exception as e:
        logger.warning("Full-text search failed: %s. Falling back to CONTAINS.", e)
        return _fallback_search(query, entity_type, limit)


def _fallback_search(query: str, entity_type: str | None, limit: int) -> list[dict[str, Any]]:
    """Simple CONTAINS-based fallback search."""
    mgr = get_neo4j_manager()
    labels = [entity_type] if entity_type and entity_type in ALLOWED_LABELS else list(ALLOWED_LABELS)
    results: list[dict[str, Any]] = []
    for label in labels:
        cypher = (
            f"MATCH (n:{label}) "
            f"WHERE n.id CONTAINS $q OR toLower(n.name) CONTAINS toLower($q) "
            f"RETURN properties(n) AS props LIMIT $limit"
        )
        rows = mgr.run_read(cypher, {"q": query, "limit": limit})
        for r in rows:
            props = r["props"]
            props["description"] = (props.get("description", "") or "")[:500]
            results.append(props)
    return results[:limit]


def get_graph_stats() -> dict[str, Any]:
    """Get comprehensive graph statistics."""
    mgr = get_neo4j_manager()
    counts = mgr.get_counts()
    rel_types: dict[str, int] = {}
    if mgr.is_connected:
        for rt in ALLOWED_REL_TYPES:
            res = mgr.run_read(f"MATCH ()-[r:{rt}]->() RETURN count(r) AS c")
            rel_types[rt] = res[0]["c"] if res else 0
    return {**counts, "relationship_types": rel_types}
