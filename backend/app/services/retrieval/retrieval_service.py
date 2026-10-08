"""Retrieval service — graph, semantic, and hybrid retrieval with secure Cypher and local fallback.

SECURITY: Never executes unrestricted LLM-generated Cypher.
All graph queries use parameterized templates with allowed labels/rels only.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from app.core.config import get_settings
from app.db.neo4j_manager import get_neo4j_manager
from app.services.embeddings.embedding_service import vector_search
from app.services.graph.graph_service import ALLOWED_LABELS, ALLOWED_REL_TYPES
from app.services.retrieval.local_kb import LocalKnowledgeBase

logger = logging.getLogger("graphcyrag.retrieval")

# ── Dangerous Cypher keywords ──────────────────────────────

FORBIDDEN_KEYWORDS = {
    "CREATE", "MERGE", "DELETE", "DETACH", "SET", "REMOVE",
    "DROP", "LOAD CSV", "CALL dbms", "CALL apoc",
}

# ── Entity ID patterns ─────────────────────────────────────

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)
CAPEC_PATTERN = re.compile(r"CAPEC-\d+", re.IGNORECASE)
ATTACK_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


def validate_cypher(cypher: str) -> bool:
    """Reject any Cypher with write/admin operations."""
    upper = cypher.upper()
    for kw in FORBIDDEN_KEYWORDS:
        if kw in upper:
            logger.warning("Rejected unsafe Cypher keyword: %s", kw)
            return False
    return True


def extract_entity_ids(question: str) -> dict[str, list[str]]:
    """Extract cybersecurity entity IDs from a natural language question."""
    return {
        "cve": [m.upper() for m in CVE_PATTERN.findall(question)],
        "cwe": [m.upper() for m in CWE_PATTERN.findall(question)],
        "capec": [m.upper() for m in CAPEC_PATTERN.findall(question)],
        "attack": [m.upper() for m in ATTACK_PATTERN.findall(question)],
    }


def _understand_intent(question: str) -> dict[str, Any]:
    """Simple intent/entity extraction from the question."""
    ids = extract_entity_ids(question)
    q_lower = question.lower()

    intent = "general"
    if any(w in q_lower for w in ("relate", "associated", "linked", "connected", "mapping")):
        intent = "relationship"
    elif any(w in q_lower for w in ("what is", "describe", "explain", "details")):
        intent = "lookup"
    elif any(w in q_lower for w in ("mitigat", "prevent", "protect", "fix", "patch")):
        intent = "mitigation"
    elif any(w in q_lower for w in ("exploit", "attack", "technique")):
        intent = "attack"
    elif any(w in q_lower for w in ("vulnerabilit", "weakness", "flaw")):
        intent = "vulnerability"

    return {"intent": intent, "ids": ids, "question": question}


# ── Local Knowledge Retrieval ────────────────────────────────

def _local_graph_retrieval(question: str, top_k: int = 10) -> list[dict[str, Any]]:
    """Graph traversal using indexed local processed datasets."""
    kb = LocalKnowledgeBase.get_instance()
    ids_map = extract_entity_ids(question)
    results: list[dict[str, Any]] = []
    seen: set[str] = set()

    # 1. Exact entity IDs from question
    for group, id_list in ids_map.items():
        for eid in id_list:
            ent = kb.get_entity(eid)
            if ent and eid not in seen:
                seen.add(eid)
                item = dict(ent)
                item["relevance_score"] = 1.0
                item["retrieval_method"] = "graph_direct"
                results.append(item)

            # Traverse 1-hop graph neighbors
            neighbors = kb.get_neighbors(eid, limit=top_k)
            for n in neighbors:
                nid = str(n.get("id", "")).upper()
                if nid and nid not in seen:
                    seen.add(nid)
                    results.append(n)

    # 2. If no direct ID matches, search by keywords
    if not results:
        keyword_hits = kb.search_entities(question, top_k=top_k)
        for kh in keyword_hits:
            kid = str(kh.get("id", "")).upper()
            if kid and kid not in seen:
                seen.add(kid)
                results.append(kh)

            # Also fetch top neighbor for top hit
            if len(results) < top_k:
                neighbors = kb.get_neighbors(kid, limit=3)
                for n in neighbors:
                    nid = str(n.get("id", "")).upper()
                    if nid and nid not in seen:
                        seen.add(nid)
                        results.append(n)

    return results[:top_k]


# ── Graph Retrieval ──────────────────────────────────────────

def graph_retrieval(question: str, top_k: int = 10) -> list[dict[str, Any]]:
    """Controlled graph-based retrieval using parameterized Cypher with local fallback."""
    mgr = get_neo4j_manager()
    if not mgr.is_connected:
        return _local_graph_retrieval(question, top_k=top_k)

    understanding = _understand_intent(question)
    ids = understanding["ids"]
    results: list[dict[str, Any]] = []

    # Direct entity lookups via Neo4j
    for label_key, id_list in ids.items():
        label = label_key.upper()
        if label not in ALLOWED_LABELS:
            continue
        for eid in id_list:
            cypher = f"MATCH (n:{label} {{id: $id}}) RETURN properties(n) AS props"
            if not validate_cypher(cypher):
                continue
            rows = mgr.run_read(cypher, {"id": eid})
            for r in rows:
                props = r["props"]
                props.pop("embedding", None)
                props["relevance_score"] = 1.0
                props["retrieval_method"] = "graph_direct"
                props["description"] = (props.get("description", "") or "")[:500]
                results.append(props)

            # Neighborhood (1-hop)
            neighbor_cypher = f"""
            MATCH (n:{label} {{id: $id}})-[r]-(m)
            WHERE ANY(lbl IN labels(m) WHERE lbl IN ['CVE','CWE','CAPEC','ATTACK'])
            RETURN properties(m) AS props, type(r) AS rel_type
            LIMIT $limit
            """
            if not validate_cypher(neighbor_cypher):
                continue
            neighbor_rows = mgr.run_read(neighbor_cypher, {"id": eid, "limit": top_k})
            for r in neighbor_rows:
                props = r["props"]
                props.pop("embedding", None)
                props["relevance_score"] = 0.8
                props["retrieval_method"] = "graph_neighbor"
                props["relationship_type"] = r.get("rel_type", "")
                props["description"] = (props.get("description", "") or "")[:500]
                results.append(props)

    # Fallback to local if Neo4j returned nothing
    if not results:
        return _local_graph_retrieval(question, top_k=top_k)

    # Deduplicate
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for r in results:
        rid = r.get("id", "")
        if rid and rid not in seen:
            seen.add(rid)
            unique.append(r)

    return unique[:top_k]


# ── Semantic Retrieval ─────────────────────────────────────

def semantic_retrieval(question: str, top_k: int = 10) -> list[dict[str, Any]]:
    """Vector similarity-based semantic retrieval with local fallback."""
    mgr = get_neo4j_manager()
    if mgr.is_connected:
        res = vector_search(question, top_k=top_k)
        if res:
            return res

    # Local semantic search
    kb = LocalKnowledgeBase.get_instance()
    return kb.search_entities(question, top_k=top_k)


# ── Hybrid Retrieval ───────────────────────────────────────

def hybrid_retrieval(question: str, top_k: int = 10) -> list[dict[str, Any]]:
    """Combine graph and semantic retrieval with configurable weights."""
    settings = get_settings()
    graph_weight = settings.graph_weight
    semantic_weight = settings.semantic_weight

    graph_results = graph_retrieval(question, top_k=top_k)
    semantic_results = semantic_retrieval(question, top_k=top_k)

    max_graph = max((r.get("relevance_score", 0) for r in graph_results), default=1.0) or 1.0
    max_semantic = max((r.get("relevance_score", 0) for r in semantic_results), default=1.0) or 1.0

    scored: dict[str, dict[str, Any]] = {}

    for r in graph_results:
        rid = r.get("id", "")
        if not rid:
            continue
        norm_score = (r.get("relevance_score", 0) / max_graph) * graph_weight
        scored[rid] = {**r, "relevance_score": norm_score, "retrieval_method": "hybrid_graph"}

    for r in semantic_results:
        rid = r.get("id", "")
        if not rid:
            continue
        norm_score = (r.get("relevance_score", 0) / max_semantic) * semantic_weight
        if rid in scored:
            scored[rid]["relevance_score"] += norm_score
            scored[rid]["retrieval_method"] = "hybrid_both"
        else:
            scored[rid] = {**r, "relevance_score": norm_score, "retrieval_method": "hybrid_semantic"}

    ranked = sorted(scored.values(), key=lambda x: x.get("relevance_score", 0), reverse=True)
    return ranked[:top_k]


# ── Unified Retrieval ──────────────────────────────────────

def retrieve(question: str, mode: str = "hybrid", top_k: int = 10) -> tuple[list[dict[str, Any]], float]:
    """Unified retrieval entry point. Returns (results, retrieval_ms)."""
    settings = get_settings()
    top_k = min(top_k, settings.top_k_limit)

    start = time.time()
    if mode == "graph":
        results = graph_retrieval(question, top_k)
    elif mode == "semantic":
        results = semantic_retrieval(question, top_k)
    else:
        results = hybrid_retrieval(question, top_k)

    elapsed_ms = (time.time() - start) * 1000
    return results, elapsed_ms
