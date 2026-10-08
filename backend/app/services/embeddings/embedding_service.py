"""Embedding service — generates and manages vector embeddings for entities."""

from __future__ import annotations

import logging
from typing import Any

import numpy as np

from app.core.config import get_settings
from app.db.neo4j_manager import get_neo4j_manager

logger = logging.getLogger("graphcyrag.embeddings")

_model = None
_dimension: int | None = None


def get_embedding_model():
    """Lazy-load the sentence transformer model."""
    global _model, _dimension
    if _model is not None:
        return _model

    settings = get_settings()
    model_name = settings.embedding_model
    try:
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer(model_name)
        # Determine dimension programmatically
        test_emb = _model.encode(["test"], show_progress_bar=False)
        _dimension = test_emb.shape[1]
        logger.info("Loaded embedding model '%s' with dimension %d", model_name, _dimension)
        return _model
    except Exception as e:
        logger.error("Failed to load embedding model '%s': %s", model_name, e)
        return None


def get_embedding_dimension() -> int:
    """Return the embedding dimension, loading the model if needed."""
    global _dimension
    if _dimension is not None:
        return _dimension
    model = get_embedding_model()
    if model is None:
        return 384  # sensible default for all-MiniLM-L6-v2
    return _dimension or 384


def generate_embeddings(texts: list[str], batch_size: int = 64) -> np.ndarray | None:
    """Generate embeddings for a list of texts."""
    model = get_embedding_model()
    if model is None:
        return None
    try:
        embeddings = model.encode(texts, batch_size=batch_size, show_progress_bar=True, normalize_embeddings=True)
        return np.array(embeddings)
    except Exception as e:
        logger.error("Embedding generation failed: %s", e)
        return None


def embed_single(text: str) -> list[float] | None:
    """Generate embedding for a single text string."""
    model = get_embedding_model()
    if model is None:
        return None
    try:
        emb = model.encode([text], show_progress_bar=False, normalize_embeddings=True)
        return emb[0].tolist()
    except Exception as e:
        logger.error("Single embedding failed: %s", e)
        return None


def build_embedding_text(entity: dict[str, Any]) -> str:
    """Build meaningful embedding text from entity fields."""
    etype = entity.get("entity_type", "")
    eid = entity.get("id", "")
    name = entity.get("name", "")
    desc = (entity.get("description", "") or "")[:2000]

    parts = [f"[{etype}] {eid}", name, desc]

    extra = entity.get("extra", {})
    if extra.get("severity"):
        parts.append(f"Severity: {extra['severity']}")
    if extra.get("abstraction"):
        parts.append(f"Abstraction: {extra['abstraction']}")
    if extra.get("platforms"):
        plist = extra["platforms"]
        if isinstance(plist, list):
            parts.append(f"Platforms: {', '.join(plist[:10])}")
    if extra.get("tactics"):
        tlist = extra["tactics"]
        if isinstance(tlist, list):
            parts.append(f"Tactics: {', '.join(tlist[:10])}")

    return " | ".join(p for p in parts if p)


def store_embeddings_in_neo4j(entities: list[dict[str, Any]], batch_size: int = 100) -> int:
    """Generate embeddings for entities and store them in Neo4j."""
    mgr = get_neo4j_manager()
    if not mgr.is_connected:
        logger.warning("Neo4j not connected – cannot store embeddings")
        return 0

    model = get_embedding_model()
    if model is None:
        logger.warning("Embedding model not available – cannot generate embeddings")
        return 0

    label_map = {"CVE": "CVE", "CWE": "CWE", "CAPEC": "CAPEC", "ATTACK": "ATTACK"}
    total = 0

    for i in range(0, len(entities), batch_size):
        batch = entities[i : i + batch_size]
        texts = [build_embedding_text(e) for e in batch]
        embeddings = generate_embeddings(texts, batch_size=batch_size)
        if embeddings is None:
            continue

        for j, entity in enumerate(batch):
            etype = entity.get("entity_type", "")
            label = label_map.get(etype)
            if not label:
                continue

            embedding_list = embeddings[j].tolist()
            eid = entity["id"]

            cypher = (
                f"MATCH (n:{label} {{id: $id}}) "
                f"SET n.embedding = $embedding, "
                f"n.embedding_model = $model, "
                f"n.embedding_dim = $dim"
            )
            try:
                mgr.run_write(cypher, {
                    "id": eid,
                    "embedding": embedding_list,
                    "model": get_settings().embedding_model,
                    "dim": len(embedding_list),
                })
                total += 1
            except Exception as e:
                logger.debug("Failed to store embedding for %s: %s", eid, e)

    logger.info("Stored %d embeddings in Neo4j", total)
    return total


def vector_search(query_text: str, top_k: int = 10, entity_type: str | None = None) -> list[dict[str, Any]]:
    """Perform vector similarity search in Neo4j."""
    mgr = get_neo4j_manager()
    if not mgr.is_connected:
        return []

    query_embedding = embed_single(query_text)
    if query_embedding is None:
        return []

    settings = get_settings()
    results: list[dict[str, Any]] = []

    # Try each label's vector index
    labels_to_search = [entity_type] if entity_type and entity_type in ("CVE", "CWE", "CAPEC", "ATTACK") else ["CVE", "CWE", "CAPEC", "ATTACK"]

    for label in labels_to_search:
        idx_name = f"{settings.vector_index_name}_{label.lower()}"
        cypher = f"""
        CALL db.index.vector.queryNodes('{idx_name}', $top_k, $embedding)
        YIELD node, score
        RETURN properties(node) AS props, score
        """
        try:
            rows = mgr.run_read(cypher, {"top_k": top_k, "embedding": query_embedding})
            for r in rows:
                props = r["props"]
                props.pop("embedding", None)
                props["relevance_score"] = r["score"]
                props["retrieval_method"] = "semantic"
                props["description"] = (props.get("description", "") or "")[:500]
                results.append(props)
        except Exception:
            # Try combined index name
            try:
                cypher2 = f"""
                CALL db.index.vector.queryNodes('{settings.vector_index_name}', $top_k, $embedding)
                YIELD node, score
                RETURN properties(node) AS props, score
                """
                rows = mgr.run_read(cypher2, {"top_k": top_k, "embedding": query_embedding})
                for r in rows:
                    props = r["props"]
                    props.pop("embedding", None)
                    props["relevance_score"] = r["score"]
                    props["retrieval_method"] = "semantic"
                    props["description"] = (props.get("description", "") or "")[:500]
                    results.append(props)
                break  # Combined index worked
            except Exception:
                continue

    # Sort by score and deduplicate
    seen: set[str] = set()
    unique_results: list[dict[str, Any]] = []
    for r in sorted(results, key=lambda x: x.get("relevance_score", 0), reverse=True):
        rid = r.get("id", "")
        if rid not in seen:
            seen.add(rid)
            unique_results.append(r)

    return unique_results[:top_k]
