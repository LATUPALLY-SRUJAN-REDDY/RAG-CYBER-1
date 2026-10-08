"""In-memory local knowledge base index for standalone and fallback retrieval."""

from __future__ import annotations

import gzip
import json
import logging
import re
from pathlib import Path
from typing import Any
from collections import defaultdict

from app.core.config import get_settings

logger = logging.getLogger("graphcyrag.local_kb")


class LocalKnowledgeBase:
    """Fast indexed in-memory store for 64k+ entities and 70k+ relationships."""

    _instance: LocalKnowledgeBase | None = None

    def __init__(self) -> None:
        self.entities_by_id: dict[str, dict[str, Any]] = {}
        self.outgoing_rels: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.incoming_rels: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.word_index: dict[str, set[str]] = defaultdict(set)
        self.loaded = False

    @classmethod
    def get_instance(cls) -> LocalKnowledgeBase:
        if cls._instance is None:
            cls._instance = LocalKnowledgeBase()
            cls._instance.load()
        return cls._instance

    def load(self, force: bool = False) -> bool:
        if self.loaded and not force:
            return True

        settings = get_settings()
        processed_dir = Path(settings.data_processed_dir).resolve()
        entities_path = processed_dir / "entities.json"
        entities_gz_path = processed_dir / "entities.json.gz"
        rels_path = processed_dir / "relationships.json"
        rels_gz_path = processed_dir / "relationships.json.gz"

        # Support reading directly from .gz if plain .json is absent
        if not entities_path.exists() and not entities_gz_path.exists():
            logger.warning("Local KB: entities.json not found at %s", entities_path)
            return False

        if not entities_path.exists() and entities_gz_path.exists():
            logger.info("Loading local entities from compressed %s...", entities_gz_path)
        else:
            logger.info("Loading local entities from %s...", entities_path)

        try:
            if entities_path.exists():
                entities = json.loads(entities_path.read_text(encoding="utf-8"))
            else:
                with gzip.open(entities_gz_path, "rt", encoding="utf-8") as f:
                    entities = json.load(f)
            self.entities_by_id.clear()
            self.word_index.clear()

            for e in entities:
                eid = str(e.get("id", "")).strip().upper()
                if not eid:
                    continue
                self.entities_by_id[eid] = e

                # Index words in id, name, and description for keyword search
                text = f"{eid} {e.get('name', '')} {e.get('description', '')[:500]}"
                tokens = re.findall(r"\b[a-zA-Z0-9_\-]{3,}\b", text.lower())
                for t in set(tokens):
                    self.word_index[t].add(eid)

            logger.info("Loaded %d entities into local KB index", len(self.entities_by_id))
        except Exception as ex:
            logger.error("Failed to load entities.json: %s", ex)
            return False

        use_gz_rels = not rels_path.exists() and rels_gz_path.exists()
        if rels_path.exists() or use_gz_rels:
            src = rels_gz_path if use_gz_rels else rels_path
            logger.info("Loading local relationships from %s...", src)
            try:
                if use_gz_rels:
                    with gzip.open(rels_gz_path, "rt", encoding="utf-8") as f:
                        rels = json.load(f)
                else:
                    rels = json.loads(rels_path.read_text(encoding="utf-8"))
                self.outgoing_rels.clear()
                self.incoming_rels.clear()

                for r in rels:
                    sid = str(r.get("source_id", "")).strip().upper()
                    tid = str(r.get("target_id", "")).strip().upper()
                    if sid and tid:
                        self.outgoing_rels[sid].append(r)
                        self.incoming_rels[tid].append(r)

                logger.info("Loaded %d relationships into local KB index", len(rels))
            except Exception as ex:
                logger.error("Failed to load relationships.json: %s", ex)

        self.loaded = True
        return True

    def get_entity(self, entity_id: str) -> dict[str, Any] | None:
        if not self.loaded:
            self.load()
        return self.entities_by_id.get(entity_id.strip().upper())

    def get_neighbors(self, entity_id: str, limit: int = 20) -> list[dict[str, Any]]:
        if not self.loaded:
            self.load()
        eid = entity_id.strip().upper()
        results: list[dict[str, Any]] = []
        seen = {eid}

        # Outgoing connections
        for r in self.outgoing_rels.get(eid, []):
            tid = r.get("target_id", "").upper()
            if tid and tid not in seen and tid in self.entities_by_id:
                seen.add(tid)
                neighbor = dict(self.entities_by_id[tid])
                neighbor["relationship_type"] = r.get("relationship_type", "")
                neighbor["relevance_score"] = 0.88
                neighbor["retrieval_method"] = "local_graph_neighbor"
                results.append(neighbor)
                if len(results) >= limit:
                    break

        # Incoming connections
        if len(results) < limit:
            for r in self.incoming_rels.get(eid, []):
                sid = r.get("source_id", "").upper()
                if sid and sid not in seen and sid in self.entities_by_id:
                    seen.add(sid)
                    neighbor = dict(self.entities_by_id[sid])
                    neighbor["relationship_type"] = r.get("relationship_type", "")
                    neighbor["relevance_score"] = 0.82
                    neighbor["retrieval_method"] = "local_graph_neighbor"
                    results.append(neighbor)
                    if len(results) >= limit:
                        break

        return results

    def search_entities(self, query: str, top_k: int = 10) -> list[dict[str, Any]]:
        if not self.loaded:
            self.load()

        q_clean = query.strip()
        tokens = re.findall(r"\b[a-zA-Z0-9_\-]{3,}\b", q_clean.lower())
        if not tokens:
            return []

        # Count score by token hits
        scores: dict[str, float] = defaultdict(float)
        for t in tokens:
            matching_ids = self.word_index.get(t, set())
            for mid in matching_ids:
                scores[mid] += 1.0
                # Exact ID match gets heavy boost
                if mid.lower() == t:
                    scores[mid] += 10.0

        if not scores:
            return []

        ranked_ids = sorted(scores.keys(), key=lambda x: scores[x], reverse=True)[:top_k]
        max_score = scores[ranked_ids[0]] if ranked_ids else 1.0

        results = []
        for rid in ranked_ids:
            ent = dict(self.entities_by_id[rid])
            ent["relevance_score"] = round(scores[rid] / max_score, 3)
            ent["retrieval_method"] = "local_keyword"
            results.append(ent)

        return results
