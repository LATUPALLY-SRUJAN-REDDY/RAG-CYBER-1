"""High-performance SQLite-backed local knowledge base for zero-memory, instant retrieval."""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import gzip
from pathlib import Path
from typing import Any
from collections import defaultdict

from app.core.config import get_settings

logger = logging.getLogger("graphcyrag.local_kb")


class LocalKnowledgeBase:
    """Zero-memory SQLite-backed knowledge base index for 64k+ entities and 70k+ relationships."""

    _instance: LocalKnowledgeBase | None = None

    def __init__(self) -> None:
        self.db_path: Path | None = None
        self.loaded = False

    @classmethod
    def get_instance(cls) -> LocalKnowledgeBase:
        if cls._instance is None:
            cls._instance = LocalKnowledgeBase()
            cls._instance.load()
        return cls._instance

    def _get_connection(self) -> sqlite3.Connection:
        if not self.db_path or not self.db_path.exists():
            self.load()
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def load(self, force: bool = False) -> bool:
        if self.loaded and not force:
            return True

        settings = get_settings()
        processed_dir = settings.resolve_data_path(settings.data_processed_dir)
        db_file = processed_dir / "cyber_kb.db"

        if db_file.exists() and db_file.stat().st_size > 100000:
            self.db_path = db_file
            self.loaded = True
            logger.info("Local KB: Connected to SQLite database at %s (size: %.1f MB)", db_file, db_file.stat().st_size / (1024 * 1024))
            return True

        # Build SQLite database if it doesn't exist
        entities_gz = processed_dir / "entities.json.gz"
        entities_json = processed_dir / "entities.json"
        rels_gz = processed_dir / "relationships.json.gz"
        rels_json = processed_dir / "relationships.json"

        if not entities_gz.exists() and not entities_json.exists():
            logger.warning("Local KB: entities file not found in %s", processed_dir)
            return False

        logger.info("Local KB: Initializing lightweight SQLite database at %s...", db_file)
        try:
            conn = sqlite3.connect(str(db_file))
            c = conn.cursor()
            c.execute("""
            CREATE TABLE IF NOT EXISTS entities (
                id TEXT PRIMARY KEY,
                entity_type TEXT,
                name TEXT,
                description TEXT,
                source TEXT,
                likelihood TEXT,
                consequences TEXT,
                mitigations TEXT
            )""")
            c.execute("""
            CREATE TABLE IF NOT EXISTS relationships (
                source_id TEXT,
                target_id TEXT,
                relationship_type TEXT
            )""")
            c.execute("""
            CREATE TABLE IF NOT EXISTS word_index (
                word TEXT,
                entity_id TEXT
            )""")

            if entities_gz.exists():
                with gzip.open(entities_gz, "rt", encoding="utf-8") as f:
                    entities = json.load(f)
            else:
                entities = json.loads(entities_json.read_text(encoding="utf-8"))

            entity_rows = []
            word_rows = []
            for e in entities:
                eid = str(e.get("id", "")).strip().upper()
                if not eid:
                    continue
                etype = str(e.get("entity_type", ""))
                name = str(e.get("name", "") or "")[:150]
                desc = str(e.get("description", "") or "")[:600]
                source = str(e.get("source", ""))
                likelihood = str(e.get("likelihood_of_exploit") or e.get("likelihood_of_attack") or "")
                consequences = e.get("common_consequences")
                con_str = json.dumps(consequences[:3]) if isinstance(consequences, list) else "[]"
                mitigations = e.get("mitigations")
                mit_str = json.dumps(mitigations[:3]) if isinstance(mitigations, list) else "[]"

                entity_rows.append((eid, etype, name, desc, source, likelihood, con_str, mit_str))
                tokens = set(re.findall(r"\b[a-zA-Z0-9_\-]{3,}\b", f"{eid} {name} {desc[:100]}".lower()))
                for t in tokens:
                    word_rows.append((t, eid))

            c.executemany("INSERT OR REPLACE INTO entities VALUES (?, ?, ?, ?, ?, ?, ?, ?)", entity_rows)
            c.executemany("INSERT INTO word_index VALUES (?, ?)", word_rows)
            del entities, entity_rows, word_rows

            if rels_gz.exists():
                with gzip.open(rels_gz, "rt", encoding="utf-8") as f:
                    rels = json.load(f)
            elif rels_json.exists():
                rels = json.loads(rels_json.read_text(encoding="utf-8"))
            else:
                rels = []

            rel_rows = []
            for r in rels:
                sid = str(r.get("source_id", "")).strip().upper()
                tid = str(r.get("target_id", "")).strip().upper()
                if sid and tid:
                    rel_rows.append((sid, tid, str(r.get("relationship_type", ""))))

            c.executemany("INSERT INTO relationships VALUES (?, ?, ?)", rel_rows)
            del rels, rel_rows

            c.execute("CREATE INDEX IF NOT EXISTS idx_word ON word_index(word)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_rel_src ON relationships(source_id)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_rel_tgt ON relationships(target_id)")
            conn.commit()
            conn.close()

            self.db_path = db_file
            self.loaded = True
            logger.info("Local KB: Successfully generated and indexed SQLite DB.")
            return True
        except Exception as ex:
            logger.error("Failed to build local SQLite DB: %s", ex)
            return False

    def get_entity(self, entity_id: str) -> dict[str, Any] | None:
        eid = entity_id.strip().upper()
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM entities WHERE id = ?", (eid,))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_dict(row)
        finally:
            conn.close()

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        try:
            d["common_consequences"] = json.loads(d.get("consequences") or "[]")
        except Exception:
            d["common_consequences"] = []
        try:
            d["mitigations"] = json.loads(d.get("mitigations") or "[]")
        except Exception:
            d["mitigations"] = []
        return d

    def get_neighbors(self, entity_id: str, limit: int = 20) -> list[dict[str, Any]]:
        eid = entity_id.strip().upper()
        conn = self._get_connection()
        results: list[dict[str, Any]] = []
        seen = {eid}
        try:
            cur = conn.cursor()
            # Outgoing
            cur.execute("""
            SELECT e.*, r.relationship_type 
            FROM relationships r
            JOIN entities e ON r.target_id = e.id
            WHERE r.source_id = ?
            LIMIT ?
            """, (eid, limit))
            for row in cur.fetchall():
                d = self._row_to_dict(row)
                rid = d["id"]
                if rid not in seen:
                    seen.add(rid)
                    d["relevance_score"] = 0.88
                    d["retrieval_method"] = "local_graph_neighbor"
                    results.append(d)

            # Incoming if needed
            if len(results) < limit:
                cur.execute("""
                SELECT e.*, r.relationship_type 
                FROM relationships r
                JOIN entities e ON r.source_id = e.id
                WHERE r.target_id = ?
                LIMIT ?
                """, (eid, limit - len(results)))
                for row in cur.fetchall():
                    d = self._row_to_dict(row)
                    rid = d["id"]
                    if rid not in seen:
                        seen.add(rid)
                        d["relevance_score"] = 0.82
                        d["retrieval_method"] = "local_graph_neighbor"
                        results.append(d)

            return results
        finally:
            conn.close()

    def search_entities(self, query: str, top_k: int = 10) -> list[dict[str, Any]]:
        q_clean = query.strip()
        tokens = re.findall(r"\b[a-zA-Z0-9_\-]{3,}\b", q_clean.lower())
        if not tokens:
            return []

        conn = self._get_connection()
        try:
            cur = conn.cursor()
            # Find matching entity IDs from index
            placeholders = ",".join("?" for _ in tokens)
            cur.execute(f"""
            SELECT entity_id, COUNT(*) as hits
            FROM word_index
            WHERE word IN ({placeholders})
            GROUP BY entity_id
            ORDER BY hits DESC
            LIMIT ?
            """, (*tokens, top_k * 2))

            ranked = cur.fetchall()
            if not ranked:
                return []

            results = []
            max_hits = ranked[0]["hits"] if ranked else 1
            for r in ranked[:top_k]:
                eid = r["entity_id"]
                cur.execute("SELECT * FROM entities WHERE id = ?", (eid,))
                row = cur.fetchone()
                if row:
                    d = self._row_to_dict(row)
                    d["relevance_score"] = round(r["hits"] / max_hits, 3)
                    d["retrieval_method"] = "local_keyword"
                    results.append(d)

            return results
        finally:
            conn.close()
