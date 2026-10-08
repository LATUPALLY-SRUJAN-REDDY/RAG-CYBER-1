"""Neo4j connection manager with health checks and schema management."""

from __future__ import annotations

import logging
from typing import Any

from neo4j import GraphDatabase, Driver, Session
from neo4j.exceptions import ServiceUnavailable, AuthError

from app.core.config import get_settings

logger = logging.getLogger("graphcyrag.db.neo4j")


class Neo4jManager:
    """Manages the Neo4j driver lifecycle, schema creation, and queries."""

    def __init__(self) -> None:
        settings = get_settings()
        self._uri = settings.neo4j_uri
        self._username = settings.neo4j_username
        self._password = settings.neo4j_password
        self._driver: Driver | None = None

    # ── Connection ──────────────────────────────────────────

    def connect(self) -> bool:
        """Attempt to connect to Neo4j. Returns True on success."""
        try:
            self._driver = GraphDatabase.driver(
                self._uri,
                auth=(self._username, self._password),
                max_connection_lifetime=300,
            )
            self._driver.verify_connectivity()
            logger.info("Connected to Neo4j at %s", self._uri)
            return True
        except (ServiceUnavailable, AuthError, Exception) as e:
            logger.warning("Cannot connect to Neo4j at %s: %s", self._uri, e)
            self._driver = None
            return False

    def close(self) -> None:
        if self._driver:
            self._driver.close()
            self._driver = None

    @property
    def is_connected(self) -> bool:
        if self._driver is None:
            return False
        try:
            self._driver.verify_connectivity()
            return True
        except Exception:
            return False

    def get_session(self, **kwargs: Any) -> Session:
        if not self._driver:
            raise RuntimeError("Neo4j driver not connected")
        return self._driver.session(**kwargs)

    # ── Health ──────────────────────────────────────────────

    def health_check(self) -> str:
        """Return 'connected' or 'unavailable'."""
        return "connected" if self.is_connected else "unavailable"

    # ── Schema ──────────────────────────────────────────────

    def create_schema(self) -> None:
        """Create constraints, indexes, and vector index."""
        if not self.is_connected:
            logger.warning("Cannot create schema – Neo4j not connected")
            return

        constraints = [
            "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (n:CVE) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (n:CWE) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT capec_id IF NOT EXISTS FOR (n:CAPEC) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT attack_id IF NOT EXISTS FOR (n:ATTACK) REQUIRE n.id IS UNIQUE",
        ]
        indexes = [
            "CREATE INDEX cve_name IF NOT EXISTS FOR (n:CVE) ON (n.name)",
            "CREATE INDEX cwe_name IF NOT EXISTS FOR (n:CWE) ON (n.name)",
            "CREATE INDEX capec_name IF NOT EXISTS FOR (n:CAPEC) ON (n.name)",
            "CREATE INDEX attack_name IF NOT EXISTS FOR (n:ATTACK) ON (n.name)",
            "CREATE FULLTEXT INDEX entity_search IF NOT EXISTS FOR (n:CVE|CWE|CAPEC|ATTACK) ON EACH [n.id, n.name, n.description]",
        ]

        with self.get_session() as session:
            for cypher in constraints + indexes:
                try:
                    session.run(cypher)
                except Exception as e:
                    logger.debug("Schema statement skipped: %s (%s)", cypher[:60], e)

        logger.info("Neo4j schema created/verified")

    def create_vector_index(self, dimension: int) -> None:
        """Create Neo4j vector index for embeddings."""
        settings = get_settings()
        if not self.is_connected:
            return

        cypher = f"""
        CREATE VECTOR INDEX {settings.vector_index_name} IF NOT EXISTS
        FOR (n:CVE|CWE|CAPEC|ATTACK) ON n.embedding
        OPTIONS {{
            indexConfig: {{
                `vector.dimensions`: {dimension},
                `vector.similarity_function`: '{settings.vector_similarity_function}'
            }}
        }}
        """
        try:
            with self.get_session() as session:
                session.run(cypher)
            logger.info("Vector index '%s' created (dim=%d)", settings.vector_index_name, dimension)
        except Exception as e:
            # Try per-label vector indexes if combined doesn't work
            logger.warning("Combined vector index failed (%s), trying per-label", e)
            for label in ("CVE", "CWE", "CAPEC", "ATTACK"):
                idx_name = f"{settings.vector_index_name}_{label.lower()}"
                per_label_cypher = f"""
                CREATE VECTOR INDEX {idx_name} IF NOT EXISTS
                FOR (n:{label}) ON n.embedding
                OPTIONS {{
                    indexConfig: {{
                        `vector.dimensions`: {dimension},
                        `vector.similarity_function`: '{settings.vector_similarity_function}'
                    }}
                }}
                """
                try:
                    with self.get_session() as session:
                        session.run(per_label_cypher)
                    logger.info("Vector index '%s' created", idx_name)
                except Exception as e2:
                    logger.warning("Vector index '%s' failed: %s", idx_name, e2)

    # ── Query helpers ──────────────────────────────────────

    def run_read(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Execute a read-only query and return results as dicts."""
        if not self.is_connected:
            return []
        with self.get_session() as session:
            result = session.run(cypher, parameters=params or {})
            return [dict(record) for record in result]

    def run_write(self, cypher: str, params: dict[str, Any] | None = None) -> None:
        """Execute a write query."""
        if not self.is_connected:
            raise RuntimeError("Neo4j not connected")
        with self.get_session() as session:
            session.run(cypher, parameters=params or {})

    def get_counts(self) -> dict[str, int]:
        """Get node counts per label and relationship count."""
        if not self.is_connected:
            return {"CVE": 0, "CWE": 0, "CAPEC": 0, "ATTACK": 0, "relationships": 0}

        counts: dict[str, int] = {}
        for label in ("CVE", "CWE", "CAPEC", "ATTACK"):
            res = self.run_read(f"MATCH (n:{label}) RETURN count(n) AS c")
            counts[label] = res[0]["c"] if res else 0

        res = self.run_read("MATCH ()-[r]->() RETURN count(r) AS c")
        counts["relationships"] = res[0]["c"] if res else 0
        return counts


# ── Singleton ───────────────────────────────────────────────

_neo4j_manager: Neo4jManager | None = None


def get_neo4j_manager() -> Neo4jManager:
    global _neo4j_manager
    if _neo4j_manager is None:
        _neo4j_manager = Neo4jManager()
    return _neo4j_manager
