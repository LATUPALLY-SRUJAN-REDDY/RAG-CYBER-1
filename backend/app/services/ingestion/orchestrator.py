"""Ingestion orchestrator — discovers, parses, and normalizes all datasets."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.models.schemas import (
    CyberEntity,
    IngestionStats,
    Relationship,
)
from app.services.ingestion.nvd_parser import parse_nvd_file
from app.services.ingestion.cwe_parser import parse_cwe_file
from app.services.ingestion.capec_parser import parse_capec_file
from app.services.ingestion.attack_parser import parse_attack_file

logger = logging.getLogger("graphcyrag.ingestion")


class IngestionOrchestrator:
    """Discovers raw data files and orchestrates parsing for all datasets."""

    def __init__(self) -> None:
        settings = get_settings()
        self.raw_dir = settings.resolve_data_path(settings.data_raw_dir)
        self.processed_dir = settings.resolve_data_path(settings.data_processed_dir)
        self.metadata_dir = settings.resolve_data_path(settings.data_metadata_dir)
        self.processed_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir.mkdir(parents=True, exist_ok=True)

        self.all_entities: list[CyberEntity] = []
        self.all_relationships: list[Relationship] = []
        self.all_stats: list[IngestionStats] = []

    def _find_file(self, subdir: str, pattern: str) -> Path | None:
        d = self.raw_dir / subdir
        if not d.exists():
            return None
        matches = sorted(d.glob(pattern))
        return matches[-1] if matches else None

    def ingest_nvd(self) -> IngestionStats | None:
        fp = self._find_file("nvd", "nvdcve*.json")
        if fp is None:
            logger.warning("No NVD file found in %s/nvd", self.raw_dir)
            return None
        logger.info("Parsing NVD: %s", fp)
        entities, rels, stats = parse_nvd_file(fp)
        self.all_entities.extend(entities)
        self.all_relationships.extend(rels)
        self.all_stats.append(stats)
        return stats

    def ingest_cwe(self) -> IngestionStats | None:
        fp = self._find_file("cwe", "cwec*.xml")
        if fp is None:
            logger.warning("No CWE file found in %s/cwe", self.raw_dir)
            return None
        logger.info("Parsing CWE: %s", fp)
        entities, rels, stats = parse_cwe_file(fp)
        self.all_entities.extend(entities)
        self.all_relationships.extend(rels)
        self.all_stats.append(stats)
        return stats

    def ingest_capec(self) -> IngestionStats | None:
        fp = self._find_file("capec", "capec*.xml")
        if fp is None:
            logger.warning("No CAPEC file found in %s/capec", self.raw_dir)
            return None
        logger.info("Parsing CAPEC: %s", fp)
        entities, rels, stats = parse_capec_file(fp)
        self.all_entities.extend(entities)
        self.all_relationships.extend(rels)
        self.all_stats.append(stats)
        return stats

    def ingest_attack(self) -> IngestionStats | None:
        fp = self._find_file("attack", "enterprise-attack*.json")
        if fp is None:
            logger.warning("No ATT&CK file found in %s/attack", self.raw_dir)
            return None
        logger.info("Parsing ATT&CK: %s", fp)
        entities, rels, stats = parse_attack_file(fp)
        self.all_entities.extend(entities)
        self.all_relationships.extend(rels)
        self.all_stats.append(stats)
        return stats

    def ingest_all(self) -> list[IngestionStats]:
        """Run all parsers and persist results."""
        self.all_entities.clear()
        self.all_relationships.clear()
        self.all_stats.clear()

        self.ingest_nvd()
        self.ingest_cwe()
        self.ingest_capec()
        self.ingest_attack()

        self._save_processed()
        self._save_metadata()
        return self.all_stats

    def _save_processed(self) -> None:
        """Persist canonical entities and relationships to JSON."""
        entities_path = self.processed_dir / "entities.json"
        rels_path = self.processed_dir / "relationships.json"

        entities_data = [e.model_dump(mode="json") for e in self.all_entities]
        rels_data = [r.model_dump(mode="json") for r in self.all_relationships]

        entities_path.write_text(json.dumps(entities_data, indent=2, default=str), encoding="utf-8")
        rels_path.write_text(json.dumps(rels_data, indent=2, default=str), encoding="utf-8")
        logger.info("Saved %d entities and %d relationships", len(entities_data), len(rels_data))

    def _save_metadata(self) -> None:
        """Persist ingestion stats."""
        meta_path = self.metadata_dir / "ingestion_stats.json"
        stats_data = [s.model_dump(mode="json") for s in self.all_stats]
        meta_path.write_text(json.dumps(stats_data, indent=2, default=str), encoding="utf-8")

    def load_processed(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Load previously processed data from disk."""
        entities_path = self.processed_dir / "entities.json"
        rels_path = self.processed_dir / "relationships.json"
        entities: list[dict[str, Any]] = []
        rels: list[dict[str, Any]] = []
        if entities_path.exists():
            entities = json.loads(entities_path.read_text(encoding="utf-8"))
        if rels_path.exists():
            rels = json.loads(rels_path.read_text(encoding="utf-8"))
        return entities, rels

    def load_metadata(self) -> list[dict[str, Any]]:
        meta_path = self.metadata_dir / "ingestion_stats.json"
        if meta_path.exists():
            return json.loads(meta_path.read_text(encoding="utf-8"))
        return []
