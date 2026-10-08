"""Standalone ingestion script for the 4 cybersecurity datasets."""

import os
import sys
from pathlib import Path

# Add backend directory to python path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from app.services.ingestion.orchestrator import IngestionOrchestrator
from app.services.graph.graph_service import ingest_entities, ingest_relationships
from app.db.neo4j_manager import get_neo4j_manager


def main():
    print("=" * 65)
    print("GraphCyRAG — Cybersecurity Multi-Source Data Ingestion Engine")
    print("=" * 65)

    orchestrator = IngestionOrchestrator()

    print("\n[1/4] Ingesting NVD CVE dataset...")
    nvd_stats = orchestrator.ingest_nvd()
    if nvd_stats:
        print(f"      Processed {nvd_stats.successful} CVE records, {nvd_stats.relationships_extracted} relationships.")

    print("\n[2/4] Ingesting MITRE CWE dataset...")
    cwe_stats = orchestrator.ingest_cwe()
    if cwe_stats:
        print(f"      Processed {cwe_stats.successful} CWE weaknesses, {cwe_stats.relationships_extracted} relationships.")

    print("\n[3/4] Ingesting MITRE CAPEC dataset...")
    capec_stats = orchestrator.ingest_capec()
    if capec_stats:
        print(f"      Processed {capec_stats.successful} CAPEC attack patterns, {capec_stats.relationships_extracted} relationships.")

    print("\n[4/4] Ingesting MITRE ATT&CK Enterprise dataset...")
    attack_stats = orchestrator.ingest_attack()
    if attack_stats:
        print(f"      Processed {attack_stats.successful} ATT&CK techniques, {attack_stats.relationships_extracted} relationships.")

    print("\n[Saving] Writing normalized canonical entities and relationships...")
    orchestrator._save_processed()
    orchestrator._save_metadata()
    print(f"         Saved {len(orchestrator.all_entities)} entities and {len(orchestrator.all_relationships)} relationships to disk.")

    # Neo4j check
    mgr = get_neo4j_manager()
    if mgr.connect():
        print("\n[Neo4j] Connected to graph database! Populating nodes and edges...")
        mgr.create_schema()
        entities_data = [e.model_dump(mode="json") for e in orchestrator.all_entities]
        rels_data = [r.model_dump(mode="json") for r in orchestrator.all_relationships]
        ingest_entities(entities_data)
        ingest_relationships(rels_data)
        print("        Neo4j ingestion complete!")
    else:
        print("\n[Neo4j] Database offline or unreachable. Canonical JSON stored for standalone fallback.")

    print("\n" + "=" * 65)
    print("Ingestion complete!")
    print("=" * 65)


if __name__ == "__main__":
    main()
