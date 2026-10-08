"""Knowledge graph statistics router."""

from __future__ import annotations

import json
from pathlib import Path
from fastapi import APIRouter

from app.models.schemas import StatsResponse
from app.core.config import get_settings
from app.db.neo4j_manager import get_neo4j_manager
from app.services.rag.rag_service import check_ollama_health

router = APIRouter(prefix="/stats", tags=["Stats"])


@router.get("", response_model=StatsResponse)
async def get_stats() -> StatsResponse:
    settings = get_settings()
    mgr = get_neo4j_manager()
    ollama_status = await check_ollama_health()

    cve_count = 0
    cwe_count = 0
    capec_count = 0
    attack_count = 0
    rel_count = 0
    neo4j_status = "unavailable"

    if mgr.is_connected:
        neo4j_status = "connected"
        try:
            # Query counts from Neo4j
            res = mgr.run_read("MATCH (n:CVE) RETURN count(n) AS c")
            if res: cve_count = res[0]["c"]
            res = mgr.run_read("MATCH (n:CWE) RETURN count(n) AS c")
            if res: cwe_count = res[0]["c"]
            res = mgr.run_read("MATCH (n:CAPEC) RETURN count(n) AS c")
            if res: capec_count = res[0]["c"]
            res = mgr.run_read("MATCH (n:ATTACK) RETURN count(n) AS c")
            if res: attack_count = res[0]["c"]
            res = mgr.run_read("MATCH ()-[r]->() RETURN count(r) AS c")
            if res: rel_count = res[0]["c"]
        except Exception:
            pass

    # Fallback to metadata / processed files if Neo4j is offline or empty
    if cve_count == 0 and cwe_count == 0 and capec_count == 0 and attack_count == 0:
        meta_path = Path(settings.data_metadata_dir).resolve() / "ingestion_stats.json"
        if meta_path.exists():
            try:
                stats_list = json.loads(meta_path.read_text(encoding="utf-8"))
                for s in stats_list:
                    ds = s.get("dataset", "").upper()
                    success = s.get("successful", 0)
                    rels = s.get("relationships_extracted", 0)
                    rel_count += rels
                    if "NVD" in ds or "CVE" in ds:
                        cve_count += success
                    elif "CWE" in ds:
                        cwe_count += success
                    elif "CAPEC" in ds:
                        capec_count += success
                    elif "ATTACK" in ds:
                        attack_count += success
            except Exception:
                pass

    return StatsResponse(
        cve_count=cve_count,
        cwe_count=cwe_count,
        capec_count=capec_count,
        attack_count=attack_count,
        relationship_count=rel_count,
        neo4j_status=neo4j_status,
        ollama_status=ollama_status,
        embedding_model=settings.embedding_model,
        dataset_versions={
            "NVD CVE": "2.0 (2026)",
            "MITRE ATT&CK": "v19.2 Enterprise",
            "MITRE CAPEC": "v3.9",
            "MITRE CWE": "v4.20",
        },
    )
