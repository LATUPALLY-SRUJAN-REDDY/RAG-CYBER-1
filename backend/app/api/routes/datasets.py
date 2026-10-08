"""Dataset management & ingestion triggers router."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from app.core.config import get_settings
from app.services.ingestion.orchestrator import IngestionOrchestrator
from app.services.graph.graph_service import ingest_entities, ingest_relationships
from app.services.embeddings.embedding_service import store_embeddings_in_neo4j

router = APIRouter(prefix="/datasets", tags=["Datasets"])


class IngestRequest(BaseModel):
    dataset: str = "all"  # "all", "nvd", "attack", "capec", "cwe"
    populate_graph: bool = True
    generate_embeddings: bool = False


@router.get("")
def list_datasets() -> list[dict[str, Any]]:
    """Return status and metadata for all 4 raw datasets."""
    settings = get_settings()
    raw_dir = Path(settings.data_raw_dir).resolve()
    processed_dir = Path(settings.data_processed_dir).resolve()

    datasets = [
        {
            "id": "nvd",
            "name": "NVD CVE Database",
            "type": "CVE",
            "version": "2.0 (2026)",
            "subdir": "nvd",
            "pattern": "nvdcve*.json",
            "description": "National Vulnerability Database JSON 2.0 vulnerability feeds with CVSS metrics and CWE references.",
        },
        {
            "id": "attack",
            "name": "MITRE ATT&CK Enterprise",
            "type": "ATTACK",
            "version": "19.2",
            "subdir": "attack",
            "pattern": "enterprise-attack*.json",
            "description": "MITRE Adversarial Tactics, Techniques, and Common Knowledge Enterprise STIX 2.1 knowledge base.",
        },
        {
            "id": "capec",
            "name": "MITRE CAPEC",
            "type": "CAPEC",
            "version": "v3.9",
            "subdir": "capec",
            "pattern": "capec*.xml",
            "description": "Common Attack Pattern Enumeration and Classification dictionary mapping attack mechanisms to weaknesses.",
        },
        {
            "id": "cwe",
            "name": "MITRE CWE",
            "type": "CWE",
            "version": "v4.20",
            "subdir": "cwe",
            "pattern": "cwec*.xml",
            "description": "Common Weakness Enumeration XML catalog of software and hardware weaknesses.",
        },
    ]

    result = []
    for ds in datasets:
        dpath = raw_dir / ds["subdir"]
        files = list(dpath.glob(ds["pattern"])) if dpath.exists() else []
        file_present = len(files) > 0
        file_size_mb = round(files[-1].stat().st_size / (1024 * 1024), 2) if file_present else 0
        file_name = files[-1].name if file_present else "Not found"

        result.append({
            **ds,
            "file_present": file_present,
            "filename": file_name,
            "size_mb": file_size_mb,
            "status": "ready" if file_present else "missing",
        })

    return result


def _run_ingestion_job(dataset: str, populate_graph: bool, gen_embeddings: bool) -> None:
    """Worker job to run ingestion and optional graph population."""
    orchestrator = IngestionOrchestrator()
    if dataset == "nvd":
        orchestrator.ingest_nvd()
    elif dataset == "attack":
        orchestrator.ingest_attack()
    elif dataset == "capec":
        orchestrator.ingest_capec()
    elif dataset == "cwe":
        orchestrator.ingest_cwe()
    else:
        orchestrator.ingest_all()

    orchestrator._save_processed()
    orchestrator._save_metadata()

    if populate_graph:
        entities_dump = [e.model_dump(mode="json") for e in orchestrator.all_entities]
        rels_dump = [r.model_dump(mode="json") for r in orchestrator.all_relationships]
        ingest_entities(entities_dump)
        ingest_relationships(rels_dump)

        if gen_embeddings:
            store_embeddings_in_neo4j(entities_dump)


@router.post("/ingest")
def trigger_ingest(req: IngestRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    """Trigger ingestion for a dataset in the background or immediately."""
    background_tasks.add_task(_run_ingestion_job, req.dataset, req.populate_graph, req.generate_embeddings)
    return {
        "status": "started",
        "dataset": req.dataset,
        "message": f"Ingestion process for '{req.dataset}' initiated in background.",
    }
