"""Canonical Pydantic models for all cybersecurity entities."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Enumerations ─────────────────────────────────────────────


class EntityType(str, Enum):
    CVE = "CVE"
    CWE = "CWE"
    CAPEC = "CAPEC"
    ATTACK = "ATTACK"


class ClaimStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"


class RetrievalMode(str, Enum):
    GRAPH = "graph"
    SEMANTIC = "semantic"
    HYBRID = "hybrid"


class ChangeAction(str, Enum):
    ADDED = "ADDED"
    UPDATED = "UPDATED"
    REMOVED = "REMOVED"
    UNCHANGED = "UNCHANGED"


class ProcessingStatus(str, Enum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


# ── Reference / External ID ────────────────────────────────


class Reference(BaseModel):
    url: str = ""
    source: str = ""
    tags: list[str] = Field(default_factory=list)
    description: str = ""


class ExternalID(BaseModel):
    source: str
    external_id: str
    url: str = ""


# ── CVSS ────────────────────────────────────────────────────


class CVSSScore(BaseModel):
    version: str = ""
    vector_string: str = ""
    base_score: float = 0.0
    base_severity: str = ""
    source: str = ""


# ── Base Entity ─────────────────────────────────────────────


class CyberEntity(BaseModel):
    """Canonical representation shared across CVE/CWE/CAPEC/ATT&CK."""

    id: str
    entity_type: EntityType
    name: str = ""
    description: str = ""
    source: str = ""
    source_version: str = ""
    source_url: str = ""
    created: Optional[str] = None
    modified: Optional[str] = None
    references: list[Reference] = Field(default_factory=list)
    external_ids: list[ExternalID] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)

    def embedding_text(self) -> str:
        """Build meaningful text for embedding generation."""
        parts = [
            f"[{self.entity_type.value}] {self.id}",
            self.name,
            self.description[:2000] if self.description else "",
        ]
        if self.extra.get("severity"):
            parts.append(f"Severity: {self.extra['severity']}")
        if self.extra.get("abstraction"):
            parts.append(f"Abstraction: {self.extra['abstraction']}")
        if self.extra.get("platforms"):
            parts.append(f"Platforms: {', '.join(self.extra['platforms'][:10])}")
        if self.extra.get("tactics"):
            parts.append(f"Tactics: {', '.join(self.extra['tactics'][:10])}")
        return " | ".join(p for p in parts if p)


# ── CVE ─────────────────────────────────────────────────────


class CVEEntity(CyberEntity):
    entity_type: EntityType = EntityType.CVE
    source: str = "NVD"
    vuln_status: str = ""
    cvss_scores: list[CVSSScore] = Field(default_factory=list)
    weakness_ids: list[str] = Field(default_factory=list)  # CWE IDs
    affected_products: list[str] = Field(default_factory=list)


# ── CWE ─────────────────────────────────────────────────────


class CWEEntity(CyberEntity):
    entity_type: EntityType = EntityType.CWE
    source: str = "MITRE_CWE"
    abstraction: str = ""
    status: str = ""
    parent_ids: list[str] = Field(default_factory=list)
    child_ids: list[str] = Field(default_factory=list)
    likelihood_of_exploit: str = ""
    common_consequences: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)


# ── CAPEC ───────────────────────────────────────────────────


class CAPECEntity(CyberEntity):
    entity_type: EntityType = EntityType.CAPEC
    source: str = "MITRE_CAPEC"
    abstraction: str = ""
    status: str = ""
    likelihood_of_attack: str = ""
    typical_severity: str = ""
    parent_ids: list[str] = Field(default_factory=list)
    child_ids: list[str] = Field(default_factory=list)
    related_weakness_ids: list[str] = Field(default_factory=list)  # CWE IDs
    taxonomy_mappings: list[dict[str, str]] = Field(default_factory=list)


# ── ATT&CK ──────────────────────────────────────────────────


class ATTACKEntity(CyberEntity):
    entity_type: EntityType = EntityType.ATTACK
    source: str = "MITRE_ATTACK"
    attack_id: str = ""
    is_subtechnique: bool = False
    parent_technique_id: str = ""
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    is_deprecated: bool = False
    is_revoked: bool = False


# ── Relationship ────────────────────────────────────────────


class Relationship(BaseModel):
    source_id: str
    target_id: str
    relationship_type: str
    source_dataset: str = ""
    provenance: str = ""


# ── Ingestion Stats ────────────────────────────────────────


class IngestionStats(BaseModel):
    dataset: str
    version: str = ""
    filename: str = ""
    sha256: str = ""
    total_records: int = 0
    successful: int = 0
    failed: int = 0
    skipped: int = 0
    relationships_extracted: int = 0
    processing_time_seconds: float = 0.0
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    errors: list[str] = Field(default_factory=list)


# ── API Models ──────────────────────────────────────────────


class QueryRequest(BaseModel):
    question: str = Field(..., min_length=3, max_length=2000)
    retrieval_mode: RetrievalMode = RetrievalMode.HYBRID
    top_k: int = Field(default=10, ge=1, le=50)


class EvidenceItem(BaseModel):
    id: str
    entity_type: str = ""
    source: str = ""
    description: str = ""
    relevance_score: float = 0.0
    retrieval_method: str = ""
    citation: str = ""


class ValidationResult(BaseModel):
    status: str = "NOT_VALIDATED"
    supported_claims: list[str] = Field(default_factory=list)
    unsupported_claims: list[str] = Field(default_factory=list)
    coverage: float = 0.0
    groundedness: float = 0.0
    total_claims: int = 0


class PerformanceMetrics(BaseModel):
    retrieval_ms: float = 0.0
    generation_ms: float = 0.0
    validation_ms: float = 0.0
    total_ms: float = 0.0


class QueryResponse(BaseModel):
    question: str
    answer: str
    retrieval_mode: str
    entities: list[dict[str, Any]] = Field(default_factory=list)
    relationships: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    citations: list[str] = Field(default_factory=list)
    validation: ValidationResult = Field(default_factory=ValidationResult)
    performance: PerformanceMetrics = Field(default_factory=PerformanceMetrics)


class HealthResponse(BaseModel):
    status: str
    neo4j: str = "unavailable"
    ollama: str = "unavailable"
    embedding_model: str = ""
    version: str = "1.0.0"


class StatsResponse(BaseModel):
    cve_count: int = 0
    cwe_count: int = 0
    capec_count: int = 0
    attack_count: int = 0
    relationship_count: int = 0
    neo4j_status: str = "unavailable"
    ollama_status: str = "unavailable"
    embedding_model: str = ""
    dataset_versions: dict[str, str] = Field(default_factory=dict)
    last_update: str = ""


class DatasetInfo(BaseModel):
    dataset: str
    version: str = ""
    filename: str = ""
    sha256: str = ""
    record_count: int = 0
    successful_records: int = 0
    failed_records: int = 0
    last_update: str = ""
    processing_status: str = "PENDING"
    graph_status: str = "PENDING"
    embedding_status: str = "PENDING"
    vector_index_status: str = "PENDING"
    changes: dict[str, int] = Field(default_factory=dict)


class MonitoringData(BaseModel):
    total_queries: int = 0
    successful_queries: int = 0
    failed_queries: int = 0
    average_latency_ms: float = 0.0
    retrieval_latency_ms: float = 0.0
    generation_latency_ms: float = 0.0
    validation_failures: int = 0
    unsupported_claim_rate: float = 0.0
    dataset_freshness: dict[str, str] = Field(default_factory=dict)
    service_health: dict[str, str] = Field(default_factory=dict)


class EvaluationResult(BaseModel):
    method: str
    precision_at_k: float = 0.0
    recall_at_k: float = 0.0
    mrr: float = 0.0
    answer_relevance: float = 0.0
    evidence_coverage: float = 0.0
    groundedness: float = 0.0
    unsupported_claim_rate: float = 0.0
    latency_ms: float = 0.0
    evaluated_at: str = ""
    note: str = ""


class GraphNeighborhood(BaseModel):
    center_node: dict[str, Any] = Field(default_factory=dict)
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)
