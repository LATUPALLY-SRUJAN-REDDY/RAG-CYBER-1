"""RAG service — end-to-end Retrieval-Augmented Generation pipeline."""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from app.core.config import get_settings
from app.models.schemas import (
    EvidenceItem,
    PerformanceMetrics,
    QueryRequest,
    QueryResponse,
    ValidationResult,
)
from app.prompts.rag_prompts import build_rag_prompt
from app.services.retrieval.retrieval_service import retrieve, extract_entity_ids
from app.services.validation.evidence_validator import validate_answer
from app.services.monitoring.monitor import record_query

logger = logging.getLogger("graphcyrag.rag")


async def check_ollama_health() -> str:
    """Check if Ollama is reachable."""
    settings = get_settings()
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            resp = await client.get(f"{settings.ollama_base_url}/api/tags")
            if resp.status_code == 200:
                return "connected"
    except Exception:
        pass
    return "unavailable"


async def generate_with_ollama(system_prompt: str, user_prompt: str) -> str:
    """Call Ollama API for LLM generation with fast connect timeout."""
    settings = get_settings()
    try:
        # Fast connect timeout so we don't stall when Ollama isn't running on cloud
        timeout = httpx.Timeout(5.0, connect=0.5)
        async with httpx.AsyncClient(timeout=timeout) as client:
            payload = {
                "model": settings.ollama_model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "top_p": 0.9,
                },
            }
            resp = await client.post(
                f"{settings.ollama_base_url}/api/chat",
                json=payload,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("message", {}).get("content", "")
    except Exception:
        pass
    return ""


def _build_evidence_items(results: list[dict[str, Any]]) -> list[EvidenceItem]:
    """Convert retrieval results to EvidenceItem objects."""
    items: list[EvidenceItem] = []
    for r in results:
        eid = r.get("id", "")
        etype = r.get("entity_type", "")
        raw_score = r.get("relevance_score", 0)
        try:
            score = round(float(raw_score), 4) if raw_score is not None else 0.0
        except (ValueError, TypeError):
            score = 0.0
        items.append(EvidenceItem(
            id=eid,
            entity_type=etype,
            source=r.get("source", "") or "",
            description=(r.get("description", "") or "")[:500],
            relevance_score=score,
            retrieval_method=r.get("retrieval_method", "") or "",
            citation=f"[{etype}] {eid}" if etype else f"[{eid}]",
        ))
    return items


def _synthesize_threat_report(question: str, results: list[dict[str, Any]], evidence: list[EvidenceItem]) -> str:
    """Generate an authoritative, structured cybersecurity intelligence report from canonical records."""
    if not results:
        return (
            f"No matching cybersecurity entities found in the local knowledge base for '{question}'. "
            "Please check entity identifiers (e.g. CWE-79, CVE-2026-..., CAPEC-66, T1190) or adjust search keywords."
        )

    # Primary entity is the highest relevance item
    primary = results[0]
    p_id = primary.get("id", "Unknown")
    p_type = primary.get("entity_type", "Entity")
    p_name = primary.get("name", "") or p_id
    p_desc = primary.get("description", "") or "No description recorded."

    lines: list[str] = [
        f"### Cybersecurity Threat Intelligence Analysis: {p_id}",
        f"**Canonical Identifier**: [{p_type}] **{p_id}** — {p_name}",
        f"**Source Knowledge Base**: {primary.get('source', 'MITRE / NVD')}",
        "",
        "#### 1. Technical Overview & Scope",
        p_desc,
        "",
    ]

    # Consequences & Exploit Likelihood
    likelihood = primary.get("likelihood_of_exploit") or primary.get("likelihood_of_attack")
    consequences = primary.get("common_consequences")
    if likelihood or consequences:
        lines.append("#### 2. Risk Profile & Consequences")
        if likelihood:
            lines.append(f"- **Likelihood of Exploitation**: {likelihood}")
        if consequences and isinstance(consequences, list):
            lines.append("- **Direct Impacts**:")
            for c in consequences[:4]:
                lines.append(f"  • {c}")
        lines.append("")

    # Ontology Relational Chains
    other_results = results[1:]
    cves = [r for r in other_results if r.get("entity_type") == "CVE"]
    cwes = [r for r in other_results if r.get("entity_type") == "CWE"]
    capecs = [r for r in other_results if r.get("entity_type") == "CAPEC"]
    attacks = [r for r in other_results if r.get("entity_type") == "ATTACK"]

    if cves or cwes or capecs or attacks:
        lines.append("#### 3. Knowledge Graph Ontology Chains")
        if cwes:
            cwe_str = ", ".join(f"[{c['id']}] {c.get('name', '')[:40]}" for c in cwes[:3])
            lines.append(f"- **Related Weaknesses (CWE)**: {cwe_str}")
        if capecs:
            capec_str = ", ".join(f"[{c['id']}] {c.get('name', '')[:40]}" for c in capecs[:3])
            lines.append(f"- **Associated Attack Patterns (CAPEC)**: {capec_str}")
        if attacks:
            attack_str = ", ".join(f"[{a['id']}] {a.get('name', '')[:40]}" for a in attacks[:3])
            lines.append(f"- **Adversary Techniques (MITRE ATT&CK)**: {attack_str}")
        if cves:
            cve_str = ", ".join(c['id'] for c in cves[:5])
            lines.append(f"- **Linked Vulnerability Disclosures (NVD CVE)**: {cve_str}")
        lines.append("")

    # Mitigations
    mitigations = primary.get("mitigations")
    if mitigations and isinstance(mitigations, list):
        lines.append("#### 4. Defensive Strategies & Mitigations")
        for m in mitigations[:4]:
            clean_m = m.strip()
            if clean_m:
                lines.append(f"- {clean_m[:280]}")
        lines.append("")

    # Citations
    citation_tags = [f"[{r.get('entity_type', '')}] {r.get('id', '')}" for r in results[:8] if r.get('id')]
    if citation_tags:
        lines.append(f"**Verified Citations**: {', '.join(citation_tags)}")

    return "\n".join(lines)


async def process_query(request: QueryRequest) -> QueryResponse:
    """Execute the full RAG pipeline: retrieve → generate → validate."""
    total_start = time.time()
    question = request.question.strip()
    mode = request.retrieval_mode.value
    top_k = request.top_k

    # Step 1: Retrieval
    results, retrieval_ms = retrieve(question, mode=mode, top_k=top_k)
    evidence_items = _build_evidence_items(results)

    # Step 2: Build prompt and generate
    gen_start = time.time()
    system_prompt, user_prompt = build_rag_prompt(question, results)

    # Try Ollama if responsive
    answer = await generate_with_ollama(system_prompt, user_prompt)

    # If Ollama is offline or produced empty result, synthesize rich threat intelligence report
    if not answer:
        answer = _synthesize_threat_report(question, results, evidence_items)

    generation_ms = (time.time() - gen_start) * 1000

    # Step 3: Validation
    val_start = time.time()
    validation = validate_answer(answer, results, question)
    validation_ms = (time.time() - val_start) * 1000

    total_ms = (time.time() - total_start) * 1000

    # Extract entities and relationships from results
    entities = [
        {"id": r.get("id", ""), "type": r.get("entity_type", ""), "name": r.get("name", "")}
        for r in results
    ]
    relationships = [
        {"source": r.get("id", ""), "type": r.get("relationship_type", ""), "target": ""}
        for r in results if r.get("relationship_type")
    ]
    citations = [e.citation for e in evidence_items if e.citation]

    performance = PerformanceMetrics(
        retrieval_ms=round(retrieval_ms, 2),
        generation_ms=round(generation_ms, 2),
        validation_ms=round(validation_ms, 2),
        total_ms=round(total_ms, 2),
    )

    response = QueryResponse(
        question=question,
        answer=answer,
        retrieval_mode=mode,
        entities=entities,
        relationships=relationships,
        evidence=evidence_items,
        citations=citations,
        validation=validation,
        performance=performance,
    )

    # Record metrics
    record_query(
        success=True,
        retrieval_ms=retrieval_ms,
        generation_ms=generation_ms,
        validation_ms=validation_ms,
        total_ms=total_ms,
        unsupported_claims=len(validation.unsupported_claims),
    )

    return response
