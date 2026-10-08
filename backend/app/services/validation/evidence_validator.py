"""Evidence validation service — checks claim grounding against retrieved evidence."""

from __future__ import annotations

import re
import logging
from typing import Any

from app.models.schemas import ValidationResult

logger = logging.getLogger("graphcyrag.validation")


def _split_into_claims(text: str) -> list[str]:
    """Break answer text into meaningful declarative sentences or bullet points."""
    lines = text.strip().split("\n")
    claims: list[str] = []
    for line in lines:
        cleaned = line.strip().lstrip("-*•0123456789. ")
        if len(cleaned) < 15:
            continue
        # Split line by sentence terminators if multiple sentences
        sentences = re.split(r"(?<=[.!?])\s+", cleaned)
        for s in sentences:
            s_clean = s.strip()
            if len(s_clean) >= 15 and not s_clean.startswith("#"):
                claims.append(s_clean)
    return claims


def validate_answer(answer: str, evidence_results: list[dict[str, Any]], question: str = "") -> ValidationResult:
    """Validate that claims in the generated answer are grounded in the retrieved evidence."""
    if not answer or not answer.strip():
        return ValidationResult(status="EMPTY_ANSWER", total_claims=0)

    if not evidence_results:
        claims = _split_into_claims(answer)
        return ValidationResult(
            status="UNSUPPORTED",
            supported_claims=[],
            unsupported_claims=claims,
            coverage=0.0,
            groundedness=0.0,
            total_claims=len(claims),
        )

    claims = _split_into_claims(answer)
    if not claims:
        return ValidationResult(status="NO_CLAIMS_DETECTED", total_claims=0, groundedness=1.0, coverage=1.0)

    # Build reference corpus of all evidence texts & IDs
    evidence_tokens: set[str] = set()
    evidence_ids: set[str] = set()

    for item in evidence_results:
        eid = str(item.get("id", "")).upper()
        if eid:
            evidence_ids.add(eid)
        name = str(item.get("name", "")).lower()
        desc = str(item.get("description", "")).lower()
        combined = f"{eid.lower()} {name} {desc}"
        words = set(re.findall(r"\b[a-zA-Z0-9_\-]{3,}\b", combined))
        evidence_tokens.update(words)

    supported: list[str] = []
    unsupported: list[str] = []

    for claim in claims:
        claim_lower = claim.lower()
        # Direct entity ID reference check
        has_id_match = any(eid in claim.upper() for eid in evidence_ids if len(eid) > 3)

        # Keyword token overlap check
        claim_words = set(re.findall(r"\b[a-zA-Z0-9_\-]{3,}\b", claim_lower))
        overlap = claim_words.intersection(evidence_tokens)
        overlap_ratio = len(overlap) / max(len(claim_words), 1)

        if has_id_match or overlap_ratio >= 0.25:
            supported.append(claim)
        else:
            unsupported.append(claim)

    total = len(claims)
    sup_count = len(supported)
    groundedness = round(sup_count / total, 3) if total > 0 else 0.0
    coverage = round(min(1.0, sup_count / max(len(evidence_results), 1)), 3)

    if groundedness >= 0.8:
        status = "SUPPORTED"
    elif groundedness >= 0.4:
        status = "PARTIALLY_SUPPORTED"
    else:
        status = "UNSUPPORTED"

    return ValidationResult(
        status=status,
        supported_claims=supported,
        unsupported_claims=unsupported,
        coverage=coverage,
        groundedness=groundedness,
        total_claims=total,
    )
