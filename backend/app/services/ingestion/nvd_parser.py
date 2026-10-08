"""NVD CVE 2.0 JSON parser.

Parses the NVD JSON feed format (version 2.0) into canonical CVEEntity objects.
Handles malformed records gracefully and reports ingestion statistics.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

from app.models.schemas import (
    CVEEntity,
    CVSSScore,
    ExternalID,
    IngestionStats,
    Reference,
    Relationship,
)

logger = logging.getLogger("graphcyrag.ingestion.nvd")


def _extract_description(descriptions: list[dict[str, Any]]) -> str:
    """Extract English description from the descriptions list."""
    for d in descriptions:
        if d.get("lang", "").lower() in ("en", "eng"):
            return d.get("value", "")
    if descriptions:
        return descriptions[0].get("value", "")
    return ""


def _extract_cvss(metrics: dict[str, Any]) -> list[CVSSScore]:
    """Extract CVSS scores from the metrics dictionary."""
    scores: list[CVSSScore] = []
    for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key, [])
        for m in metric_list:
            cvss_data = m.get("cvssData", {})
            scores.append(
                CVSSScore(
                    version=cvss_data.get("version", metric_key.replace("cvssMetric", "")),
                    vector_string=cvss_data.get("vectorString", ""),
                    base_score=cvss_data.get("baseScore", 0.0),
                    base_severity=cvss_data.get("baseSeverity", m.get("baseSeverity", "")),
                    source=m.get("source", ""),
                )
            )
    return scores


def _extract_weakness_ids(weaknesses: list[dict[str, Any]]) -> list[str]:
    """Extract CWE IDs from the weaknesses list."""
    cwe_ids: list[str] = []
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-") and val not in cwe_ids:
                cwe_ids.append(val)
    return cwe_ids


def _extract_references(refs: list[dict[str, Any]]) -> list[Reference]:
    return [
        Reference(
            url=r.get("url", ""),
            source=r.get("source", ""),
            tags=r.get("tags", []),
        )
        for r in refs
    ]


def _extract_severity(cvss_scores: list[CVSSScore]) -> str:
    """Get highest severity from available CVSS scores."""
    for s in cvss_scores:
        if s.base_severity:
            return s.base_severity
    return ""


def parse_nvd_file(filepath: str | Path) -> tuple[list[CVEEntity], list[Relationship], IngestionStats]:
    """Parse an NVD CVE 2.0 JSON file.

    Returns:
        Tuple of (entities, relationships, stats).
    """
    filepath = Path(filepath)
    start = time.time()
    entities: list[CVEEntity] = []
    relationships: list[Relationship] = []
    errors: list[str] = []

    # Compute SHA-256
    sha256 = hashlib.sha256(filepath.read_bytes()).hexdigest()

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to read NVD file %s: %s", filepath, e)
        return [], [], IngestionStats(
            dataset="NVD",
            filename=filepath.name,
            sha256=sha256,
            errors=[str(e)],
        )

    version = data.get("version", "")
    total = data.get("totalResults", 0)
    vulns = data.get("vulnerabilities", [])

    for idx, vuln_wrapper in enumerate(vulns):
        try:
            cve_data = vuln_wrapper.get("cve", {})
            if not cve_data:
                errors.append(f"Record {idx}: missing 'cve' key")
                continue

            cve_id = cve_data.get("id", "")
            if not cve_id:
                errors.append(f"Record {idx}: missing CVE id")
                continue

            descriptions = cve_data.get("descriptions", [])
            desc = _extract_description(descriptions)

            metrics = cve_data.get("metrics", {})
            cvss_scores = _extract_cvss(metrics)
            severity = _extract_severity(cvss_scores)

            weakness_ids = _extract_weakness_ids(cve_data.get("weaknesses", []))
            refs = _extract_references(cve_data.get("references", []))

            entity = CVEEntity(
                id=cve_id,
                name=cve_id,
                description=desc,
                source_version=version,
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                created=cve_data.get("published", ""),
                modified=cve_data.get("lastModified", ""),
                references=refs,
                vuln_status=cve_data.get("vulnStatus", ""),
                cvss_scores=cvss_scores,
                weakness_ids=weakness_ids,
                external_ids=[ExternalID(source="NVD", external_id=cve_id, url=f"https://nvd.nist.gov/vuln/detail/{cve_id}")],
                extra={"severity": severity, "source_identifier": cve_data.get("sourceIdentifier", "")},
            )
            entities.append(entity)

            # Create CVE → CWE relationships
            for cwe_id in weakness_ids:
                relationships.append(
                    Relationship(
                        source_id=cve_id,
                        target_id=cwe_id,
                        relationship_type="CVE_CWE",
                        source_dataset="NVD",
                        provenance=f"NVD weakness mapping for {cve_id}",
                    )
                )

        except Exception as e:
            errors.append(f"Record {idx}: {str(e)[:200]}")
            logger.warning("Error parsing NVD record %d: %s", idx, e)
            continue

    elapsed = time.time() - start
    stats = IngestionStats(
        dataset="NVD",
        version=version,
        filename=filepath.name,
        sha256=sha256,
        total_records=len(vulns),
        successful=len(entities),
        failed=len(vulns) - len(entities),
        relationships_extracted=len(relationships),
        processing_time_seconds=round(elapsed, 3),
        errors=errors[:100],  # Cap error list
    )
    logger.info("NVD parsing complete: %d/%d records, %d relationships", len(entities), len(vulns), len(relationships))
    return entities, relationships, stats
