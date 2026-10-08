"""MITRE CWE XML parser.

Parses cwec_v*.xml into canonical CWEEntity objects.
Inspects the actual XML namespace and structure.
"""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

from app.models.schemas import (
    CWEEntity,
    ExternalID,
    IngestionStats,
    Reference,
    Relationship,
)

logger = logging.getLogger("graphcyrag.ingestion.cwe")

NS = "{http://cwe.mitre.org/cwe-7}"


def _text(el: ET.Element | None) -> str:
    if el is None:
        return ""
    parts: list[str] = []
    if el.text:
        parts.append(el.text.strip())
    for child in el:
        if child.text:
            parts.append(child.text.strip())
        if child.tail:
            parts.append(child.tail.strip())
    return " ".join(parts)


def _extract_related_weaknesses(weakness: ET.Element) -> tuple[list[str], list[str], list[Relationship]]:
    """Extract parent/child CWE relationships."""
    parents: list[str] = []
    children: list[str] = []
    rels: list[Relationship] = []
    related_el = weakness.find(f"{NS}Related_Weaknesses")
    if related_el is None:
        return parents, children, rels

    cwe_id = f"CWE-{weakness.attrib.get('ID', '')}"
    for rw in related_el.findall(f"{NS}Related_Weakness"):
        nature = rw.attrib.get("Nature", "")
        related_cwe = f"CWE-{rw.attrib.get('CWE_ID', '')}"
        if nature == "ChildOf":
            parents.append(related_cwe)
            rels.append(Relationship(
                source_id=cwe_id,
                target_id=related_cwe,
                relationship_type="CWE_CHILD",
                source_dataset="MITRE_CWE",
                provenance=f"CWE ChildOf relationship",
            ))
        elif nature == "ParentOf":
            children.append(related_cwe)
    return parents, children, rels


def _extract_consequences(weakness: ET.Element) -> list[str]:
    cons_el = weakness.find(f"{NS}Common_Consequences")
    if cons_el is None:
        return []
    results: list[str] = []
    for con in cons_el.findall(f"{NS}Consequence"):
        scope = _text(con.find(f"{NS}Scope"))
        impact = _text(con.find(f"{NS}Impact"))
        if scope or impact:
            results.append(f"{scope}: {impact}".strip(": "))
    return results


def _extract_mitigations(weakness: ET.Element) -> list[str]:
    mit_el = weakness.find(f"{NS}Potential_Mitigations")
    if mit_el is None:
        return []
    results: list[str] = []
    for mit in mit_el.findall(f"{NS}Mitigation"):
        desc = _text(mit.find(f"{NS}Description"))
        if desc:
            results.append(desc[:500])
    return results


def _extract_references(weakness: ET.Element) -> list[Reference]:
    refs_el = weakness.find(f"{NS}References")
    if refs_el is None:
        return []
    results: list[Reference] = []
    for ref in refs_el.findall(f"{NS}Reference"):
        url = ref.attrib.get("External_Reference_ID", "")
        results.append(Reference(
            url=url,
            source="MITRE_CWE",
        ))
    return results


def parse_cwe_file(filepath: str | Path) -> tuple[list[CWEEntity], list[Relationship], IngestionStats]:
    """Parse a CWE XML file."""
    filepath = Path(filepath)
    start = time.time()
    entities: list[CWEEntity] = []
    relationships: list[Relationship] = []
    errors: list[str] = []

    sha256 = hashlib.sha256(filepath.read_bytes()).hexdigest()

    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as e:
        logger.error("Failed to parse CWE XML %s: %s", filepath, e)
        return [], [], IngestionStats(dataset="CWE", filename=filepath.name, sha256=sha256, errors=[str(e)])

    version = root.attrib.get("Version", "")
    weaknesses_el = root.find(f"{NS}Weaknesses")
    weakness_list = weaknesses_el.findall(f"{NS}Weakness") if weaknesses_el is not None else list(root.iter(f"{NS}Weakness"))
    total = len(weakness_list)

    for idx, w in enumerate(weakness_list):
        try:
            cwe_num = w.attrib.get("ID", "")
            if not cwe_num:
                errors.append(f"Record {idx}: missing ID")
                continue

            cwe_id = f"CWE-{cwe_num}"
            name = w.attrib.get("Name", "")
            abstraction = w.attrib.get("Abstraction", "")
            status = w.attrib.get("Status", "")

            desc = _text(w.find(f"{NS}Description"))
            parents, children, rels = _extract_related_weaknesses(w)
            consequences = _extract_consequences(w)
            mitigations = _extract_mitigations(w)
            refs = _extract_references(w)
            likelihood = _text(w.find(f"{NS}Likelihood_Of_Exploit"))

            entity = CWEEntity(
                id=cwe_id,
                name=name,
                description=desc,
                source_version=version,
                source_url=f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
                references=refs,
                external_ids=[ExternalID(source="MITRE_CWE", external_id=cwe_id, url=f"https://cwe.mitre.org/data/definitions/{cwe_num}.html")],
                abstraction=abstraction,
                status=status,
                parent_ids=parents,
                child_ids=children,
                likelihood_of_exploit=likelihood,
                common_consequences=consequences,
                mitigations=mitigations,
                extra={"abstraction": abstraction},
            )
            entities.append(entity)
            relationships.extend(rels)

        except Exception as e:
            errors.append(f"Record {idx} (CWE-{w.attrib.get('ID', '?')}): {str(e)[:200]}")
            logger.warning("Error parsing CWE record %d: %s", idx, e)
            continue

    elapsed = time.time() - start
    stats = IngestionStats(
        dataset="CWE",
        version=version,
        filename=filepath.name,
        sha256=sha256,
        total_records=total,
        successful=len(entities),
        failed=total - len(entities),
        relationships_extracted=len(relationships),
        processing_time_seconds=round(elapsed, 3),
        errors=errors[:100],
    )
    logger.info("CWE parsing complete: %d/%d records, %d relationships", len(entities), total, len(relationships))
    return entities, relationships, stats
