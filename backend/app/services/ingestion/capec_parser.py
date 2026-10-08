"""MITRE CAPEC XML parser.

Parses capec_v*.xml (namespace http://capec.mitre.org/capec-3) into
canonical CAPECEntity objects, extracting relationships to CWE and ATT&CK.
"""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
import xml.etree.ElementTree as ET

from app.models.schemas import (
    CAPECEntity,
    ExternalID,
    IngestionStats,
    Reference,
    Relationship,
)

logger = logging.getLogger("graphcyrag.ingestion.capec")

NS = "{http://capec.mitre.org/capec-3}"


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


def _extract_related_patterns(ap: ET.Element, capec_id: str) -> tuple[list[str], list[str], list[Relationship]]:
    """Extract parent/child CAPEC relationships."""
    parents: list[str] = []
    children: list[str] = []
    rels: list[Relationship] = []
    el = ap.find(f"{NS}Related_Attack_Patterns")
    if el is None:
        return parents, children, rels

    for rap in el.findall(f"{NS}Related_Attack_Pattern"):
        nature = rap.attrib.get("Nature", "")
        related_id = f"CAPEC-{rap.attrib.get('CAPEC_ID', '')}"
        if nature == "ChildOf":
            parents.append(related_id)
            rels.append(Relationship(
                source_id=capec_id,
                target_id=related_id,
                relationship_type="CAPEC_CHILD",
                source_dataset="MITRE_CAPEC",
                provenance="CAPEC ChildOf relationship",
            ))
        elif nature == "ParentOf":
            children.append(related_id)
    return parents, children, rels


def _extract_related_weaknesses(ap: ET.Element, capec_id: str) -> tuple[list[str], list[Relationship]]:
    cwe_ids: list[str] = []
    rels: list[Relationship] = []
    el = ap.find(f"{NS}Related_Weaknesses")
    if el is None:
        return cwe_ids, rels

    for rw in el.findall(f"{NS}Related_Weakness"):
        cwe_num = rw.attrib.get("CWE_ID", "")
        if cwe_num:
            cwe_id = f"CWE-{cwe_num}"
            if cwe_id not in cwe_ids:
                cwe_ids.append(cwe_id)
                rels.append(Relationship(
                    source_id=cwe_id,
                    target_id=capec_id,
                    relationship_type="CWE_CAPEC",
                    source_dataset="MITRE_CAPEC",
                    provenance="CAPEC Related_Weakness mapping",
                ))
    return cwe_ids, rels


def _extract_taxonomy_mappings(ap: ET.Element, capec_id: str) -> tuple[list[dict[str, str]], list[Relationship]]:
    mappings: list[dict[str, str]] = []
    rels: list[Relationship] = []
    el = ap.find(f"{NS}Taxonomy_Mappings")
    if el is None:
        return mappings, rels

    for tm in el.findall(f"{NS}Taxonomy_Mapping"):
        taxonomy = tm.attrib.get("Taxonomy_Name", "")
        entry_id_el = tm.find(f"{NS}Entry_ID")
        entry_name_el = tm.find(f"{NS}Entry_Name")
        entry_id = entry_id_el.text.strip() if entry_id_el is not None and entry_id_el.text else ""
        entry_name = entry_name_el.text.strip() if entry_name_el is not None and entry_name_el.text else ""

        mappings.append({"taxonomy": taxonomy, "entry_id": entry_id, "entry_name": entry_name})

        if "ATT&CK" in taxonomy.upper() or "ATTACK" in taxonomy.upper():
            if entry_id:
                rels.append(Relationship(
                    source_id=capec_id,
                    target_id=entry_id,
                    relationship_type="CAPEC_ATTACK",
                    source_dataset="MITRE_CAPEC",
                    provenance=f"CAPEC taxonomy mapping to {taxonomy}",
                ))

    return mappings, rels


def parse_capec_file(filepath: str | Path) -> tuple[list[CAPECEntity], list[Relationship], IngestionStats]:
    """Parse a CAPEC XML file."""
    filepath = Path(filepath)
    start = time.time()
    entities: list[CAPECEntity] = []
    relationships: list[Relationship] = []
    errors: list[str] = []

    sha256 = hashlib.sha256(filepath.read_bytes()).hexdigest()

    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as e:
        logger.error("Failed to parse CAPEC XML %s: %s", filepath, e)
        return [], [], IngestionStats(dataset="CAPEC", filename=filepath.name, sha256=sha256, errors=[str(e)])

    version = root.attrib.get("Version", "")
    aps_el = root.find(f"{NS}Attack_Patterns")
    ap_list = aps_el.findall(f"{NS}Attack_Pattern") if aps_el is not None else list(root.iter(f"{NS}Attack_Pattern"))
    total = len(ap_list)

    for idx, ap in enumerate(ap_list):
        try:
            ap_num = ap.attrib.get("ID", "")
            if not ap_num:
                errors.append(f"Record {idx}: missing ID")
                continue

            capec_id = f"CAPEC-{ap_num}"
            name = ap.attrib.get("Name", "")
            abstraction = ap.attrib.get("Abstraction", "")
            status = ap.attrib.get("Status", "")

            desc = _text(ap.find(f"{NS}Description"))
            likelihood = _text(ap.find(f"{NS}Likelihood_Of_Attack"))
            severity = _text(ap.find(f"{NS}Typical_Severity"))

            parents, children, child_rels = _extract_related_patterns(ap, capec_id)
            cwe_ids, cwe_rels = _extract_related_weaknesses(ap, capec_id)
            tax_mappings, attack_rels = _extract_taxonomy_mappings(ap, capec_id)

            entity = CAPECEntity(
                id=capec_id,
                name=name,
                description=desc,
                source_version=version,
                source_url=f"https://capec.mitre.org/data/definitions/{ap_num}.html",
                external_ids=[ExternalID(source="MITRE_CAPEC", external_id=capec_id, url=f"https://capec.mitre.org/data/definitions/{ap_num}.html")],
                abstraction=abstraction,
                status=status,
                likelihood_of_attack=likelihood,
                typical_severity=severity,
                parent_ids=parents,
                child_ids=children,
                related_weakness_ids=cwe_ids,
                taxonomy_mappings=tax_mappings,
                extra={"abstraction": abstraction, "severity": severity},
            )
            entities.append(entity)
            relationships.extend(child_rels)
            relationships.extend(cwe_rels)
            relationships.extend(attack_rels)

        except Exception as e:
            errors.append(f"Record {idx}: {str(e)[:200]}")
            logger.warning("Error parsing CAPEC record %d: %s", idx, e)
            continue

    elapsed = time.time() - start
    stats = IngestionStats(
        dataset="CAPEC",
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
    logger.info("CAPEC parsing complete: %d/%d records, %d relationships", len(entities), total, len(relationships))
    return entities, relationships, stats
