"""MITRE ATT&CK Enterprise STIX JSON parser.

Parses enterprise-attack-*.json (STIX 2.x bundle) into canonical
ATTACKEntity objects and extracts subtechnique relationships.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

from app.models.schemas import (
    ATTACKEntity,
    ExternalID,
    IngestionStats,
    Reference,
    Relationship,
)

logger = logging.getLogger("graphcyrag.ingestion.attack")


def _get_attack_id(obj: dict[str, Any]) -> str:
    """Extract the ATT&CK external ID (e.g., T1059)."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _get_attack_url(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def _extract_references(obj: dict[str, Any]) -> list[Reference]:
    refs: list[Reference] = []
    for ref in obj.get("external_references", []):
        refs.append(Reference(
            url=ref.get("url", ""),
            source=ref.get("source_name", ""),
            description=ref.get("description", ""),
        ))
    return refs


def _extract_tactics(obj: dict[str, Any]) -> list[str]:
    return [
        kc.get("phase_name", "")
        for kc in obj.get("kill_chain_phases", [])
        if kc.get("kill_chain_name") == "mitre-attack"
    ]


def parse_attack_file(filepath: str | Path) -> tuple[list[ATTACKEntity], list[Relationship], IngestionStats]:
    """Parse a MITRE ATT&CK Enterprise STIX JSON file."""
    filepath = Path(filepath)
    start = time.time()
    entities: list[ATTACKEntity] = []
    relationships: list[Relationship] = []
    errors: list[str] = []

    sha256 = hashlib.sha256(filepath.read_bytes()).hexdigest()

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to read ATT&CK file %s: %s", filepath, e)
        return [], [], IngestionStats(dataset="ATTACK", filename=filepath.name, sha256=sha256, errors=[str(e)])

    objects = data.get("objects", [])
    attack_patterns = [o for o in objects if o.get("type") == "attack-pattern"]
    stix_relationships = [o for o in objects if o.get("type") == "relationship"]
    total = len(attack_patterns)

    # Build STIX ID → ATT&CK ID map for relationship resolution
    stix_to_attack: dict[str, str] = {}

    for idx, obj in enumerate(attack_patterns):
        try:
            attack_id = _get_attack_id(obj)
            stix_id = obj.get("id", "")
            if not attack_id:
                errors.append(f"Record {idx}: no ATT&CK external_id found")
                continue

            if stix_id:
                stix_to_attack[stix_id] = attack_id

            is_sub = obj.get("x_mitre_is_subtechnique", False)
            is_deprecated = obj.get("x_mitre_deprecated", False)
            is_revoked = obj.get("revoked", False)
            name = obj.get("name", "")
            description = obj.get("description", "")
            platforms = obj.get("x_mitre_platforms", [])
            tactics = _extract_tactics(obj)
            refs = _extract_references(obj)
            url = _get_attack_url(obj)

            # Determine parent technique ID for sub-techniques
            parent_id = ""
            if is_sub and "." in attack_id:
                parent_id = attack_id.split(".")[0]

            entity = ATTACKEntity(
                id=attack_id,
                name=name,
                description=description[:5000] if description else "",
                source_version=data.get("id", ""),
                source_url=url,
                created=obj.get("created", ""),
                modified=obj.get("modified", ""),
                references=refs,
                external_ids=[ExternalID(source="MITRE_ATTACK", external_id=attack_id, url=url)],
                attack_id=attack_id,
                is_subtechnique=is_sub,
                parent_technique_id=parent_id,
                tactics=tactics,
                platforms=platforms,
                is_deprecated=is_deprecated,
                is_revoked=is_revoked,
                extra={"tactics": tactics, "platforms": platforms},
            )
            entities.append(entity)

            # Subtechnique relationship
            if is_sub and parent_id:
                relationships.append(Relationship(
                    source_id=attack_id,
                    target_id=parent_id,
                    relationship_type="SUBTECHNIQUE_OF",
                    source_dataset="MITRE_ATTACK",
                    provenance="ATT&CK subtechnique relationship",
                ))

        except Exception as e:
            errors.append(f"Record {idx}: {str(e)[:200]}")
            logger.warning("Error parsing ATT&CK record %d: %s", idx, e)
            continue

    # Process STIX relationships for subtechnique-of
    for rel in stix_relationships:
        try:
            rel_type = rel.get("relationship_type", "")
            if rel_type == "subtechnique-of":
                src_stix = rel.get("source_ref", "")
                tgt_stix = rel.get("target_ref", "")
                src_id = stix_to_attack.get(src_stix, "")
                tgt_id = stix_to_attack.get(tgt_stix, "")
                if src_id and tgt_id:
                    exists = any(
                        r.source_id == src_id and r.target_id == tgt_id and r.relationship_type == "SUBTECHNIQUE_OF"
                        for r in relationships
                    )
                    if not exists:
                        relationships.append(Relationship(
                            source_id=src_id,
                            target_id=tgt_id,
                            relationship_type="SUBTECHNIQUE_OF",
                            source_dataset="MITRE_ATTACK",
                            provenance="ATT&CK STIX relationship object",
                        ))
        except Exception:
            continue

    elapsed = time.time() - start
    stats = IngestionStats(
        dataset="ATTACK",
        version=data.get("id", ""),
        filename=filepath.name,
        sha256=sha256,
        total_records=total,
        successful=len(entities),
        failed=total - len(entities),
        relationships_extracted=len(relationships),
        processing_time_seconds=round(elapsed, 3),
        errors=errors[:100],
    )
    logger.info("ATT&CK parsing complete: %d/%d records, %d relationships", len(entities), total, len(relationships))
    return entities, relationships, stats
