"""Monitoring service — tracks metrics, query latencies, and service health."""

from __future__ import annotations

import time
import logging
from typing import Any
from collections import deque

from app.models.schemas import MonitoringData
from app.db.neo4j_manager import get_neo4j_manager

logger = logging.getLogger("graphcyrag.monitoring")

_MAX_HISTORY = 500
_queries: deque[dict[str, Any]] = deque(maxlen=_MAX_HISTORY)


def record_query(
    success: bool = True,
    retrieval_ms: float = 0.0,
    generation_ms: float = 0.0,
    validation_ms: float = 0.0,
    total_ms: float = 0.0,
    unsupported_claims: int = 0,
) -> None:
    """Record query execution telemetry."""
    record = {
        "timestamp": time.time(),
        "success": success,
        "retrieval_ms": retrieval_ms,
        "generation_ms": generation_ms,
        "validation_ms": validation_ms,
        "total_ms": total_ms,
        "unsupported_claims": unsupported_claims,
    }
    _queries.append(record)


def get_monitoring_data() -> MonitoringData:
    """Compute aggregated monitoring statistics."""
    total = len(_queries)
    if total == 0:
        mgr = get_neo4j_manager()
        neo4j_status = "connected" if mgr.is_connected else "disconnected"
        return MonitoringData(
            service_health={
                "neo4j": neo4j_status,
                "api": "healthy",
            }
        )

    successful = sum(1 for q in _queries if q.get("success", False))
    failed = total - successful

    avg_total = sum(q.get("total_ms", 0.0) for q in _queries) / total
    avg_retrieval = sum(q.get("retrieval_ms", 0.0) for q in _queries) / total
    avg_generation = sum(q.get("generation_ms", 0.0) for q in _queries) / total

    val_failures = sum(1 for q in _queries if q.get("unsupported_claims", 0) > 0)
    unsupported_rate = round(val_failures / total, 3)

    mgr = get_neo4j_manager()
    neo4j_status = "connected" if mgr.is_connected else "disconnected"

    return MonitoringData(
        total_queries=total,
        successful_queries=successful,
        failed_queries=failed,
        average_latency_ms=round(avg_total, 2),
        retrieval_latency_ms=round(avg_retrieval, 2),
        generation_latency_ms=round(avg_generation, 2),
        validation_failures=val_failures,
        unsupported_claim_rate=unsupported_rate,
        service_health={
            "neo4j": neo4j_status,
            "api": "healthy",
        },
    )
