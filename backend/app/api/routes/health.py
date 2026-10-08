"""Health check router."""

from __future__ import annotations

from fastapi import APIRouter
from app.models.schemas import HealthResponse
from app.db.neo4j_manager import get_neo4j_manager
from app.services.rag.rag_service import check_ollama_health
from app.core.config import get_settings

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("", response_model=HealthResponse)
async def get_health() -> HealthResponse:
    mgr = get_neo4j_manager()
    neo4j_status = "connected" if mgr.is_connected else "unavailable"
    ollama_status = await check_ollama_health()
    settings = get_settings()

    overall = "healthy" if (neo4j_status == "connected" or ollama_status == "connected") else "degraded"

    return HealthResponse(
        status=overall,
        neo4j=neo4j_status,
        ollama=ollama_status,
        embedding_model=settings.embedding_model,
        version="1.0.0",
    )
