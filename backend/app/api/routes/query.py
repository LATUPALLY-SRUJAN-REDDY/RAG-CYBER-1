"""Query & RAG router."""

from __future__ import annotations

import logging
from fastapi import APIRouter, HTTPException
from app.models.schemas import QueryRequest, QueryResponse
from app.services.rag.rag_service import process_query

logger = logging.getLogger("graphcyrag.api.query")
router = APIRouter(prefix="/query", tags=["Query"])


@router.post("", response_model=QueryResponse)
async def query_endpoint(request: QueryRequest) -> QueryResponse:
    try:
        response = await process_query(request)
        return response
    except Exception as e:
        logger.error("Query processing failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Query error: {str(e)}")
