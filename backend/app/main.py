"""Main FastAPI entry point for the GraphCyRAG application."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.logging import setup_logging
from app.db.neo4j_manager import get_neo4j_manager
from app.api.routes import health, query, stats, datasets, graph, monitoring

# Setup logging
setup_logging()
logger = logging.getLogger("graphcyrag.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup & shutdown events."""
    settings = get_settings()
    logger.info("Initializing GraphCyRAG API on %s:%d...", settings.api_host, settings.api_port)

    # Attempt connection to Neo4j
    mgr = get_neo4j_manager()
    connected = mgr.connect()
    if connected:
        logger.info("Neo4j database connection established.")
        mgr.create_schema()
    else:
        logger.warning("Neo4j is currently unreachable; running with fallback capabilities.")

    yield

    logger.info("Shutting down GraphCyRAG API...")
    mgr.close()


app = FastAPI(
    title="GraphCyRAG API",
    description="Cybersecurity Knowledge Graph Retrieval-Augmented Generation Platform for CVE, CWE, CAPEC & ATT&CK.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS Configuration
settings = get_settings()
origins = settings.cors_origin_list
if not origins:
    origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if "*" not in origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(health.router, prefix="/api")
app.include_router(query.router, prefix="/api")
app.include_router(stats.router, prefix="/api")
app.include_router(datasets.router, prefix="/api")
app.include_router(graph.router, prefix="/api")
app.include_router(monitoring.router, prefix="/api")


@app.get("/")
def root():
    return {
        "name": "GraphCyRAG API",
        "version": "1.0.0",
        "status": "operational",
        "docs_url": "/docs",
    }
