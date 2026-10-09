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

# CORS Configuration — allow all origins for Vercel & local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
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


@app.get("/api")
def root():
    return {
        "name": "GraphCyRAG API",
        "version": "1.0.0",
        "status": "operational",
        "docs_url": "/docs",
    }

# Serve frontend static files
import os
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

frontend_dist = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend", "dist")
if os.path.isdir(frontend_dist):
    # Mount assets folder
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")
    
    # Catch-all route to serve index.html for client-side routing
    @app.get("/{catchall:path}")
    def serve_frontend(catchall: str):
        if catchall.startswith("api/") or catchall == "api":
            return {"detail": "Not Found"}
        index_path = os.path.join(frontend_dist, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return {"detail": "Frontend not found"}
else:
    @app.get("/")
    def root_fallback():
        return {
            "name": "GraphCyRAG API",
            "version": "1.0.0",
            "status": "operational",
            "docs_url": "/docs",
            "message": "Backend API is running. Point your frontend to this URL."
        }
