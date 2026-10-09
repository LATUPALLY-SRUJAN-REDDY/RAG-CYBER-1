"""Core configuration loaded from environment variables."""

from __future__ import annotations

import os
from pathlib import Path
from functools import lru_cache
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings – sourced from environment / .env file."""

    # ── Neo4j ──────────────────────────────────────────────────
    neo4j_uri: str = Field(default="bolt://localhost:7687")
    neo4j_username: str = Field(default="neo4j")
    neo4j_password: str = Field(default="changeme_neo4j_password")

    # ── Ollama ─────────────────────────────────────────────────
    ollama_base_url: str = Field(default="http://localhost:11434")
    ollama_model: str = Field(default="llama3")

    # ── Embedding ──────────────────────────────────────────────
    embedding_model: str = Field(default="all-MiniLM-L6-v2")

    # ── API ────────────────────────────────────────────────────
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    api_base_url: str = Field(default="http://localhost:8000")
    cors_origins: str = Field(default="http://localhost:5173,http://localhost:3000")

    # ── Vector Index ───────────────────────────────────────────
    vector_index_name: str = Field(default="cybersecurity_embeddings")
    vector_similarity_function: str = Field(default="cosine")

    # ── Retrieval ──────────────────────────────────────────────
    top_k_limit: int = Field(default=50)
    default_top_k: int = Field(default=10)
    graph_traversal_limit: int = Field(default=5)
    query_timeout: int = Field(default=30)
    graph_weight: float = Field(default=0.4)
    semantic_weight: float = Field(default=0.6)

    # ── Data paths ─────────────────────────────────────────────
    data_raw_dir: str = Field(default="../data/raw")
    data_processed_dir: str = Field(default="../data/processed")
    data_metadata_dir: str = Field(default="../data/metadata")
    data_evaluation_dir: str = Field(default="../data/evaluation")

    # ── Logging ────────────────────────────────────────────────
    log_level: str = Field(default="INFO")

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}

    # ── Helpers ────────────────────────────────────────────────
    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def resolve_data_path(self, relative: str) -> Path:
        """Return an absolute path resolved robustly regardless of current working directory."""
        p = Path(relative)
        if p.exists():
            return p.resolve()
        
        # Try relative to project root (4 levels up from this file: backend/app/core/config.py)
        project_root = Path(__file__).resolve().parent.parent.parent.parent
        rel_cleaned = relative.lstrip("./\\").replace("../", "").replace("..\\", "")
        candidate = project_root / rel_cleaned
        if candidate.exists():
            return candidate.resolve()

        # Try relative to CWD
        cwd_candidate = Path.cwd() / rel_cleaned
        if cwd_candidate.exists():
            return cwd_candidate.resolve()

        return p.resolve()


@lru_cache
def get_settings() -> Settings:
    return Settings()
