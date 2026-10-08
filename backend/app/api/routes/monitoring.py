"""Monitoring & telemetry router."""

from __future__ import annotations

from fastapi import APIRouter
from app.models.schemas import MonitoringData
from app.services.monitoring.monitor import get_monitoring_data

router = APIRouter(prefix="/monitoring", tags=["Monitoring"])


@router.get("", response_model=MonitoringData)
def get_monitoring() -> MonitoringData:
    return get_monitoring_data()
