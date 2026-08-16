import datetime as dt
from typing import Optional
from pydantic import BaseModel


class CheckPoint(BaseModel):
    checked_at: dt.datetime
    status: str
    latency_ms: Optional[float]

    class Config:
        from_attributes = True


class IncidentOut(BaseModel):
    id: int
    started_at: dt.datetime
    resolved_at: Optional[dt.datetime]
    severity: str
    summary: Optional[str]

    class Config:
        from_attributes = True


class ServerOut(BaseModel):
    id: int
    protocol: str
    remark: str
    country_name: str
    country_flag: str
    status: str
    latency_ms: Optional[float]
    last_checked_at: Optional[dt.datetime]
    uptime_pct_24h: float
    history: list[CheckPoint]
    open_incident: Optional[IncidentOut]


class SubscriptionOut(BaseModel):
    id: int
    name: str
    status: str
    last_fetched_at: Optional[dt.datetime]
    servers: list[ServerOut]


class StatusOut(BaseModel):
    overall_status: str
    generated_at: dt.datetime
    subscriptions: list[SubscriptionOut]
    recent_incidents: list[IncidentOut]
