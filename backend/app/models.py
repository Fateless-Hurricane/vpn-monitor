import enum
import datetime as dt

from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text, Enum, UniqueConstraint
)
from sqlalchemy.orm import relationship

from .database import Base


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


class ServerStatus(str, enum.Enum):
    operational = "operational"
    degraded = "degraded"
    down = "down"
    unknown = "unknown"


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    url = Column(String, nullable=False, unique=True)
    last_fetched_at = Column(DateTime, nullable=True)
    last_hash = Column(String, nullable=True)  # hash of raw config list, for change detection
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)

    servers = relationship("Server", back_populates="subscription", cascade="all, delete-orphan")
    change_events = relationship("SubscriptionChangeEvent", back_populates="subscription", cascade="all, delete-orphan")


class Server(Base):
    """A single config/server discovered from a subscription."""
    __tablename__ = "servers"
    __table_args__ = (
        UniqueConstraint("subscription_id", "fingerprint", name="uq_sub_server_fp"),
    )

    id = Column(Integer, primary_key=True)
    subscription_id = Column(Integer, ForeignKey("subscriptions.id"), nullable=False)

    # Identity / dedupe key: protocol+address+port+id is stable across re-fetches
    fingerprint = Column(String, index=True, nullable=False)

    protocol = Column(String, nullable=False)  # vless / vmess / trojan / shadowsocks
    remark = Column(String, nullable=True)     # original tag/name from the config
    address = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    country_name = Column(String, default="Unknown")
    country_flag = Column(String, default="🏳️")
    raw_uri = Column(Text, nullable=False)      # original share-link, needed to rebuild xray config

    is_active = Column(Boolean, default=True)   # false if removed from subscription on a later fetch
    current_status = Column(Enum(ServerStatus), default=ServerStatus.unknown)
    current_latency_ms = Column(Float, nullable=True)
    last_checked_at = Column(DateTime, nullable=True)
    consecutive_failures = Column(Integer, default=0)

    first_seen_at = Column(DateTime, default=utcnow)
    last_seen_at = Column(DateTime, default=utcnow)

    subscription = relationship("Subscription", back_populates="servers")
    checks = relationship("CheckResult", back_populates="server", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="server", cascade="all, delete-orphan")



class CheckResult(Base):
    __tablename__ = "check_results"

    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False)
    checked_at = Column(DateTime, default=utcnow, index=True)

    tcp_success = Column(Boolean, default=False)
    tcp_latency_ms = Column(Float, nullable=True)

    proxy_success = Column(Boolean, default=False)   # real V2Ray/proxy connectivity test
    proxy_latency_ms = Column(Float, nullable=True)

    status = Column(Enum(ServerStatus), default=ServerStatus.unknown)
    error = Column(Text, nullable=True)

    server = relationship("Server", back_populates="checks")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False)

    started_at = Column(DateTime, default=utcnow)
    resolved_at = Column(DateTime, nullable=True)
    severity = Column(String, default="down")  # "down" or "degraded"
    summary = Column(String, nullable=True)

    server = relationship("Server", back_populates="incidents")


class SubscriptionChangeEvent(Base):
    __tablename__ = "subscription_change_events"

    id = Column(Integer, primary_key=True)
    subscription_id = Column(Integer, ForeignKey("subscriptions.id"), nullable=False)
    occurred_at = Column(DateTime, default=utcnow)
    added_count = Column(Integer, default=0)
    removed_count = Column(Integer, default=0)
    detail = Column(Text, nullable=True)  # JSON-ish text summary

    subscription = relationship("Subscription", back_populates="change_events")
