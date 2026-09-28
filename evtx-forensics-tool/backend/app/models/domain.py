from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class NormalizedEvent:
    id: str | None = None
    source_filename: str | None = None
    timestamp_utc: datetime | None = None
    record_id: str | None = None
    provider: str | None = None
    event_id: int | None = None
    version: int | None = None
    channel: str | None = None
    computer: str | None = None
    level: str | None = None
    category: str | None = None
    title: str | None = None
    subject_user: str | None = None
    subject_domain: str | None = None
    subject_sid: str | None = None
    target_user: str | None = None
    target_domain: str | None = None
    target_sid: str | None = None
    logon_id: str | None = None
    logon_type: int | None = None
    logon_type_name: str | None = None
    source_ip: str | None = None
    source_host: str | None = None
    status: str | None = None
    sub_status: str | None = None
    group_name: str | None = None
    group_sid: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    raw_xml: str | None = None


@dataclass
class Finding:
    id: str | None = None
    type: str | None = None
    title: str | None = None
    summary: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    correlation_type: str = "direct"
    confidence: str = "MEDIUM"
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence_event_ids: list[str] = field(default_factory=list)


@dataclass
class FindingEvent:
    finding_id: str | None = None
    event_id: str | None = None
    relationship: str = "SUPPORTING_EVENT"
    notes: str | None = None


@dataclass
class ReconstructedSession:
    id: str | None = None
    user: str | None = None
    computer: str | None = None
    logon_id: str | None = None
    logon_type: int | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    evidence_event_ids: list[str] = field(default_factory=list)
    correlation_notes: list[str] = field(default_factory=list)
    status: str = "open"


@dataclass
class CorrelationEvidence:
    type: str = "direct"
    matched_fields: list[str] = field(default_factory=list)
    time_difference: str | None = None
    notes: str | None = None
    confidence: str = "MEDIUM"


@dataclass
class AuthenticationRuleConfig:
    failed_attempt_threshold: int = 5
    failed_attempt_window_minutes: int = 5
    success_match_window_minutes: int = 10
    privileged_group_window_minutes: int = 15
