from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class EventResponse(BaseModel):
    id: str
    timestamp_utc: datetime | None = None
    record_id: str | None = None
    provider: str | None = None
    channel: str | None = None
    event_id: int | None = None
    version: int | None = None
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
    attributes: dict[str, Any] = Field(default_factory=dict)
    raw_xml: str | None = None
    source_filename: str | None = None


class FindingResponse(BaseModel):
    id: str
    type: str | None = None
    title: str | None = None
    summary: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    correlation_type: str | None = None
    confidence: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence_event_ids: list[str] = Field(default_factory=list)


class SessionResponse(BaseModel):
    id: str
    user: str | None = None
    computer: str | None = None
    logon_id: str | None = None
    logon_type: int | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    evidence_event_ids: list[str] = Field(default_factory=list)
    correlation_notes: list[str] = Field(default_factory=list)
    status: str = "open"


class AnalyzedFileResponse(BaseModel):
    filename: str
    sha256: str
    file_size: int
    record_count: int


class EvtxAnalysisResponse(BaseModel):
    filename: str
    record_count: int
    files: list[AnalyzedFileResponse] = Field(default_factory=list)
    providers: list[str] = Field(default_factory=list)
    channels: list[str] = Field(default_factory=list)
    event_id_counts: dict[str, int] = Field(default_factory=dict)
    events: list[EventResponse] = Field(default_factory=list)
    findings: list[FindingResponse] = Field(default_factory=list)
    sessions: list[SessionResponse] = Field(default_factory=list)