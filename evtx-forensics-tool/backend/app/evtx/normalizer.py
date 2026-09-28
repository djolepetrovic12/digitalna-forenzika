from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.app.config.event_registry import resolve_event_definition
from backend.app.evtx.extractors import extract_generic_fields
from backend.app.models.domain import NormalizedEvent


LOGON_TYPE_MAP = {
    2: "Interactive",
    3: "Network",
    5: "Service",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}


def normalize_timestamp_utc(raw_value: str | None) -> datetime | None:
    if not raw_value:
        return None

    try:
        dt = datetime.fromisoformat(raw_value.replace("Z", "+00:00"))
    except ValueError:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def normalize_logon_type(raw_value: Any) -> tuple[int | None, str | None]:
    if raw_value is None:
        return None, None

    try:
        value = int(str(raw_value).strip())
    except (TypeError, ValueError):
        return None, None

    return value, LOGON_TYPE_MAP.get(value)


def normalize_event(xml_text: str, *, source_filename: str | None = None, record_id: str | int | None = None) -> NormalizedEvent:
    fields = extract_generic_fields(xml_text)
    system = fields.get("system", {})
    event_data = fields.get("event_data", {})
    user_data = fields.get("user_data", {})

    event_id = None
    provider = None
    channel = None
    version = None
    computer = None
    level = None
    raw_record_id = None

    provider_node = system.get("Provider")
    if isinstance(provider_node, dict):
        provider = provider_node.get("Name")

    if system.get("EventID") is not None:
        try:
            event_id = int(str(system["EventID"]))
        except ValueError:
            event_id = None

    if system.get("Version") is not None:
        try:
            version = int(str(system["Version"]))
        except ValueError:
            version = None

    channel = system.get("Channel")
    computer = system.get("Computer")
    level = system.get("Level")
    raw_record_id = system.get("EventRecordID")

    if record_id is None:
        record_id = raw_record_id

    definition = resolve_event_definition(provider, channel, event_id, version)

    target_user = event_data.get("TargetUserName") or event_data.get("TargetUser") or event_data.get("MemberName")
    target_domain = event_data.get("TargetDomainName") or event_data.get("TargetDomain")
    target_sid = event_data.get("TargetUserSid") or event_data.get("TargetSid") or event_data.get("MemberSid")
    subject_user = event_data.get("SubjectUserName")
    subject_domain = event_data.get("SubjectDomainName")
    subject_sid = event_data.get("SubjectUserSid") or event_data.get("SubjectSid")
    logon_id = event_data.get("TargetLogonId") or event_data.get("SubjectLogonId") or event_data.get("LogonId")
    source_ip = event_data.get("IpAddress") or event_data.get("ClientAddress")
    src_host = event_data.get("WorkstationName") or event_data.get("Workstation")
    status = event_data.get("Status")
    sub_status = event_data.get("SubStatus")
    group_name = event_data.get("GroupName")
    group_sid = event_data.get("GroupSid") or event_data.get("GroupDomain")

    logon_type, logon_type_name = normalize_logon_type(event_data.get("LogonType"))

    normalized = NormalizedEvent(
        id=None,
        source_filename=source_filename,
        timestamp_utc=normalize_timestamp_utc(system.get("TimeCreated")),
        record_id=str(record_id) if record_id is not None else None,
        provider=provider,
        event_id=event_id,
        version=version,
        channel=channel,
        computer=computer,
        level=level,
        category=definition.category,
        title=definition.title,
        subject_user=subject_user,
        subject_domain=subject_domain,
        subject_sid=subject_sid,
        target_user=target_user,
        target_domain=target_domain,
        target_sid=target_sid,
        logon_id=str(logon_id) if logon_id is not None else None,
        logon_type=logon_type,
        logon_type_name=logon_type_name,
        source_ip=source_ip if source_ip and source_ip != "-" else None,
        source_host=src_host,
        status=status,
        sub_status=sub_status,
        group_name=group_name,
        group_sid=group_sid,
        attributes={**event_data, **user_data},
        raw_xml=xml_text,
    )

    return normalized
