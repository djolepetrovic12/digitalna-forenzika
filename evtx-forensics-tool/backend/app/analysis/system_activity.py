from __future__ import annotations

from datetime import datetime

from backend.app.models.domain import Finding, NormalizedEvent

SYSTEM_EVENT_KEYS: set[tuple[str, int]] = {
    ("Microsoft-Windows-Kernel-General", 12),
    ("Microsoft-Windows-Kernel-General", 13),
    ("Microsoft-Windows-Kernel-Power", 41),
    ("USER32", 1074),
    ("EventLog", 6005),
    ("EventLog", 6006),
    ("EventLog", 6008),
}


def reconstruct_system_activity(events: list[NormalizedEvent]) -> list[Finding]:
    grouped: dict[str | None, list[NormalizedEvent]] = {}
    for event in events:
        if (event.provider, event.event_id) in SYSTEM_EVENT_KEYS:
            grouped.setdefault(event.computer, []).append(event)

    findings: list[Finding] = []
    for computer, group in grouped.items():
        ordered = sorted(group, key=lambda item: item.timestamp_utc or datetime.min)
        if not ordered:
            continue
        evidence_ids = [event.id or str(event.record_id) for event in ordered]
        unexpected = any((event.provider, event.event_id) in {("Microsoft-Windows-Kernel-Power", 41), ("EventLog", 6008)} for event in ordered)
        findings.append(
            Finding(
                id=f"system-{computer}-{ordered[0].id or ordered[0].record_id}",
                type="SYSTEM_LIFECYCLE",
                title="Unexpected shutdown" if unexpected else "System startup / shutdown activity",
                summary=(
                    f"System activity on {computer or 'unknown computer'} includes unexpected shutdown evidence."
                    if unexpected else
                    f"{len(ordered)} system lifecycle events were observed on {computer or 'unknown computer'}."
                ),
                start_time=ordered[0].timestamp_utc,
                end_time=ordered[-1].timestamp_utc,
                correlation_type="direct",
                confidence="HIGH" if unexpected else "MEDIUM",
                metadata={"matched_fields": ["computer", "provider", "event_id", "chronological relationship"], "event_ids": [event.event_id for event in ordered]},
                evidence_event_ids=evidence_ids,
            )
        )
    return findings


def attach_shutdown_context(findings: list[Finding], sessions: list, events: list[NormalizedEvent]) -> list[Finding]:
    shutdowns = [event for event in events if (event.provider, event.event_id) in {("Microsoft-Windows-Kernel-Power", 41), ("EventLog", 6008)}]
    if not shutdowns:
        return findings
    for session in sessions:
        if session.status != "open" or session.end_time is None:
            continue
        nearby = [
            event for event in shutdowns
            if event.computer == session.computer and event.timestamp_utc and abs((event.timestamp_utc - session.end_time).total_seconds()) <= 15 * 60
        ]
        if nearby:
            context_ids = [event.id or str(event.record_id) for event in nearby]
            findings.append(
                Finding(
                    id=f"shutdown-context-{session.id}",
                    type="SESSION_SHUTDOWN_CONTEXT",
                    title="Unexpected shutdown near incomplete session",
                    summary="The session has no observed normal termination event. An unexpected system shutdown/restart was recorded near the end of available activity; this is contextual evidence, not proof of causation.",
                    start_time=session.end_time,
                    end_time=nearby[-1].timestamp_utc,
                    correlation_type="indirect",
                    confidence="MEDIUM",
                    metadata={"matched_fields": ["computer", "time proximity"], "relationship": "CONTEXT_EVENT", "time_difference_seconds": int(abs((nearby[-1].timestamp_utc - session.end_time).total_seconds()))},
                    evidence_event_ids=[*session.evidence_event_ids, *context_ids],
                )
            )
    return findings
