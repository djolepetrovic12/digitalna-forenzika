from __future__ import annotations

from datetime import datetime

from backend.app.models.domain import NormalizedEvent, ReconstructedSession


def reconstruct_sessions(events: list[NormalizedEvent]) -> list[ReconstructedSession]:
    grouped: dict[tuple[str | None, str | None], list[NormalizedEvent]] = {}

    for event in sorted(events, key=lambda item: item.timestamp_utc or datetime.min):
        if event.event_id not in {4624, 4672, 4647, 4634}:
            continue

        if event.event_id == 4624 and event.logon_type == 10:
            continue

        if event.event_id != 4624 and not any(
            existing.event_id == 4624
            for existing in grouped.get((event.computer, event.logon_id), [])
        ):
            continue

        key = (event.computer, event.logon_id)
        grouped.setdefault(key, []).append(event)

    sessions: list[ReconstructedSession] = []
    for (computer, logon_id), group in grouped.items():
        ordered = sorted(group, key=lambda item: item.timestamp_utc or datetime.min)
        if not ordered:
            continue

        session_user = None
        for event in ordered:
            if event.target_user:
                session_user = event.target_user
                break
            if event.subject_user:
                session_user = event.subject_user
                break

        sessions.append(
            ReconstructedSession(
            id=f"session-{computer}-{logon_id}-{ordered[0].id or ordered[0].record_id}",
                user=session_user,
                computer=computer,
                logon_id=logon_id,
                logon_type=ordered[0].logon_type,
                start_time=ordered[0].timestamp_utc,
                end_time=ordered[-1].timestamp_utc,
                evidence_event_ids=[event.id or str(event.record_id) for event in ordered],
                correlation_notes=["matched by computer + Logon ID", "supports 4624 -> 4672 -> 4647/4634 flow"],
                status="closed" if any(event.event_id in {4647, 4634} for event in ordered) else "open",
            )
        )

    return sessions
