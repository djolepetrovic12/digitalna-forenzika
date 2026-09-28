from __future__ import annotations

from datetime import datetime

from backend.app.models.domain import Finding, NormalizedEvent, ReconstructedSession


def reconstruct_remote_sessions(events: list[NormalizedEvent]) -> list[ReconstructedSession]:
    starts = [event for event in events if event.event_id == 4624 and event.logon_type == 10]
    results: list[ReconstructedSession] = []
    for start in sorted(starts, key=lambda item: item.timestamp_utc or datetime.min):
        related = [
            event for event in events
            if event is not start
            and event.computer == start.computer
            and event.logon_id == start.logon_id
            and event.event_id in {4778, 4779, 4647, 4634}
            and (event.timestamp_utc or datetime.min) >= (start.timestamp_utc or datetime.min)
        ]
        ordered = [start, *sorted(related, key=lambda item: item.timestamp_utc or datetime.min)]
        terminal = next((event for event in reversed(ordered) if event.event_id in {4647, 4634}), None)
        results.append(
            ReconstructedSession(
                id=f"rdp-{start.computer}-{start.logon_id}-{start.id or start.record_id}",
                user=start.target_user,
                computer=start.computer,
                logon_id=start.logon_id,
                logon_type=10,
                start_time=start.timestamp_utc,
                end_time=terminal.timestamp_utc if terminal else (ordered[-1].timestamp_utc if terminal else None),
                evidence_event_ids=[event.id or str(event.record_id) for event in ordered],
                correlation_notes=["matched by computer + Logon ID", "4779 is a disconnect, not session termination", "4778 is a reconnect"],
                status="closed" if terminal else "open",
            )
        )
    return results


def remote_sessions_to_findings(sessions: list[ReconstructedSession], events: list[NormalizedEvent]) -> list[Finding]:
    by_id = {event.id or str(event.record_id): event for event in events}
    findings: list[Finding] = []
    for session in sessions:
        evidence = [by_id[event_id] for event_id in session.evidence_event_ids if event_id in by_id]
        if not evidence:
            continue
        findings.append(
            Finding(
                id=f"rdp-finding-{session.id}",
                type="REMOTE_SESSION",
                title="Remote / RDP session",
                summary=f"RemoteInteractive session for {session.user or 'unknown user'} on {session.computer or 'unknown computer'} with {len(evidence) - 1} disconnect/reconnect or termination events.",
                start_time=session.start_time,
                end_time=session.end_time,
                correlation_type="direct",
                confidence="HIGH",
                metadata={"matched_fields": ["computer", "logon_id"], "state_events": [event.event_id for event in evidence]},
                evidence_event_ids=session.evidence_event_ids,
            )
        )
    return findings
