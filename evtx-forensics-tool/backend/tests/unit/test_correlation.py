from datetime import datetime, timedelta, timezone

from backend.app.analysis.authentication import AuthenticationRuleConfig, detect_failed_logon_clusters, detect_failed_then_success
from backend.app.analysis.sessions import reconstruct_sessions
from backend.app.models.domain import NormalizedEvent


def make_event(*, event_id, timestamp, computer="WIN-TEST", target_user="alice", target_domain="WIN-TEST", target_sid="S-1-5-21-1", logon_id="0x100", source_ip="10.0.0.5", logon_type=2, subject_user=None, subject_sid=None, category=None):
    return NormalizedEvent(
        id=f"{event_id}-{timestamp.isoformat()}",
        timestamp_utc=timestamp,
        record_id=str(event_id),
        provider="Microsoft-Windows-Security-Auditing",
        event_id=event_id,
        version=1,
        channel="Security",
        computer=computer,
        category=category or "AUTHENTICATION",
        title=f"Event {event_id}",
        subject_user=subject_user,
        subject_sid=subject_sid,
        target_user=target_user,
        target_domain=target_domain,
        target_sid=target_sid,
        logon_id=logon_id,
        logon_type=logon_type,
        logon_type_name="Interactive" if logon_type == 2 else "Network",
        source_ip=source_ip,
        status="0x0" if event_id == 4624 else "0xC000006A",
        raw_xml="<Event />",
    )


def test_reconstructs_single_logon_session_from_supported_events():
    base = datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc)
    events = [
        make_event(event_id=4624, timestamp=base, logon_id="0x100"),
        make_event(event_id=4672, timestamp=base + timedelta(seconds=5), logon_id="0x100"),
        make_event(event_id=4647, timestamp=base + timedelta(minutes=15), logon_id="0x100"),
        make_event(event_id=4634, timestamp=base + timedelta(minutes=16), logon_id="0x100"),
    ]

    sessions = reconstruct_sessions(events)
    assert len(sessions) == 1
    assert sessions[0].user == "alice"
    assert sessions[0].logon_id == "0x100"
    assert sessions[0].evidence_event_ids == ["4624-2026-09-20T10:00:00+00:00", "4672-2026-09-20T10:00:05+00:00", "4647-2026-09-20T10:15:00+00:00", "4634-2026-09-20T10:16:00+00:00"]


def test_same_username_with_different_logon_ids_remains_distinct_sessions():
    base = datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc)
    events = [
        make_event(event_id=4624, timestamp=base, logon_id="0x100"),
        make_event(event_id=4624, timestamp=base + timedelta(minutes=30), logon_id="0x200"),
    ]

    sessions = reconstruct_sessions(events)
    assert len(sessions) == 2
    assert {session.logon_id for session in sessions} == {"0x100", "0x200"}


def test_repeated_failed_logons_create_failed_attempt_finding():
    base = datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc)
    events = [
        make_event(event_id=4625, timestamp=base + timedelta(seconds=i), target_user="alice", source_ip="10.0.0.5", computer="WIN-TEST")
        for i in range(5)
    ]

    findings = detect_failed_logon_clusters(events, AuthenticationRuleConfig())
    assert len(findings) == 1
    assert findings[0].title == "Repeated failed logon attempts"


def test_failed_then_success_is_detected_only_for_matching_fields():
    base = datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc)
    failed_events = [
        make_event(event_id=4625, timestamp=base + timedelta(seconds=i), target_user="alice", source_ip="10.0.0.5", computer="WIN-TEST")
        for i in range(5)
    ]
    success_match = make_event(event_id=4624, timestamp=base + timedelta(minutes=2), target_user="alice", source_ip="10.0.0.5", computer="WIN-TEST", logon_id="0x100")
    success_unrelated = make_event(event_id=4624, timestamp=base + timedelta(minutes=1), target_user="alice", source_ip="10.0.0.9", computer="WIN-TEST", logon_id="0x999")

    findings = detect_failed_then_success(failed_events + [success_match, success_unrelated], AuthenticationRuleConfig())
    assert len(findings) == 1
    assert findings[0].title == "Repeated failed logons followed by successful logon"
