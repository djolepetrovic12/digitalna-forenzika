from datetime import datetime, timedelta, timezone

from backend.app.analysis.engine import analyze_events
from backend.app.models.domain import NormalizedEvent


def event(event_id, when, *, computer="WIN-TEST", user="alice", sid="S-1-5-21-1", logon_id="0x100", logon_type=2, source_ip="10.0.0.5", provider="Microsoft-Windows-Security-Auditing", channel="Security"):
    return NormalizedEvent(
        id=f"e-{event_id}-{when.timestamp()}",
        source_filename=f"{channel}.evtx",
        timestamp_utc=when,
        record_id=str(event_id),
        provider=provider,
        event_id=event_id,
        channel=channel,
        computer=computer,
        target_user=user,
        target_sid=sid,
        logon_id=logon_id,
        logon_type=logon_type,
        source_ip=source_ip,
        attributes={"MemberSid": sid, "MemberName": user},
        raw_xml="<Event />",
    )


def test_analysis_engine_keeps_sessions_separate_by_computer_and_logon_id():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    findings, sessions = analyze_events([
        event(4624, base, logon_id="0x1"),
        event(4672, base + timedelta(seconds=1), logon_id="0x1"),
        event(4624, base + timedelta(minutes=1), logon_id="0x2"),
        event(4634, base + timedelta(minutes=2), logon_id="0x1"),
        event(4634, base + timedelta(minutes=3), logon_id="0x2", computer="OTHER-PC"),
    ])
    assert len(sessions) == 2
    assert {session.logon_id for session in sessions} == {"0x1", "0x2"}
    assert not any(finding.type == "SESSION_SHUTDOWN_CONTEXT" for finding in findings)


def test_failed_attempts_do_not_match_unrelated_success():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    failed = [event(4625, base + timedelta(seconds=index), user="marko", source_ip="10.0.0.1") for index in range(5)]
    unrelated = event(4624, base + timedelta(minutes=2), user="petar", source_ip="10.0.0.2")
    findings, _ = analyze_events([*failed, unrelated])
    assert any(finding.type == "FAILED_LOGON_CLUSTER" for finding in findings)
    assert not any(finding.type == "FAILED_LOGON_THEN_SUCCESS" for finding in findings)


def test_account_sid_and_rdp_disconnect_reconnect_are_evidence_linked():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    account_events = [
        event(4720, base, sid="S-1-5-21-10", user="forensicTest"),
        event(4732, base + timedelta(minutes=1), sid="S-1-5-21-10", user="forensicTest"),
        event(4726, base + timedelta(minutes=2), sid="S-1-5-21-10", user="forensicTest"),
    ]
    remote_events = [
        event(4624, base, user="remote", sid="S-1-5-21-20", logon_id="0x9", logon_type=10),
        event(4779, base + timedelta(minutes=5), user="remote", sid="S-1-5-21-20", logon_id="0x9", logon_type=10),
        event(4778, base + timedelta(minutes=10), user="remote", sid="S-1-5-21-20", logon_id="0x9", logon_type=10),
    ]
    findings, sessions = analyze_events([*account_events, *remote_events])
    account = next(finding for finding in findings if finding.type == "ACCOUNT_LIFECYCLE")
    remote = next(session for session in sessions if session.logon_type == 10)
    assert account.correlation_type == "direct"
    assert len(account.evidence_event_ids) == 3
    assert remote.status == "open"
    assert remote.evidence_event_ids[-1].startswith("e-4778")


def test_unexpected_shutdown_is_context_for_open_session():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    session = event(4624, base, computer="WIN-TEST")
    shutdown = event(6008, base + timedelta(minutes=5), computer="WIN-TEST", provider="EventLog", channel="System")
    findings, _ = analyze_events([session, shutdown])
    context = next(finding for finding in findings if finding.type == "SESSION_SHUTDOWN_CONTEXT")
    assert context.correlation_type == "indirect"
    assert "not proof of causation" in context.summary
