from datetime import datetime, timedelta, timezone

from backend.app.analysis.accounts import reconstruct_account_lifecycles
from backend.app.analysis.authentication import AuthenticationRuleConfig, detect_failed_logon_clusters, detect_failed_then_success
from backend.app.analysis.engine import analyze_events
from backend.app.analysis.system_activity import reconstruct_system_activity
from backend.app.config.event_registry import resolve_event_definition
from backend.app.models.domain import NormalizedEvent


def event(event_id, when, *, computer="WIN-TEST", user="alice", sid="S-1-5-21-1", logon_id="0x100", logon_type=2, source_ip="10.0.0.5", provider="Microsoft-Windows-Security-Auditing", channel="Security", attributes=None):
    event_attributes = {"MemberSid": sid, "MemberName": user, **(attributes or {})}
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
        activity_id=event_attributes.get("ActivityID"),
        related_activity_id=event_attributes.get("RelatedActivityID"),
        attributes=event_attributes,
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


def test_failed_logon_cluster_requires_identity_for_clustering():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    failed = [
        event(4625, base + timedelta(seconds=i), user=None, sid=None, source_ip=None, computer="WIN-TEST")
        for i in range(5)
    ]
    findings = detect_failed_logon_clusters(failed, AuthenticationRuleConfig())
    assert findings == []


def test_failed_logon_cluster_detects_same_user_same_ip_within_window():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    failed = [
        event(4625, base + timedelta(seconds=i * 30), user="forensicTest", sid="S-1-5-21-99", source_ip="10.0.0.5", computer="WIN-TEST")
        for i in range(4)
    ]
    findings = detect_failed_logon_clusters(failed, AuthenticationRuleConfig())
    assert len(findings) == 1
    assert findings[0].type == "FAILED_LOGON_CLUSTER"
    assert findings[0].metadata["matched_fields"] == ["computer", "target_user", "source_ip", "time_window"]
    assert len(findings[0].evidence_event_ids) == 4


def test_failed_then_success_uses_exact_failed_cluster_evidence():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    failed = [
        event(4625, base + timedelta(seconds=i * 30), user="forensicTest", sid="S-1-5-21-99", source_ip="10.0.0.5", computer="WIN-TEST")
        for i in range(4)
    ]
    unrelated_failed = event(4625, base + timedelta(minutes=2), user="otheruser", sid="S-1-5-21-98", source_ip="10.0.0.8", computer="WIN-TEST")
    success = event(4624, base + timedelta(minutes=3), user="forensicTest", sid="S-1-5-21-99", source_ip="10.0.0.5", computer="WIN-TEST", logon_id="0x987")
    findings = detect_failed_then_success(failed + [unrelated_failed, success], AuthenticationRuleConfig())
    assert len(findings) == 1
    assert findings[0].title == "Repeated failed logons followed by successful logon"
    expected_ids = {event.id for event in failed} | {success.id}
    assert set(findings[0].evidence_event_ids) == expected_ids
    assert findings[0].evidence_event_ids[-1] == success.id


def test_failed_logon_cluster_uses_rolling_window_without_duplicates():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    failed = [
        event(4625, base + timedelta(minutes=0), user="forensicTest", sid="S-1-5-21-99", source_ip="10.0.0.5", computer="WIN-TEST"),
        event(4625, base + timedelta(minutes=1), user="forensicTest", sid="S-1-5-21-99", source_ip="10.0.0.5", computer="WIN-TEST"),
        event(4625, base + timedelta(minutes=2), user="forensicTest", sid="S-1-5-21-99", source_ip="10.0.0.5", computer="WIN-TEST"),
        event(4625, base + timedelta(minutes=3), user="forensicTest", sid="S-1-5-21-99", source_ip="10.0.0.5", computer="WIN-TEST"),
        event(4625, base + timedelta(minutes=65), user="forensicTest", sid="S-1-5-21-99", source_ip="10.0.0.5", computer="WIN-TEST"),
    ]
    findings = detect_failed_logon_clusters(failed, AuthenticationRuleConfig())
    assert len(findings) == 1
    assert findings[0].start_time == base
    assert findings[0].end_time == base + timedelta(minutes=3)


def test_failed_then_success_requires_matching_user_and_computer():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    failed = [
        event(4625, base + timedelta(minutes=i), user="forensicTest", sid="S-1-5-21-99", source_ip="10.0.0.5", computer="WIN-TEST")
        for i in range(4)
    ]
    wrong_user_success = event(4624, base + timedelta(minutes=5), user="otherUser", sid="S-1-5-21-98", source_ip="10.0.0.5", computer="WIN-TEST", logon_id="0x777")
    wrong_pc_success = event(4624, base + timedelta(minutes=5), user="forensicTest", sid="S-1-5-21-99", source_ip="10.0.0.5", computer="OTHER-PC", logon_id="0x888")
    findings = detect_failed_then_success(failed + [wrong_user_success, wrong_pc_success], AuthenticationRuleConfig())
    assert findings == []


def test_anonymous_failed_logons_without_activity_id_are_not_clustered():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    failed = [event(4625, base + timedelta(seconds=i), user=None, sid=None, source_ip=None, computer="WIN-TEST") for i in range(5)]
    assert detect_failed_logon_clusters(failed, AuthenticationRuleConfig()) == []


def test_anonymous_failed_logons_with_same_activity_id_cluster():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    failed = [
        event(4625, base + timedelta(seconds=i), user=None, sid="S-1-0-0", source_ip="127.0.0.1", computer="WIN-TEST", attributes={"ActivityID": "{a6bcbc0c-4fe6-0004-86bc-bca6e64fdd01}"})
        for i in range(4)
    ]
    findings = detect_failed_logon_clusters(failed, AuthenticationRuleConfig())
    assert len(findings) == 1
    assert findings[0].metadata["correlation"] == "activity_id"
    assert findings[0].metadata["matched_fields"] == ["computer", "activity_id", "source_ip", "time_window"]


def test_anonymous_failed_logons_with_different_activity_ids_are_not_clustered():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    failed = [
        event(4625, base + timedelta(seconds=i), user=None, sid="S-1-0-0", source_ip="127.0.0.1", computer="WIN-TEST", attributes={"ActivityID": f"{{{i}}}"})
        for i in range(4)
    ]
    assert detect_failed_logon_clusters(failed, AuthenticationRuleConfig()) == []


def test_activity_id_failed_then_success_matches_same_activity():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    activity_id = "{a6bcbc0c-4fe6-0004-86bc-bca6e64fdd01}"
    failed = [
        event(4625, base + timedelta(seconds=i), user=None, sid="S-1-0-0", source_ip="127.0.0.1", computer="WIN-TEST", attributes={"ActivityID": activity_id})
        for i in range(4)
    ]
    success = event(4624, base + timedelta(seconds=8), user="djole.pet.sremac@gmail.com", sid="S-1-5-21-777", source_ip="127.0.0.1", computer="WIN-TEST", logon_id="0xabc", attributes={"ActivityID": activity_id})
    findings = detect_failed_then_success(failed + [success], AuthenticationRuleConfig())
    assert len(findings) == 1
    assert findings[0].type == "FAILED_LOGON_THEN_SUCCESS"
    assert findings[0].summary.startswith("A failed logon pattern was followed by a successful logon for djole.pet.sremac@gmail.com")
    assert set(findings[0].evidence_event_ids) == {ev.id for ev in failed} | {success.id}


def test_activity_id_success_with_wrong_activity_does_not_match():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    failed = [
        event(4625, base + timedelta(seconds=i), user=None, sid="S-1-0-0", source_ip="127.0.0.1", computer="WIN-TEST", attributes={"ActivityID": "{x}"})
        for i in range(4)
    ]
    bad_success = event(4624, base + timedelta(seconds=8), user="other", sid="S-1-5-21-777", source_ip="127.0.0.1", computer="WIN-TEST", logon_id="0xabc", attributes={"ActivityID": "{y}"})
    assert detect_failed_then_success(failed + [bad_success], AuthenticationRuleConfig()) == []


def test_activity_id_success_with_wrong_computer_does_not_match():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    activity_id = "{a6bcbc0c-4fe6-0004-86bc-bca6e64fdd01}"
    failed = [
        event(4625, base + timedelta(seconds=i), user=None, sid="S-1-0-0", source_ip="127.0.0.1", computer="WIN-TEST", attributes={"ActivityID": activity_id})
        for i in range(4)
    ]
    bad_success = event(4624, base + timedelta(seconds=8), user="other", sid="S-1-5-21-777", source_ip="127.0.0.1", computer="OTHER-PC", logon_id="0xabc", attributes={"ActivityID": activity_id})
    assert detect_failed_then_success(failed + [bad_success], AuthenticationRuleConfig()) == []


def test_real_windows_activity_id_login_shape_matches():
    base = datetime(2026, 10, 1, 1, 58, 48, 396358, tzinfo=timezone.utc)
    activity_id = "{a6bcbc0c-4fe6-0004-86bc-bca6e64fdd01}"
    failed = [
        event(4625, base + timedelta(milliseconds=0), user=None, sid="S-1-0-0", source_ip="127.0.0.1", computer="DESKTOP-913S4IT", logon_type=2, attributes={"ActivityID": activity_id}),
        event(4625, base + timedelta(milliseconds=1559), user=None, sid="S-1-0-0", source_ip="127.0.0.1", computer="DESKTOP-913S4IT", logon_type=2, attributes={"ActivityID": activity_id}),
        event(4625, base + timedelta(milliseconds=2616), user=None, sid="S-1-0-0", source_ip="127.0.0.1", computer="DESKTOP-913S4IT", logon_type=2, attributes={"ActivityID": activity_id}),
        event(4625, base + timedelta(milliseconds=3777), user=None, sid="S-1-0-0", source_ip="127.0.0.1", computer="DESKTOP-913S4IT", logon_type=2, attributes={"ActivityID": activity_id}),
    ]
    success = event(4624, base + timedelta(seconds=12), user="djole.pet.sremac@gmail.com", sid="S-1-5-21-777", source_ip="127.0.0.1", computer="DESKTOP-913S4IT", logon_type=11, logon_id="0xabc", attributes={"ActivityID": activity_id})
    cluster_findings = detect_failed_logon_clusters(failed, AuthenticationRuleConfig())
    success_findings = detect_failed_then_success(failed + [success], AuthenticationRuleConfig())
    assert len(cluster_findings) == 1
    assert len(success_findings) == 1
    assert set(cluster_findings[0].evidence_event_ids) == {ev.id for ev in failed}
    assert set(success_findings[0].evidence_event_ids) == {ev.id for ev in failed} | {success.id}


def test_known_user_authentication_still_works_with_identity_path():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    failed = [
        event(4625, base + timedelta(seconds=i), user="forensicTest", sid="S-1-5-21-99", source_ip="10.0.0.5", computer="WIN-TEST")
        for i in range(4)
    ]
    success = event(4624, base + timedelta(minutes=1), user="forensicTest", sid="S-1-5-21-99", source_ip="10.0.0.5", computer="WIN-TEST", logon_id="0xabc")
    assert len(detect_failed_logon_clusters(failed, AuthenticationRuleConfig())) == 1
    assert len(detect_failed_then_success(failed + [success], AuthenticationRuleConfig())) == 1


def test_placeholder_user_name_is_normalized_to_none():
    xml = '''
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-10-01T01:58:48.396358Z"/>
    <EventRecordID>101</EventRecordID>
    <Channel>Security</Channel>
    <Computer>DESKTOP-913S4IT</Computer>
    <Correlation ActivityID="{a6bcbc0c-4fe6-0004-86bc-bca6e64fdd01}"/>
  </System>
  <EventData>
    <Data Name="TargetUserName">-</Data>
    <Data Name="TargetDomainName">-</Data>
    <Data Name="IpAddress">127.0.0.1</Data>
    <Data Name="WorkstationName">-</Data>
    <Data Name="LogonType">2</Data>
  </EventData>
</Event>
'''.strip()
    event_model = __import__('backend.app.evtx.normalizer', fromlist=['normalize_event']).normalize_event(xml)
    assert event_model.target_user is None
    assert event_model.target_domain is None
    assert event_model.source_ip == "127.0.0.1"
    assert event_model.source_host is None
    assert event_model.activity_id == "{a6bcbc0c-4fe6-0004-86bc-bca6e64fdd01}"


def test_same_activity_id_but_different_auth_contexts_are_not_merged():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    activity_id = "{70249b5b-5149-0002-0d9c-24704951dd01}"
    service = [
        event(4625, base + timedelta(seconds=i), user=None, sid="S-1-0-0", source_ip=None, computer="DESKTOP-913S4IT", logon_type=3, attributes={
            "ActivityID": activity_id,
            "LogonProcessName": "Authz",
            "AuthenticationPackageName": "Kerberos",
            "ProcessName": "C:\\Program Files (x86)\\National Instruments\\Shared\\NI WebServer\\SystemWebServer.exe",
        })
        for i in range(4)
    ]
    interactive = [
        event(4625, base + timedelta(seconds=10 + i), user=None, sid="S-1-0-0", source_ip="127.0.0.1", computer="DESKTOP-913S4IT", logon_type=2, attributes={
            "ActivityID": activity_id,
            "LogonProcessName": "User32",
            "AuthenticationPackageName": "Negotiate",
            "ProcessName": "C:\\Windows\\System32\\svchost.exe",
        })
        for i in range(4)
    ]
    findings = detect_failed_logon_clusters(service + interactive, AuthenticationRuleConfig())
    assert len(findings) == 2
    assert {tuple(f.evidence_event_ids) for f in findings} == {
        tuple(event.id for event in service),
        tuple(event.id for event in interactive),
    }


def test_interactive_activity_id_cluster_matches_same_auth_context_success_regardless_of_logon_type():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    activity_id = "{70249b5b-5149-0002-0d9c-24704951dd01}"
    failed = [
        event(4625, base + timedelta(seconds=i), user=None, sid="S-1-0-0", source_ip="127.0.0.1", computer="DESKTOP-913S4IT", logon_type=2, attributes={
            "ActivityID": activity_id,
            "LogonProcessName": "User32",
            "AuthenticationPackageName": "Negotiate",
            "ProcessName": "C:\\Windows\\System32\\svchost.exe",
        })
        for i in range(4)
    ]
    success = event(4624, base + timedelta(seconds=8), user="djole.pet.sremac@gmail.com", sid="S-1-5-21-777", source_ip="127.0.0.1", computer="DESKTOP-913S4IT", logon_type=11, attributes={
        "ActivityID": activity_id,
        "LogonProcessName": "User32",
        "AuthenticationPackageName": "Negotiate",
        "ProcessName": "C:\\Windows\\System32\\svchost.exe",
    })
    clusters = detect_failed_logon_clusters(failed, AuthenticationRuleConfig())
    chain = detect_failed_then_success(failed + [success], AuthenticationRuleConfig())
    assert len(clusters) == 1
    assert set(clusters[0].evidence_event_ids) == {ev.id for ev in failed}
    assert len(chain) == 1
    assert set(chain[0].evidence_event_ids) == {ev.id for ev in failed} | {success.id}


def test_same_activity_id_rejects_wrong_process_or_package_or_source_ip():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    activity_id = "{70249b5b-5149-0002-0d9c-24704951dd01}"
    failed = [
        event(4625, base + timedelta(seconds=i), user=None, sid="S-1-0-0", source_ip="127.0.0.1", computer="DESKTOP-913S4IT", logon_type=2, attributes={
            "ActivityID": activity_id,
            "LogonProcessName": "User32",
            "AuthenticationPackageName": "Negotiate",
            "ProcessName": "C:\\Windows\\System32\\svchost.exe",
        })
        for i in range(4)
    ]
    wrong_process = event(4624, base + timedelta(seconds=8), user="djole.pet.sremac@gmail.com", sid="S-1-5-21-777", source_ip="127.0.0.1", computer="DESKTOP-913S4IT", logon_type=11, attributes={
        "ActivityID": activity_id,
        "LogonProcessName": "User32",
        "AuthenticationPackageName": "Negotiate",
        "ProcessName": "C:\\Windows\\System32\\notepad.exe",
    })
    wrong_package = event(4624, base + timedelta(seconds=8), user="djole.pet.sremac@gmail.com", sid="S-1-5-21-777", source_ip="127.0.0.1", computer="DESKTOP-913S4IT", logon_type=11, attributes={
        "ActivityID": activity_id,
        "LogonProcessName": "User32",
        "AuthenticationPackageName": "NTLM",
        "ProcessName": "C:\\Windows\\System32\\svchost.exe",
    })
    wrong_ip = event(4624, base + timedelta(seconds=8), user="djole.pet.sremac@gmail.com", sid="S-1-5-21-777", source_ip="10.0.0.2", computer="DESKTOP-913S4IT", logon_type=11, attributes={
        "ActivityID": activity_id,
        "LogonProcessName": "User32",
        "AuthenticationPackageName": "Negotiate",
        "ProcessName": "C:\\Windows\\System32\\svchost.exe",
    })
    assert detect_failed_then_success(failed + [wrong_process], AuthenticationRuleConfig()) == []
    assert detect_failed_then_success(failed + [wrong_package], AuthenticationRuleConfig()) == []
    assert detect_failed_then_success(failed + [wrong_ip], AuthenticationRuleConfig()) == []


def test_process_whitespace_is_normalized_for_context_matching():
    activity_id = "{70249b5b-5149-0002-0d9c-24704951dd01}"
    left = [
        event(4625, datetime(2026, 9, 20, 10, tzinfo=timezone.utc) + timedelta(seconds=i), user=None, sid="S-1-0-0", source_ip="127.0.0.1", computer="DESKTOP-913S4IT", logon_type=2, attributes={
            "ActivityID": activity_id,
            "LogonProcessName": "User32 ",
            "AuthenticationPackageName": " Negotiate ",
            "ProcessName": "C:\\Windows\\System32\\svchost.exe",
        })
        for i in range(4)
    ]
    right = [
        event(4625, datetime(2026, 9, 20, 10, 0, 1, tzinfo=timezone.utc) + timedelta(seconds=i), user=None, sid="S-1-0-0", source_ip="127.0.0.1", computer="DESKTOP-913S4IT", logon_type=2, attributes={
            "ActivityID": activity_id,
            "LogonProcessName": "User32",
            "AuthenticationPackageName": "Negotiate",
            "ProcessName": "C:\\Windows\\System32\\svchost.exe",
        })
        for i in range(4)
    ]
    assert len(detect_failed_logon_clusters(left + right, AuthenticationRuleConfig())) == 1


def test_service_processes_with_same_activity_id_are_not_merged():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    activity_id = "{70249b5b-5149-0002-0d9c-24704951dd01}"
    first = [
        event(4625, base + timedelta(seconds=i), user=None, sid="S-1-0-0", source_ip=None, computer="DESKTOP-913S4IT", logon_type=3, attributes={
            "ActivityID": activity_id,
            "LogonProcessName": "Authz",
            "AuthenticationPackageName": "Kerberos",
            "ProcessName": "C:\\Program Files (x86)\\National Instruments\\Shared\\NI WebServer\\SystemWebServer.exe",
        })
        for i in range(4)
    ]
    second = [
        event(4625, base + timedelta(seconds=10 + i), user=None, sid="S-1-0-0", source_ip=None, computer="DESKTOP-913S4IT", logon_type=3, attributes={
            "ActivityID": activity_id,
            "LogonProcessName": "Authz",
            "AuthenticationPackageName": "Kerberos",
            "ProcessName": "C:\\Program Files (x86)\\National Instruments\\Shared\\NI WebServer\\ApplicationWebServer.exe",
        })
        for i in range(4)
    ]
    findings = detect_failed_logon_clusters(first + second, AuthenticationRuleConfig())
    assert len(findings) == 2
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    failed = [event(4625, base + timedelta(seconds=i), user=None, sid=None, source_ip=None, computer="WIN-TEST") for i in range(5)]
    assert detect_failed_logon_clusters(failed, AuthenticationRuleConfig()) == []


def test_authentication_detects_local_failures_without_ip_when_user_known():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    failed = [
        event(4625, base + timedelta(minutes=i), user="forensicTest", sid="S-1-5-21-99", source_ip=None, computer="WIN-TEST")
        for i in range(4)
    ]
    findings = detect_failed_logon_clusters(failed, AuthenticationRuleConfig())
    assert len(findings) == 1
    assert findings[0].metadata["matched_fields"] == ["computer", "target_user", "time_window"]


def test_failed_then_success_requires_same_user_and_same_computer():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    failed = [
        event(4625, base + timedelta(minutes=i), user="forensicTest", sid="S-1-5-21-99", source_ip="10.0.0.5", computer="WIN-TEST")
        for i in range(4)
    ]
    bad_user = event(4624, base + timedelta(minutes=5), user="otherUser", sid="S-1-5-21-98", source_ip="10.0.0.5", computer="WIN-TEST", logon_id="0x777")
    bad_pc = event(4624, base + timedelta(minutes=5), user="forensicTest", sid="S-1-5-21-99", source_ip="10.0.0.5", computer="OTHER-PC", logon_id="0x888")
    findings = detect_failed_then_success(failed + [bad_user, bad_pc], AuthenticationRuleConfig())
    assert findings == []


def test_group_membership_lifecycle_uses_member_sid_not_group_target():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    events = [
        event(4720, base, user="ForensicDemo", sid="S-1-5-21-99", computer="WIN-TEST"),
        event(4732, base + timedelta(minutes=1), user="ForensicDemo", sid="S-1-5-21-99", source_ip=None, computer="WIN-TEST", attributes={"MemberSid": "S-1-5-21-99", "MemberName": "ForensicDemo", "TargetUserName": "Administrators"}),
    ]
    findings = reconstruct_account_lifecycles(events)
    assert len(findings) == 1
    assert findings[0].title == "Account activity: ForensicDemo"
    assert any(action["group_name"] == "Administrators" for action in findings[0].metadata["actions"])


def test_group_membership_removal_uses_member_sid_not_group_target():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    events = [
        event(4720, base, user="ForensicDemo", sid="S-1-5-21-99", computer="WIN-TEST"),
        event(4733, base + timedelta(minutes=1), user="ForensicDemo", sid="S-1-5-21-99", source_ip=None, computer="WIN-TEST", attributes={"MemberSid": "S-1-5-21-99", "MemberName": "ForensicDemo", "TargetUserName": "Users"}),
    ]
    findings = reconstruct_account_lifecycles(events)
    assert len(findings) == 1
    assert findings[0].title == "Account activity: ForensicDemo"
    assert any(action["label"] == "Removed from local group" for action in findings[0].metadata["actions"])


def test_group_membership_uses_member_sid_when_member_name_is_dash():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    events = [
        event(4720, base, user="ForensicDemo", sid="S-1-5-21-99", computer="WIN-TEST"),
        event(4732, base + timedelta(minutes=1), user="ForensicDemo", sid="S-1-5-21-99", source_ip=None, computer="WIN-TEST", attributes={"MemberSid": "S-1-5-21-99", "MemberName": "-", "TargetUserName": "Users"}),
    ]
    findings = reconstruct_account_lifecycles(events)
    assert len(findings) == 1
    assert findings[0].title == "Account activity: ForensicDemo"


def test_account_lifecycle_unifies_account_events_for_same_sid():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    events = [
        event(4720, base, user="ForensicDemo", sid="S-1-5-21-99", computer="WIN-TEST"),
        event(4732, base + timedelta(minutes=1), user="ForensicDemo", sid="S-1-5-21-99", computer="WIN-TEST", attributes={"MemberSid": "S-1-5-21-99", "MemberName": "ForensicDemo", "TargetUserName": "Administrators"}),
        event(4624, base + timedelta(minutes=2), user="ForensicDemo", sid="S-1-5-21-99", computer="WIN-TEST"),
        event(4733, base + timedelta(minutes=3), user="ForensicDemo", sid="S-1-5-21-99", computer="WIN-TEST", attributes={"MemberSid": "S-1-5-21-99", "MemberName": "ForensicDemo", "TargetUserName": "Administrators"}),
        event(4726, base + timedelta(minutes=4), user="ForensicDemo", sid="S-1-5-21-99", computer="WIN-TEST"),
    ]
    findings = reconstruct_account_lifecycles(events)
    assert len(findings) == 1
    assert findings[0].title == "Account activity: ForensicDemo"
    assert {action["label"] for action in findings[0].metadata["actions"]} == {"Account created", "Added to local group", "Successful logon", "Removed from local group", "Account deleted"}


def test_registry_resolves_group_account_events():
    for event_id, expected in {
        4720: "User account created",
        4726: "User account deleted",
        4732: "Member added to local security group",
        4733: "Member removed from local security group",
    }.items():
        definition = resolve_event_definition("Microsoft-Windows-Security-Auditing", "Security", event_id)
        assert definition.category == "ACCOUNT"
        assert definition.title == expected


def test_system_activity_uses_provider_specific_keys():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    valid_events = [
        event(6006, base, user=None, sid=None, source_ip=None, computer="WIN-TEST", provider="EventLog", channel="System"),
        event(13, base + timedelta(minutes=1), user=None, sid=None, source_ip=None, computer="WIN-TEST", provider="Microsoft-Windows-Kernel-General", channel="System"),
        event(12, base + timedelta(minutes=2), user=None, sid=None, source_ip=None, computer="WIN-TEST", provider="Microsoft-Windows-Kernel-General", channel="System"),
        event(6005, base + timedelta(minutes=3), user=None, sid=None, source_ip=None, computer="WIN-TEST", provider="EventLog", channel="System"),
        event(12, base + timedelta(minutes=4), user=None, sid=None, source_ip=None, computer="WIN-TEST", provider="Microsoft-Windows-Wininit", channel="System"),
        event(12, base + timedelta(minutes=5), user=None, sid=None, source_ip=None, computer="WIN-TEST", provider="Microsoft-Windows-UserModePowerService", channel="System"),
    ]
    findings = reconstruct_system_activity(valid_events)
    assert len(findings) == 1
    assert set(findings[0].evidence_event_ids) == {valid_events[0].id, valid_events[1].id, valid_events[2].id, valid_events[3].id}
    assert valid_events[4].id not in findings[0].evidence_event_ids
    assert valid_events[5].id not in findings[0].evidence_event_ids


def test_system_lifecycle_rejects_unrelated_provider_event_id_12():
    base = datetime(2026, 9, 20, 10, tzinfo=timezone.utc)
    valid_events = [
        event(6006, base, user=None, sid=None, source_ip=None, computer="WIN-TEST", provider="EventLog", channel="System"),
        event(13, base + timedelta(minutes=1), user=None, sid=None, source_ip=None, computer="WIN-TEST", provider="Microsoft-Windows-Kernel-General", channel="System"),
        event(12, base + timedelta(minutes=2), user=None, sid=None, source_ip=None, computer="WIN-TEST", provider="Microsoft-Windows-Kernel-General", channel="System"),
        event(6005, base + timedelta(minutes=3), user=None, sid=None, source_ip=None, computer="WIN-TEST", provider="EventLog", channel="System"),
    ]
    other_provider_event = event(12, base + timedelta(minutes=4), user=None, sid=None, source_ip=None, computer="WIN-TEST", provider="Microsoft-Windows-Wininit", channel="System")
    findings = reconstruct_system_activity(valid_events + [other_provider_event])
    assert len(findings) == 1
    assert other_provider_event.id not in findings[0].evidence_event_ids
