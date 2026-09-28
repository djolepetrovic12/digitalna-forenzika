from __future__ import annotations

from datetime import datetime

from backend.app.analysis.accounts import reconstruct_account_lifecycles
from backend.app.analysis.authentication import AuthenticationRuleConfig, detect_failed_logon_clusters, detect_failed_then_success
from backend.app.analysis.remote_sessions import reconstruct_remote_sessions, remote_sessions_to_findings
from backend.app.analysis.sessions import reconstruct_sessions
from backend.app.analysis.system_activity import attach_shutdown_context, reconstruct_system_activity
from backend.app.models.domain import Finding, NormalizedEvent, ReconstructedSession


def analyze_events(events: list[NormalizedEvent]) -> tuple[list[Finding], list[ReconstructedSession]]:
    ordered = sorted(events, key=lambda event: event.timestamp_utc or datetime.min)
    config = AuthenticationRuleConfig()
    findings = detect_failed_logon_clusters(ordered, config)
    findings.extend(detect_failed_then_success(ordered, config))
    findings.extend(reconstruct_account_lifecycles(ordered))
    remote_sessions = reconstruct_remote_sessions(ordered)
    findings.extend(remote_sessions_to_findings(remote_sessions, ordered))
    findings.extend(reconstruct_system_activity(ordered))
    sessions = reconstruct_sessions(ordered)
    findings = attach_shutdown_context(findings, sessions, ordered)
    return findings, [*sessions, *remote_sessions]
