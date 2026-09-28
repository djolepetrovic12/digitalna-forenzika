from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from backend.app.models.domain import CorrelationEvidence, Finding, NormalizedEvent


@dataclass
class AuthenticationRuleConfig:
    failed_attempt_threshold: int = 4
    failed_attempt_window_minutes: int = 5
    success_match_window_minutes: int = 10


def detect_failed_logon_clusters(events: list[NormalizedEvent], config: AuthenticationRuleConfig) -> list[Finding]:
    failed = [event for event in events if event.event_id == 4625]
    findings: list[Finding] = []

    if not failed:
        return findings

    grouped: dict[tuple[str | None, str | None, str | None], list[NormalizedEvent]] = {}
    for event in failed:
        key = (event.computer, event.target_user, event.source_ip)
        grouped.setdefault(key, []).append(event)

    for (computer, target_user, source_ip), cluster in grouped.items():
        cluster = sorted(cluster, key=lambda item: item.timestamp_utc or datetime.min)
        if len(cluster) < config.failed_attempt_threshold:
            continue

        window_start = cluster[0].timestamp_utc
        window_end = cluster[-1].timestamp_utc
        if window_start is None or window_end is None:
            continue

        if window_end - window_start <= timedelta(minutes=config.failed_attempt_window_minutes):
            findings.append(
                Finding(
                    id=f"failed-{computer}-{target_user}-{source_ip}",
                    type="FAILED_LOGON_CLUSTER",
                    title="Repeated failed logon attempts",
                    summary=f"{len(cluster)} failed logon attempts for account {target_user} from {source_ip or 'an unknown source'} were recorded within {int((window_end - window_start).total_seconds())} seconds.",
                    start_time=window_start,
                    end_time=window_end,
                    correlation_type="indirect",
                    confidence="MEDIUM",
                    metadata={
                        "matched_fields": ["computer", "target_user", "source_ip", "time_window"],
                        "event_ids": [event.record_id for event in cluster],
                    },
                    evidence_event_ids=[event.id or str(event.record_id) for event in cluster],
                )
            )

    return findings


def detect_failed_then_success(events: list[NormalizedEvent], config: AuthenticationRuleConfig) -> list[Finding]:
    findings: list[Finding] = []
    failed_clusters = detect_failed_logon_clusters(events, config)

    successful = [event for event in events if event.event_id == 4624]
    for cluster in failed_clusters:
        failed_events = [event for event in events if event.event_id == 4625 and cluster.start_time and event.timestamp_utc and cluster.start_time <= event.timestamp_utc <= cluster.end_time]
        if not failed_events:
            continue

        for success in successful:
            if success.timestamp_utc is None or cluster.end_time is None:
                continue
            if success.timestamp_utc < cluster.end_time:
                continue
            if success.timestamp_utc - cluster.end_time > timedelta(minutes=config.success_match_window_minutes):
                continue

            if success.computer != failed_events[0].computer:
                continue
            if success.target_user != failed_events[0].target_user:
                continue
            if success.target_sid and failed_events[0].target_sid and success.target_sid != failed_events[0].target_sid:
                continue
            if success.source_ip and failed_events[0].source_ip and success.source_ip != failed_events[0].source_ip:
                continue

            evidence = CorrelationEvidence(
                type="indirect",
                matched_fields=["computer", "target_user", "source_ip", "time_window"],
                time_difference=f"{int((success.timestamp_utc - cluster.end_time).total_seconds())}s",
                notes="Failed attempts cluster matched a later successful logon with shared account and source context.",
                confidence="MEDIUM",
            )

            findings.append(
                Finding(
                    id=f"failed-success-{success.record_id}",
                    type="FAILED_LOGON_THEN_SUCCESS",
                    title="Repeated failed logons followed by successful logon",
                    summary=f"A failed logon pattern for {success.target_user} was followed by a successful logon on {success.computer} within the configured time window.",
                    start_time=cluster.start_time,
                    end_time=success.timestamp_utc,
                    correlation_type="indirect",
                    confidence="MEDIUM",
                    metadata={
                        "evidence": evidence,
                        "event_ids": [event.record_id for event in failed_events] + [success.record_id],
                    },
                    evidence_event_ids=[event.id or str(event.record_id) for event in failed_events] + [success.id or str(success.record_id)],
                )
            )
            break

    return findings
