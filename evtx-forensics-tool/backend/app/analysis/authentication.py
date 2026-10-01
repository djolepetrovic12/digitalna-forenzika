from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from backend.app.models.domain import CorrelationEvidence, Finding, NormalizedEvent


@dataclass
class AuthenticationRuleConfig:
    failed_attempt_threshold: int = 4
    failed_attempt_window_minutes: int = 5
    success_match_window_minutes: int = 10


def _normalize_account_name(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    if not cleaned or cleaned in {"-", "None", "null"}:
        return None
    return cleaned


def _normalize_context_value(value: str | int | None) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    if not cleaned or cleaned in {"-", "None", "null", "NULL"}:
        return None
    return cleaned.lower()


def _anonymous_authentication_context(event: NormalizedEvent) -> tuple[str | None, str | None, int | None, str | None, str | None, str | None, str | None] | None:
    if event.target_user is not None:
        return None

    activity_id = _normalize_context_value(event.activity_id)
    if activity_id is None:
        return None

    logon_process_name = _normalize_context_value(event.attributes.get("LogonProcessName"))
    auth_package = _normalize_context_value(event.attributes.get("AuthenticationPackageName"))
    process_name = _normalize_context_value(event.attributes.get("ProcessName"))
    source_ip = _normalize_context_value(event.source_ip)
    return (event.computer, activity_id, event.logon_type, logon_process_name, auth_package, process_name, source_ip)


def same_authentication_context(failed_event: NormalizedEvent, candidate_event: NormalizedEvent) -> bool:
    if failed_event.computer != candidate_event.computer:
        return False

    if _normalize_context_value(failed_event.activity_id) != _normalize_context_value(candidate_event.activity_id):
        return False

    failed_logon_process = _normalize_context_value(failed_event.attributes.get("LogonProcessName"))
    candidate_logon_process = _normalize_context_value(candidate_event.attributes.get("LogonProcessName"))
    if failed_logon_process and candidate_logon_process and failed_logon_process != candidate_logon_process:
        return False

    failed_auth_package = _normalize_context_value(failed_event.attributes.get("AuthenticationPackageName"))
    candidate_auth_package = _normalize_context_value(candidate_event.attributes.get("AuthenticationPackageName"))
    if failed_auth_package and candidate_auth_package and failed_auth_package != candidate_auth_package:
        return False

    failed_process_name = _normalize_context_value(failed_event.attributes.get("ProcessName"))
    candidate_process_name = _normalize_context_value(candidate_event.attributes.get("ProcessName"))
    if failed_process_name and candidate_process_name and failed_process_name != candidate_process_name:
        return False

    failed_ip = _normalize_context_value(failed_event.source_ip)
    candidate_ip = _normalize_context_value(candidate_event.source_ip)
    if failed_ip and candidate_ip and failed_ip != candidate_ip:
        return False

    return True


def _failed_logon_cluster_key(event: NormalizedEvent) -> tuple[str | None, str | None, int | None, str | None, str | None, str | None, str | None] | None:
    target_user = _normalize_account_name(event.target_user)
    if target_user is not None:
        source_ip = event.source_ip.strip() if isinstance(event.source_ip, str) else event.source_ip
        if source_ip in {None, "-", "", "unknown", "Unknown"}:
            source_ip = None
        return (event.computer, target_user, None, None, None, None, source_ip)

    anonymous_context = _anonymous_authentication_context(event)
    if anonymous_context is not None:
        return anonymous_context

    return None


def _cluster_matched_fields(cluster_key: tuple[str | None, str | None, int | None, str | None, str | None, str | None, str | None], *, activity_based: bool) -> list[str]:
    if activity_based:
        fields = ["computer", "activity_id"]
        if cluster_key[6] is not None:
            fields.append("source_ip")
        fields.append("time_window")
        return fields

    fields = ["computer", "target_user"]
    if cluster_key[6] is not None:
        fields.append("source_ip")
    fields.append("time_window")
    return fields


def detect_failed_logon_clusters(events: list[NormalizedEvent], config: AuthenticationRuleConfig) -> list[Finding]:
    failed_events = [event for event in events if event.event_id == 4625]
    if not failed_events:
        return []

    grouped: dict[tuple[str | None, str | None, str | None], list[NormalizedEvent]] = {}
    for event in failed_events:
        key = _failed_logon_cluster_key(event)
        if key is not None:
            grouped.setdefault(key, []).append(event)

    findings: list[Finding] = []
    for key, cluster in grouped.items():
        ordered = sorted(cluster, key=lambda item: item.timestamp_utc or datetime.min)
        if len(ordered) < config.failed_attempt_threshold:
            continue

        activity_based = any(event.target_user is None for event in ordered) and any(event.activity_id is not None for event in ordered)
        if activity_based:
            activity_id = _normalize_context_value(ordered[0].activity_id)
            source_ip = _normalize_context_value(ordered[0].source_ip)
            context = _anonymous_authentication_context(ordered[0])
            if context is None:
                continue
            target_user = None
            logon_type = context[2]
            logon_process_name = context[3]
            auth_package = context[4]
            process_name = context[5]
        else:
            target_user = _normalize_account_name(ordered[0].target_user)
            activity_id = None
            source_ip = _normalize_context_value(ordered[0].source_ip)
            logon_type = None
            logon_process_name = None
            auth_package = None
            process_name = None

        computer = ordered[0].computer
        start_index = 0
        while start_index < len(ordered):
            end_index = start_index
            start_time = ordered[start_index].timestamp_utc
            if start_time is None:
                start_index += 1
                continue

            while end_index + 1 < len(ordered):
                next_time = ordered[end_index + 1].timestamp_utc
                if next_time is None:
                    break
                if next_time - start_time > timedelta(minutes=config.failed_attempt_window_minutes):
                    break
                end_index += 1

            window_events = ordered[start_index:end_index + 1]
            if len(window_events) >= config.failed_attempt_threshold:
                window_start = window_events[0].timestamp_utc
                window_end = window_events[-1].timestamp_utc
                if window_start is None or window_end is None:
                    start_index += 1
                    continue

                evidence_ids = [event.id or str(event.record_id) for event in window_events]
                matched_fields = _cluster_matched_fields(key, activity_based=activity_based)
                if activity_based:
                    summary = f"{len(window_events)} related failed logon attempts were recorded within {int((window_end - window_start).total_seconds())} seconds."
                    title = "Repeated failed logon attempts"
                    event_label = "Unknown account"
                    correlation_info = {
                        "activity_id": activity_id,
                        "source_ip": source_ip,
                        "logon_type": logon_type,
                        "logon_process_name": logon_process_name,
                        "authentication_package_name": auth_package,
                        "process_name": process_name,
                    }
                else:
                    summary = f"{len(window_events)} failed logon attempts for account {target_user} from {source_ip or 'an unknown source'} were recorded within {int((window_end - window_start).total_seconds())} seconds."
                    title = "Repeated failed logon attempts"
                    event_label = target_user
                    correlation_info = {"target_user": target_user, "source_ip": source_ip}

                findings.append(
                    Finding(
                        id=f"failed-{computer}-{target_user or activity_id or 'unknown'}-{source_ip or 'unknown'}-{window_start.isoformat()}-{window_end.isoformat()}",
                        type="FAILED_LOGON_CLUSTER",
                        title=title,
                        summary=summary,
                        start_time=window_start,
                        end_time=window_end,
                        correlation_type="indirect",
                        confidence="MEDIUM",
                        metadata={
                            "matched_fields": matched_fields,
                            "event_ids": evidence_ids,
                            "computer": ordered[0].computer,
                            "target_user": target_user,
                            "activity_id": activity_id,
                            "source_ip": source_ip,
                            "correlation": "activity_id" if activity_based else "target_user",
                            "event_label": event_label,
                            "authentication_context": {
                                "computer": ordered[0].computer,
                                "activity_id": activity_id,
                                "logon_type": logon_type,
                                "logon_process_name": logon_process_name,
                                "authentication_package_name": auth_package,
                                "process_name": process_name,
                                "source_ip": source_ip,
                            },
                            **correlation_info,
                        },
                        evidence_event_ids=evidence_ids,
                    )
                )
                start_index = end_index + 1
                continue

            start_index += 1

    return findings


def detect_failed_then_success(events: list[NormalizedEvent], config: AuthenticationRuleConfig) -> list[Finding]:
    findings: list[Finding] = []
    successful = [event for event in events if event.event_id == 4624]

    for cluster in detect_failed_logon_clusters(events, config):
        failed_event_ids = {str(item) for item in cluster.metadata.get("event_ids", [])}
        failed_events = [
            event for event in events
            if event.event_id == 4625 and (event.id or str(event.record_id)) in failed_event_ids
        ]
        if not failed_events:
            continue

        cluster_start = cluster.start_time
        cluster_end = cluster.end_time
        if cluster_start is None or cluster_end is None:
            continue

        for success in successful:
            if success.timestamp_utc is None:
                continue
            if success.timestamp_utc <= cluster_end:
                continue
            if success.timestamp_utc - cluster_end > timedelta(minutes=config.success_match_window_minutes):
                continue

            if success.computer != failed_events[0].computer:
                continue

            failed_user = _normalize_account_name(failed_events[0].target_user)
            success_user = _normalize_account_name(success.target_user)

            if cluster.metadata.get("correlation") == "activity_id":
                if not same_authentication_context(failed_events[0], success):
                    continue
                matched_fields = ["computer", "activity_id", "time_window"]
                if success.source_ip and failed_events[0].source_ip:
                    matched_fields.append("source_ip")
                summary_user = success_user or "Unknown account"
                evidence = CorrelationEvidence(
                    type="indirect",
                    matched_fields=matched_fields,
                    time_difference=f"{int((success.timestamp_utc - cluster_end).total_seconds())}s",
                    notes="Failed attempts cluster matched a later successful logon with the same Windows ActivityID and broader authentication context.",
                    confidence="MEDIUM",
                )
                findings.append(
                    Finding(
                        id=f"failed-success-{success.record_id}",
                        type="FAILED_LOGON_THEN_SUCCESS",
                        title="Repeated failed logons followed by successful logon",
                        summary=f"A failed logon pattern was followed by a successful logon for {summary_user} on {success.computer} within the configured time window.",
                        start_time=cluster_start,
                        end_time=success.timestamp_utc,
                        correlation_type="indirect",
                        confidence="MEDIUM",
                        metadata={
                            "evidence": evidence,
                            "event_ids": [event.id or str(event.record_id) for event in failed_events] + [success.id or str(success.record_id)],
                            "matched_fields": matched_fields,
                            "activity_id": cluster.metadata.get("activity_id"),
                            "authentication_context": cluster.metadata.get("authentication_context"),
                        },
                        evidence_event_ids=[event.id or str(event.record_id) for event in failed_events] + [success.id or str(success.record_id)],
                    )
                )
                break

            if failed_user is None or success_user is None or failed_user != success_user:
                continue

            if success.target_sid and failed_events[0].target_sid and failed_events[0].target_sid not in {None, "S-1-0-0"} and success.target_sid != failed_events[0].target_sid:
                continue
            if success.source_ip and failed_events[0].source_ip and success.source_ip != failed_events[0].source_ip:
                continue

            matched_fields = ["computer", "target_user"]
            if success.target_sid and failed_events[0].target_sid and failed_events[0].target_sid not in {None, "S-1-0-0"}:
                matched_fields.append("target_sid")
            if success.source_ip and failed_events[0].source_ip:
                matched_fields.append("source_ip")
            matched_fields.append("time_window")

            evidence = CorrelationEvidence(
                type="indirect",
                matched_fields=matched_fields,
                time_difference=f"{int((success.timestamp_utc - cluster_end).total_seconds())}s",
                notes="Failed attempts cluster matched a later successful logon with shared account and source context.",
                confidence="MEDIUM",
            )

            findings.append(
                Finding(
                    id=f"failed-success-{success.record_id}",
                    type="FAILED_LOGON_THEN_SUCCESS",
                    title="Repeated failed logons followed by successful logon",
                    summary=f"A failed logon pattern for {success_user} was followed by a successful logon on {success.computer} within the configured time window.",
                    start_time=cluster_start,
                    end_time=success.timestamp_utc,
                    correlation_type="indirect",
                    confidence="MEDIUM",
                    metadata={
                        "evidence": evidence,
                        "event_ids": [event.id or str(event.record_id) for event in failed_events] + [success.id or str(success.record_id)],
                        "matched_fields": matched_fields,
                    },
                    evidence_event_ids=[event.id or str(event.record_id) for event in failed_events] + [success.id or str(success.record_id)],
                )
            )
            break

    return findings
