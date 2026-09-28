from __future__ import annotations

from datetime import datetime, timedelta

from backend.app.models.domain import Finding, NormalizedEvent

ACCOUNT_EVENTS = {4624, 4720, 4726, 4732, 4733}


def _account_key(event: NormalizedEvent) -> tuple[str | None, str | None]:
    member_sid = event.attributes.get("MemberSid") or event.attributes.get("MemberSecurityId")
    return (event.target_sid or member_sid, event.target_user or event.attributes.get("MemberName"))


def reconstruct_account_lifecycles(events: list[NormalizedEvent]) -> list[Finding]:
    groups: dict[tuple[str | None, str | None], list[NormalizedEvent]] = {}
    for event in events:
        if event.event_id in ACCOUNT_EVENTS:
            key = _account_key(event)
            if key != (None, None):
                groups.setdefault(key, []).append(event)

    findings: list[Finding] = []
    for (account_sid, account_name), group in groups.items():
        ordered = sorted(group, key=lambda item: item.timestamp_utc or datetime.min)
        if not any(event.event_id in {4720, 4732, 4733, 4726} for event in ordered):
            continue
        evidence_ids = [event.id or str(event.record_id) for event in ordered]
        actions = []
        for event in ordered:
            labels = {4720: "Account created", 4732: "Added to local group", 4624: "Successful logon", 4733: "Removed from local group", 4726: "Account deleted"}
            label = labels.get(event.event_id)
            if label:
                group_name = event.group_name or event.attributes.get("TargetUserName") or event.attributes.get("GroupName")
                actions.append({"event_id": event.event_id, "label": label, "group_name": group_name, "record_id": event.record_id})

        matched_fields = ["target_sid"] if account_sid else ["target_user"]
        findings.append(
            Finding(
                id=f"account-{account_sid or account_name}-{ordered[0].id or ordered[0].record_id}",
                type="ACCOUNT_LIFECYCLE",
                title=f"Account activity: {account_name or account_sid or 'unknown account'}",
                summary=f"{len(actions)} account lifecycle events were observed for {account_name or account_sid or 'an unknown account'}.",
                start_time=ordered[0].timestamp_utc,
                end_time=ordered[-1].timestamp_utc,
                correlation_type="direct" if account_sid else "indirect",
                confidence="HIGH" if account_sid else "MEDIUM",
                metadata={"account_sid": account_sid, "account_name": account_name, "actions": actions, "matched_fields": matched_fields},
                evidence_event_ids=evidence_ids,
            )
        )
    return findings
