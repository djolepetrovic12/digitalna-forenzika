from __future__ import annotations

from datetime import datetime

from backend.app.models.domain import Finding, NormalizedEvent

ACCOUNT_EVENTS = {4624, 4720, 4726, 4732, 4733}


def _clean_account_value(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    if not cleaned or cleaned in {"-", "None", "null"}:
        return None
    return cleaned


def _account_key(event: NormalizedEvent) -> tuple[str | None, str | None]:
    if event.event_id in {4732, 4733}:
        member_sid = _clean_account_value(event.attributes.get("MemberSid") or event.attributes.get("MemberSecurityId"))
        if member_sid:
            return member_sid, None
        member_name = _clean_account_value(event.attributes.get("MemberName"))
        if member_name:
            return None, member_name
        return None, None

    account_sid = _clean_account_value(event.target_sid)
    if account_sid:
        return account_sid, None
    account_name = _clean_account_value(event.target_user)
    if account_name:
        return None, account_name
    return None, None


def reconstruct_account_lifecycles(events: list[NormalizedEvent]) -> list[Finding]:
    groups: dict[tuple[str | None, str | None], list[NormalizedEvent]] = {}
    for event in events:
        if event.event_id in ACCOUNT_EVENTS:
            key = _account_key(event)
            if key != (None, None):
                groups.setdefault(key, []).append(event)

    findings: list[Finding] = []
    for (account_sid, _), group in groups.items():
        ordered = sorted(group, key=lambda item: item.timestamp_utc or datetime.min)
        if not any(event.event_id in {4720, 4732, 4733, 4726} for event in ordered):
            continue

        account_name = next(
            (
                _clean_account_value(event.target_user)
                or _clean_account_value(event.attributes.get("MemberName"))
                or _clean_account_value(event.attributes.get("TargetUserName"))
                for event in ordered
                if _clean_account_value(event.target_user) or _clean_account_value(event.attributes.get("MemberName")) or _clean_account_value(event.attributes.get("TargetUserName"))
            ),
            account_sid,
        )
        evidence_ids = [event.id or str(event.record_id) for event in ordered]
        actions = []
        for event in ordered:
            labels = {4720: "Account created", 4732: "Added to local group", 4624: "Successful logon", 4733: "Removed from local group", 4726: "Account deleted"}
            label = labels.get(event.event_id)
            if label:
                group_name = event.group_name or event.attributes.get("TargetUserName") or event.attributes.get("GroupName") or event.attributes.get("Group")
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
