from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EventDefinition:
    provider: str
    channel: str
    event_id: int
    version: int | None = None
    category: str = "OTHER"
    title: str = "Unknown event"
    extractor: str = "generic"


DEFAULT_EVENT_DEFINITION = EventDefinition(
    provider="UNKNOWN",
    channel="UNKNOWN",
    event_id=0,
    version=None,
    category="OTHER",
    title="Unknown event",
    extractor="generic",
)


EVENT_REGISTRY: dict[tuple[str, str, int], EventDefinition] = {
    ("Microsoft-Windows-Security-Auditing", "Security", 4624): EventDefinition(
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        event_id=4624,
        category="AUTHENTICATION",
        title="Successful logon",
        extractor="security_4624",
    ),
    ("Microsoft-Windows-Security-Auditing", "Security", 4625): EventDefinition(
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        event_id=4625,
        category="AUTHENTICATION",
        title="Failed logon",
        extractor="security_4625",
    ),
    ("Microsoft-Windows-Security-Auditing", "Security", 4634): EventDefinition(
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        event_id=4634,
        category="SESSION",
        title="Logon session ended",
        extractor="security_4634",
    ),
    ("Microsoft-Windows-Security-Auditing", "Security", 4647): EventDefinition(
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        event_id=4647,
        category="SESSION",
        title="User initiated logoff",
        extractor="security_4647",
    ),
    ("Microsoft-Windows-Security-Auditing", "Security", 4672): EventDefinition(
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        event_id=4672,
        category="PRIVILEGE",
        title="Special privileges assigned to new logon",
        extractor="security_4672",
    ),
    ("Microsoft-Windows-Kernel-General", "System", 12): EventDefinition(
        provider="Microsoft-Windows-Kernel-General",
        channel="System",
        event_id=12,
        category="SYSTEM_STARTUP",
        title="Operating system started",
        extractor="system_12",
    ),
    ("Microsoft-Windows-Kernel-General", "System", 13): EventDefinition(
        provider="Microsoft-Windows-Kernel-General",
        channel="System",
        event_id=13,
        category="SYSTEM_SHUTDOWN",
        title="Operating system shutdown",
        extractor="system_13",
    ),
    ("EventLog", "System", 6005): EventDefinition(
        provider="EventLog",
        channel="System",
        event_id=6005,
        category="SYSTEM_STARTUP",
        title="Event Log service started",
        extractor="system_6005",
    ),
    ("EventLog", "System", 6006): EventDefinition(
        provider="EventLog",
        channel="System",
        event_id=6006,
        category="SYSTEM_SHUTDOWN",
        title="Event Log service stopped",
        extractor="system_6006",
    ),
    ("EventLog", "System", 6008): EventDefinition(
        provider="EventLog",
        channel="System",
        event_id=6008,
        category="SYSTEM_SHUTDOWN",
        title="Previous shutdown was unexpected",
        extractor="system_6008",
    ),
    ("Microsoft-Windows-Kernel-Power", "System", 41): EventDefinition(
        provider="Microsoft-Windows-Kernel-Power",
        channel="System",
        event_id=41,
        category="SYSTEM_SHUTDOWN",
        title="System shutdown/restart was unexpected",
        extractor="system_41",
    ),
    ("USER32", "System", 1074): EventDefinition(
        provider="USER32",
        channel="System",
        event_id=1074,
        category="SYSTEM_SHUTDOWN",
        title="User initiated shutdown or restart",
        extractor="system_1074",
    ),
}


def resolve_event_definition(provider: str | None, channel: str | None, event_id: int | None, version: int | None = None) -> EventDefinition:
    if provider is None or channel is None or event_id is None:
        return DEFAULT_EVENT_DEFINITION

    match = EVENT_REGISTRY.get((provider, channel, event_id))
    if match is not None:
        return match

    return EventDefinition(
        provider=provider,
        channel=channel,
        event_id=event_id,
        version=version,
        category="OTHER",
        title=f"Unknown {provider} event {event_id}",
        extractor="generic",
    )
