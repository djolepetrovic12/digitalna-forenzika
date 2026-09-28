from datetime import datetime, timezone

from backend.app.evtx.normalizer import normalize_event, normalize_timestamp_utc


REALISTIC_EVENT_XML = '''
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
    <EventID>4624</EventID>
    <Version>1</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-09-20T00:41:21.0000000Z" />
    <EventRecordID>18551</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WIN-TEST</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-1111</Data>
    <Data Name="TargetUserName">testuser</Data>
    <Data Name="TargetDomainName">WIN-TEST</Data>
    <Data Name="TargetLogonId">0x41d92</Data>
    <Data Name="LogonType">2</Data>
    <Data Name="IpAddress">-</Data>
    <Data Name="WorkstationName">WIN-TEST</Data>
  </EventData>
</Event>
'''.strip()


def test_normalize_timestamp_utc_accepts_iso_string():
    dt = normalize_timestamp_utc("2026-09-20T00:41:21Z")
    assert dt is not None
    assert dt.tzinfo == timezone.utc
    assert dt.isoformat() == "2026-09-20T00:41:21+00:00"


def test_normalize_timestamp_utc_handles_naive_values():
    dt = normalize_timestamp_utc("2026-09-20T00:41:21")
    assert dt is not None
    assert dt.tzinfo == timezone.utc


def test_normalize_timestamp_utc_handles_missing_values():
    assert normalize_timestamp_utc(None) is None


def test_normalize_event_reads_windows_xml_attribute_fields():
    normalized = normalize_event(REALISTIC_EVENT_XML)

    assert normalized.provider == "Microsoft-Windows-Security-Auditing"
    assert normalized.channel == "Security"
    assert normalized.event_id == 4624
    assert normalized.computer == "WIN-TEST"
    assert normalized.target_user == "testuser"
    assert normalized.logon_id == "0x41d92"
    assert normalized.logon_type == 2
    assert normalized.logon_type_name == "Interactive"
    assert normalized.source_ip is None
    assert normalized.timestamp_utc is not None
