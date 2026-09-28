from __future__ import annotations

import argparse
from pathlib import Path

from backend.app.evtx.reader import EvtxReader
from backend.app.evtx.normalizer import normalize_event


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect a normalized event from an EVTX file.")
    parser.add_argument("path", type=Path, help="Path to an EVTX file")
    parser.add_argument("--event-id", type=int, default=4624, help="Event ID to inspect")
    parser.add_argument("--limit", type=int, default=3, help="How many matching records to display")
    args = parser.parse_args()

    reader = EvtxReader()
    count = 0
    for record in reader.iter_records(args.path):
        if record.xml is None:
            continue
        normalized = normalize_event(record.xml, record_id=record.record_id)
        if normalized.event_id != args.event_id:
            continue

        print(f"Event ID:      {normalized.event_id}")
        print(f"Record ID:     {normalized.record_id}")
        print(f"Timestamp UTC: {normalized.timestamp_utc.isoformat() if normalized.timestamp_utc else 'N/A'}")
        print(f"Provider:      {normalized.provider}")
        print(f"Channel:       {normalized.channel}")
        print(f"Computer:      {normalized.computer}")
        print(f"User:          {normalized.target_user or normalized.subject_user or 'N/A'}")
        print(f"SID:           {normalized.target_sid or normalized.subject_sid or 'N/A'}")
        print(f"Logon ID:      {normalized.logon_id or 'N/A'}")
        print(f"Logon Type:    {normalized.logon_type_name or normalized.logon_type or 'N/A'}")
        print(f"Source IP:     {normalized.source_ip or 'N/A'}")
        print("---")
        count += 1
        if count >= args.limit:
            break

    if count == 0:
        print(f"No events found for Event ID {args.event_id} in {args.path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
