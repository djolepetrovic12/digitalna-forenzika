from __future__ import annotations

import argparse
from pathlib import Path

from backend.app.evtx.extractors import extract_generic_fields


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse a synthetic or real EVTX-like XML file and summarize normalized event structure.")
    parser.add_argument("path", type=Path, help="Path to an XML file or EVTX file")
    args = parser.parse_args()

    xml_text = args.path.read_text(encoding="utf-8", errors="replace")
    records = extract_generic_fields(xml_text)
    print(f"File: {args.path}")
    print(f"System keys: {list(records.get('system', {}).keys())}")
    print(f"EventData keys: {list(records.get('event_data', {}).keys())}")
    print("Synthetic XML parse completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
