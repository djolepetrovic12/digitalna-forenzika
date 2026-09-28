from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from backend.app.evtx.reader import EvtxReader


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect an EVTX file and summarize basic record metadata.")
    parser.add_argument("path", type=Path, help="Path to an EVTX file")
    args = parser.parse_args()

    path = args.path
    if not path.exists():
        raise SystemExit(f"File not found: {path}")

    reader = EvtxReader()
    counts: Counter[int] = Counter()
    seen = 0
    try:
        for record in reader.iter_records(path):
            seen += 1
            counts[record.record_id] += 1
    except Exception as exc:  # pragma: no cover
        raise SystemExit(f"Failed to parse EVTX: {exc}") from exc

    print(f"File: {path.name}")
    print(f"Records found: {seen}")
    print(f"Unique record IDs: {len(counts)}")
    print("--")
    print("This is the first proof-of-concept evtx reader boundary.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
