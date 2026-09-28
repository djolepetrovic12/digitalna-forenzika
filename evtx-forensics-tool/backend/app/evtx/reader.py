from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

try:
    from Evtx.Evtx import Evtx
except ImportError as exc:
    raise RuntimeError("python-evtx is required to read .evtx files") from exc


@dataclass
class RawEvent:
    source_path: str
    record_id: int
    xml: str
    provider: str | None = None
    channel: str | None = None
    computer: str | None = None
    event_id: int | None = None
    timestamp: str | None = None
    version: int | None = None


class EvtxReader:
    def iter_records(self, path: str | Path) -> Iterator[RawEvent]:
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"EVTX file not found: {file_path}")

        with Evtx(file_path.as_posix()) as evtx:
            for record in evtx.records():
                xml = record.xml()
                if xml is None:
                    continue

                yield RawEvent(
                    source_path=file_path.name,
                    record_id=int(record.record_num()),
                    xml=xml,
                )
