from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from backend.app.analysis.engine import analyze_events
from backend.app.evtx.normalizer import normalize_event
from backend.app.evtx.reader import EvtxReader
from backend.app.models.domain import Finding, NormalizedEvent, ReconstructedSession


@dataclass
class AnalyzedFile:
    filename: str
    sha256: str
    file_size: int
    record_count: int


@dataclass
class EvtxAnalysisResult:
    filename: str
    files: list[AnalyzedFile]
    events: list[NormalizedEvent]
    findings: list[Finding]
    sessions: list[ReconstructedSession]
    providers: list[str]
    channels: list[str]
    event_id_counts: dict[str, int]


def analyze_evtx_files(files: list[tuple[Path, str, str, int]]) -> EvtxAnalysisResult:
    events: list[NormalizedEvent] = []
    analyzed_files: list[AnalyzedFile] = []

    for file_index, (path, filename, sha256, file_size) in enumerate(files):
        file_events: list[NormalizedEvent] = []
        for record in EvtxReader().iter_records(path):
            normalized = normalize_event(
                record.xml,
                source_filename=filename,
                record_id=record.record_id,
            )
            normalized.id = f"{file_index}-{sha256[:12]}-{record.record_id}"
            file_events.append(normalized)

        events.extend(file_events)
        analyzed_files.append(
            AnalyzedFile(
                filename=filename,
                sha256=sha256,
                file_size=file_size,
                record_count=len(file_events),
            )
        )

    ordered_events = sorted(events, key=lambda event: event.timestamp_utc or datetime.min)
    findings, sessions = analyze_events(ordered_events)

    return EvtxAnalysisResult(
        filename=", ".join(file.filename for file in analyzed_files),
        files=analyzed_files,
        events=ordered_events,
        findings=findings,
        sessions=sessions,
        providers=sorted({event.provider for event in ordered_events if event.provider}),
        channels=sorted({event.channel for event in ordered_events if event.channel}),
        event_id_counts={
            str(event_id): count
            for event_id, count in sorted(
                Counter(event.event_id for event in ordered_events if event.event_id is not None).items()
            )
        },
    )