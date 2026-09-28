from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from backend.app.models.domain import NormalizedEvent
from backend.app.schemas.api import AnalyzedFileResponse, EventResponse, EvtxAnalysisResponse, FindingResponse, SessionResponse
from backend.app.services.evtx_analysis_service import EvtxAnalysisResult, analyze_evtx_files

app = FastAPI(title="Windows Event Log Forensic Analyzer", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_UPLOAD_SIZE = 512 * 1024 * 1024


def to_event_response(event: NormalizedEvent) -> EventResponse:
    return EventResponse(
        id=event.id or event.record_id or "unknown-event",
        source_filename=event.source_filename,
        timestamp_utc=event.timestamp_utc,
        record_id=event.record_id,
        provider=event.provider,
        channel=event.channel,
        event_id=event.event_id,
        version=event.version,
        computer=event.computer,
        level=event.level,
        category=event.category,
        title=event.title,
        subject_user=event.subject_user,
        subject_domain=event.subject_domain,
        subject_sid=event.subject_sid,
        target_user=event.target_user,
        target_domain=event.target_domain,
        target_sid=event.target_sid,
        logon_id=event.logon_id,
        logon_type=event.logon_type,
        logon_type_name=event.logon_type_name,
        source_ip=event.source_ip,
        source_host=event.source_host,
        status=event.status,
        sub_status=event.sub_status,
        group_name=event.group_name,
        group_sid=event.group_sid,
        attributes=event.attributes,
        raw_xml=event.raw_xml,
    )


def to_analysis_response(result: EvtxAnalysisResult) -> EvtxAnalysisResponse:
    return EvtxAnalysisResponse(
        filename=result.filename,
        record_count=len(result.events),
        files=[AnalyzedFileResponse(**item.__dict__) for item in result.files],
        providers=result.providers,
        channels=result.channels,
        event_id_counts=result.event_id_counts,
        events=[to_event_response(event) for event in result.events],
        findings=[FindingResponse(**finding.__dict__) for finding in result.findings],
        sessions=[SessionResponse(**session.__dict__) for session in result.sessions],
    )


@app.post("/api/analyze/evtx", response_model=EvtxAnalysisResponse)
async def analyze_uploaded_evtx(
    files: list[UploadFile] | None = File(default=None),
    file: UploadFile | None = File(default=None),
):
    uploads = files or ([file] if file is not None else [])
    if not uploads:
        raise HTTPException(status_code=400, detail="At least one EVTX file is required")

    temporary_paths: list[tuple[Path, str, str, int]] = []
    paths_to_remove: list[Path] = []
    try:
        for upload in uploads:
            filename = upload.filename or "uploaded.evtx"
            if not filename.lower().endswith(".evtx"):
                raise HTTPException(status_code=400, detail="Only .evtx files are supported")

            digest = hashlib.sha256()
            file_size = 0
            with tempfile.NamedTemporaryFile(prefix="evtx-analysis-", suffix=".evtx", delete=False) as temporary_file:
                temporary_path = Path(temporary_file.name)
                paths_to_remove.append(temporary_path)
                while chunk := await upload.read(1024 * 1024):
                    file_size += len(chunk)
                    if file_size > MAX_UPLOAD_SIZE:
                        raise HTTPException(status_code=413, detail=f"{filename} exceeds the 512 MB upload limit")
                    digest.update(chunk)
                    temporary_file.write(chunk)
            temporary_paths.append((temporary_path, filename, digest.hexdigest(), file_size))

        result = analyze_evtx_files(temporary_paths)
        return to_analysis_response(result)
    except HTTPException:
        raise
    except FileNotFoundError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Unable to parse EVTX file: {exc}") from exc
    finally:
        for upload in uploads:
            await upload.close()
        for temporary_path in paths_to_remove:
            temporary_path.unlink(missing_ok=True)
