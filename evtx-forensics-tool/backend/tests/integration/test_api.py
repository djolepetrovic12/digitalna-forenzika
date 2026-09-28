from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def _sample_evtx_path() -> Path:
    return Path(__file__).resolve().parents[3] / "bits_openvpn.evtx"


def test_analyze_evtx_upload_in_memory():
    sample_path = _sample_evtx_path()
    if not sample_path.exists():
        return

    response = client.post(
        "/api/analyze/evtx",
        files={"file": (sample_path.name, sample_path.read_bytes(), "application/octet-stream")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["record_count"] == 1537
    assert body["event_id_counts"]["61"] == 492
    assert body["findings"] == []
    assert body["sessions"] == []
    assert body["files"][0]["filename"] == sample_path.name
    assert body["files"][0]["record_count"] == 1537


def test_analyze_multiple_evtx_files_together():
    sample_path = _sample_evtx_path()
    if not sample_path.exists():
        return

    content = sample_path.read_bytes()
    response = client.post(
        "/api/analyze/evtx",
        files=[
            ("files", ("Security.evtx", content, "application/octet-stream")),
            ("files", ("Application.evtx", content, "application/octet-stream")),
        ],
    )

    assert response.status_code == 200
    body = response.json()
    assert body["record_count"] == 3074
    assert [item["filename"] for item in body["files"]] == ["Security.evtx", "Application.evtx"]
    assert body["event_id_counts"]["61"] == 984


def test_analyze_evtx_rejects_non_evtx_upload():
    response = client.post(
        "/api/analyze/evtx",
        files={"file": ("notes.txt", b"not an evtx file", "text/plain")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Only .evtx files are supported"


def test_case_persistence_routes_are_not_exposed():
    response = client.get("/api/cases")

    assert response.status_code == 404