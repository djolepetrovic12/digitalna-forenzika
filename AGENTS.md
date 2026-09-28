# AGENTS.md

## Purpose

This repository contains a master's project for offline forensic analysis of Windows Event Log (`.evtx`) files.

The Git repository root also contains the thesis/project document. The application itself lives under:

`evtx-forensics-tool/`

Treat `evtx-forensics-tool/` as the application root.

The software must stay focused on the thesis scope: parse EVTX files, normalize relevant events, build a unified timeline, correlate related records, and reconstruct selected security-relevant activities in a transparent and inspectable way.

## Repository boundaries

- Do not move, rename, rewrite, or otherwise modify the thesis/project Word document unless the user explicitly asks.
- Do not create application source files outside `evtx-forensics-tool/`.
- Do not modify files under `evtx-forensics-tool/.venv/`.
- Do not commit or generate real `.evtx` evidence files into Git.
- Do not commit `node_modules`, local databases, temporary exports, or secrets.
- Prefer small, reviewable changes over broad rewrites.
- Before adding a production dependency, verify that the existing stack cannot reasonably do the job.

## Source of truth

Before substantial work, read:

1. this `AGENTS.md`
2. `evtx-forensics-tool/docs/PROJECT_SPEC.md` if present
3. `evtx-forensics-tool/docs/ARCHITECTURE.md` if present
4. the files directly relevant to the requested task

If implementation behavior and documentation disagree, do not silently choose one. Point out the mismatch and propose the smallest correction.

Keep `AGENTS.md` compact. Put detailed architecture, supported-event definitions, and longer design explanations in `docs/`.

## Core architecture

Preserve this dependency direction:

`EVTX -> reader -> XML extraction -> normalization -> analysis/correlation -> API -> frontend`

The forensic core must be usable without React and without FastAPI.

### Backend layers

Keep responsibilities separate:

- `evtx/reader`: low-level EVTX access through `python-evtx`
- `evtx/parser` / `evtx/normalizer`: convert raw records into stable internal models
- `analysis/` or `correlation/`: pure forensic logic over normalized domain objects
- `services/`: in-memory analysis orchestration
- `api/`: HTTP translation only
- `scripts/`: small developer/manual inspection tools

Do not place forensic logic in FastAPI route handlers.

Do not make core correlation functions depend on HTTP request objects or React-oriented response shapes.

Prefer functions shaped conceptually like:

`NormalizedEvent[] -> Finding[]`
`NormalizedEvent[] -> ReconstructedSession[]`

Analysis rules operate directly on in-memory domain objects.

### Frontend layers

Keep React responsible for presentation and interaction, not forensic interpretation.

Prefer:

- `api/` for HTTP clients
- `types/` for API/domain types
- `components/events/`
- `components/findings/`
- `components/sessions/`
- `components/timeline/`
- `pages/`
- `mocks/` for simple development data

The frontend should display meanings supplied by the backend. It must not independently decide what Event 4624, 4672, etc. mean.

## Domain rules

Use a central `NormalizedEvent` model.

Preserve raw event XML for inspectability.

Do not treat Event ID alone as globally meaningful. Interpret supported events using at least:

- Provider
- Channel
- Event ID

and Version when needed.

Normalize timestamps to timezone-aware UTC internally.

`EventRecordID` is useful for ordering inside one source log, not as a global sequence across different logs.

Prefer SID and Logon ID over display usernames when stronger identifiers are available.

Treat `computer + Logon ID` as the primary key-like correlation pair for a Windows logon session.

Do not equate RDP disconnect with session termination.

Do not interpret Security/System/Application records as proof of malicious intent.

## Correlation rules

Correlation must be explainable.

Every reconstructed relationship or finding should preserve:

- the source events
- why they were connected
- which fields matched
- the time relationship
- whether the relationship is direct or indirect

Direct correlation uses strong shared identifiers such as Logon ID or SID.

Indirect correlation may use combinations such as:

- computer
- username
- source IP
- logon type
- timestamp proximity

Time proximity alone is not sufficient evidence of a strong relationship.

Do not invent statistical probabilities.

If qualitative confidence is used, keep it transparent:

- HIGH: strong direct identifiers agree
- MEDIUM: several indirect fields agree
- LOW: weak/contextual relationship

Correlation confidence is not the same thing as security severity.

## Forensic safeguards

- Never modify imported EVTX evidence.
- Compute and preserve SHA-256 for imported source files.
- Preserve source filename and record identifiers.
- Preserve raw XML.
- Unknown events must not crash ingestion.
- Missing fields are normal and must be handled safely.
- Absence of a log record does not prove an activity did not occur.
- Audit policy and missing/overwritten logs limit conclusions.
- Correlation does not prove causation.
- A reconstructed sequence is not automatically a security incident.
- Findings must link back to the actual source events used.

## Manual inspectability is a first-class requirement

The user must be able to verify each layer without needing the full application.

Maintain small CLI/developer utilities under `backend/scripts/`, for example:

- `inspect_evtx.py`
- `inspect_event.py`
- `analyze_file.py`
- `analyze_case.py`

These should make it easy to answer:

- Can the EVTX file be opened?
- Which Event IDs were found?
- Were important fields normalized correctly?
- Which sessions/findings were reconstructed?
- Which source records support a result?

Keep output readable for a human developer. These scripts are development aids, not a second application.

## Synthetic scenario checks

Keep small synthetic scenarios or unit-test fixtures for core logic. Important scenarios include:

- simple interactive logon/logoff
- two sessions for the same username with different Logon IDs
- repeated 4625 failures
- repeated failures followed by matching 4624 success
- failures followed by an unrelated success that must NOT correlate
- 4720 -> 4732 account/group sequence
- different SIDs that must not be merged
- RDP 4624 type 10 -> 4779 disconnect -> 4778 reconnect -> final logoff
- unexpected shutdown near an otherwise incomplete session
- 4672 by itself not being labeled malicious

Most correlation checks should be possible with programmatically constructed `NormalizedEvent` objects and should not require a real EVTX file.

## Layer-by-layer verification

When implementing a feature, validate at the lowest relevant layer first.

Preferred progression:

1. parser/normalizer output
2. analysis/correlation output
3. FastAPI response
4. React display

Do not debug through the frontend when a lower layer can be checked directly.

For backend API work, preserve FastAPI's interactive API documentation so endpoints can be manually called without React.

For frontend work, simple typed mock objects are encouraged so components can be developed without a running backend.

## Development workflow

For any non-trivial task:

1. Inspect the relevant existing files.
2. State the intended small change.
3. Implement the smallest coherent slice.
4. Run the relevant checks.
5. Report exactly what changed and what was verified.
6. Stop rather than expanding scope without request.

Do not generate the entire project in one pass.

Do not replace working architecture simply because another pattern is fashionable.

Prefer clarity suitable for a master's project over enterprise complexity.

## Testing expectations

Testing is practical and focused, not process-heavy.

Use:

- small unit tests for normalization and correlation logic
- integration tests for EVTX -> normalized event -> analysis -> API response
- manual CLI inspection for real files
- FastAPI interactive docs for API checks
- simple frontend mocks and visual checks
- controlled Windows VM scenarios for end-to-end ground truth

After modifying backend forensic logic, run the narrow relevant tests and at least one representative scenario.

After modifying an API endpoint, verify the endpoint directly.

After modifying frontend behavior, verify it with mock data or the live API as appropriate.

Do not claim something was tested if it was not actually run.

## Supported scope

Core analysis focuses on:

Security:

- 4624
- 4625
- 4634
- 4647
- 4672
- 4720
- 4726
- 4732
- 4733
- 4778
- 4779

System:

- Kernel-General 12
- Kernel-General 13
- EventLog 6005
- EventLog 6006
- 6008
- Kernel-Power 41
- USER32/User32 1074

Application:

- generic normalization, search, timeline context, and raw inspection
- no universal meaning assigned to arbitrary provider-specific Event IDs

Optional events may be added only after the core works and only when they support the thesis.

## Out of scope unless explicitly requested

Do not turn the project into:

- a SIEM
- EDR/antivirus
- live event collector
- remote endpoint agent
- Active Directory investigation platform
- network capture tool
- Registry/browser/memory forensic suite
- malware scanner
- machine-learning detector
- general Sigma engine
- complete Windows Event ID encyclopedia
- manual BinXML implementation
- deleted-record carving/recovery suite
- cloud/multi-user platform

## Dependency policy

Expected stack:

Backend:

- Python 3.12+
- FastAPI
- python-evtx
- Pydantic
- pytest
- standard-library XML or `lxml` if justified

Frontend:

- React
- TypeScript
- Vite
- Tailwind CSS
- shadcn/ui
- TanStack Table
- React Router
- Recharts only where useful
- date-fns if useful

Do not introduce PostgreSQL, Redis, Elasticsearch, Kafka, Docker, Celery, or cloud infrastructure without explicit approval.

## Documentation maintenance

When architecture or behavior changes materially, update the relevant document in `evtx-forensics-tool/docs/`.

Preferred documents:

- `PROJECT_SPEC.md` — product scope and requirements
- `ARCHITECTURE.md` — layers, dependency direction, data flow
- `SUPPORTED_EVENTS.md` — event/provider/channel mappings and extracted fields
- `CORRELATION_RULES.md` — reconstruction logic and limitations
- `MANUAL_TESTING.md` — simple developer verification commands and VM scenarios

Do not duplicate long explanations across all documents. Link between them.

## Definition of a good change

A good change is:

- scoped
- understandable
- independently testable
- consistent with the forensic model
- traceable to evidence
- easy to demonstrate
- easy for the user to inspect manually

When in doubt, choose the simpler design that preserves those properties.
