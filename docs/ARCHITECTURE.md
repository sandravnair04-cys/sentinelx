# SENTINELX — System architecture

This document describes the as-built system. It complements the high-level diagrams in the root `README.md`.

## 1. Component view

| Component | Location | Responsibility |
| --- | --- | --- |
| Central API | `app/main.py`, `app/api/` | FastAPI application, security headers, RBAC middleware, REST surface |
| Ingestion gateway | `app/ingestion/` | Agent credential auth, normalisation, per-agent idempotency, endpoint/forwarder registry |
| Collectors/parsers | `app/collectors/` | Windows/Linux/Wazuh text parsing and event persistence |
| Detection | `app/detection/` | Built-in rules, Sigma-compatible subset, MITRE mapping |
| Correlation | `app/correlation/` | Event clustering and incident creation |
| Risk engine | `app/risk/` | Deterministic 0–100 explainable scoring |
| Agents | `app/agents/` | Six LangGraph nodes, structured outputs, approval interrupt |
| Response | `app/api/routes/response.py` | Recommendations, human decisions, simulated execution, audit |
| Reports | `app/reports/`, `app/api/routes/reports.py` | PDF and JSON exports |
| Threat intel | `app/threat_intel/` | Optional VirusTotal/AbuseIPDB with cache |
| Storage | `app/models.py`, `app/database.py` | SQLAlchemy models (SQLite dev / PostgreSQL prod) |
| SXUF forwarder | `forwarder/sxuf/` | Standalone endpoint agent (Windows/Linux) |
| React dashboard | `frontend/src/` | 14-page SOC UI (TypeScript, Tailwind, Recharts, Lucide) |

## 2. Data flow

1. **Collect.** SXUF tails only configured sources. File collectors persist byte offsets; journald uses cursors; Windows uses record IDs. Checkpoints advance only after server acknowledgement.
2. **Buffer.** Events are written to a disk-backed JSONL queue (`state/buffer.jsonl`). A SQLite ledger (`state/dedupe.sqlite3`) claims client event IDs so restarts never re-send.
3. **Authenticate.** Forwarder presents `X-Agent-ID` + `X-Agent-Key`. Server stores only SHA-256 of the key, checks status/expiry/scope, and rate-limits failures (10 per minute per IP+agent).
4. **Ingest.** `POST /api/ingest/batch` normalises each event into the common schema, maps severity/event type/action, computes a stable `event_uid` from `(agent_id, event_id)`, and writes an `IngestReceipt`. Duplicates are acknowledged, not re-inserted.
5. **Register.** Each batch/heartbeat upserts `Endpoint` and `Forwarder` rows; stale heartbeats mark them offline.
6. **Detect / correlate / score.** With `AUTO_PROCESS_FORWARDED=true` (default), every accepted forwarded batch immediately runs detection and correlation — a Splunk-like continuous pipeline. Human-submitted events use the same path through `POST /api/events/submit`. The existing deterministic core runs unchanged on all stored events.
7. **Investigate.** LangGraph orchestrates six agents with typed state. LLM output is validated; failures fall back to deterministic templates. The graph pauses at `waiting_approval`; only an authenticated human can resume it.
8. **Respond and report.** Response actions are recorded with analyst identity and reason, executed only in simulation. Reports export as PDF and JSON.

## 3. Trust boundaries

- **Agent credentials are ingest-only.** `require_agent(scope)` denies all analyst endpoints.
- **Human roles.** `admin` (full), `analyst` (read + write), `viewer` (read-only via `viewer_write_guard` middleware).
- **Untrusted data.** Log lines, intel records and LLM payloads are wrapped in explicit untrusted-data markers. No shell execution, `eval`, or side-effecting tools are available to agents.
- **Secrets.** Registration keys are displayed once and stored hashed. `.env`, databases, reports and forwarder state are gitignored.

## 4. Persistence

- SQLite is the zero-config default; models and Alembic migrations are PostgreSQL-compatible.
- Alembic head: `2f4a9c1d7b60` (adds endpoint/forwarder/credential/receipt/saved-search tables).
- Redis is optional (`REDIS_URL`, Compose profile `redis`); the current rate limiter and cache are in-process and documented as such.
- Elasticsearch is optional (`ELASTICSEARCH_URL`, Compose profile `elastic`) for large-scale search; the SQL database remains the source of truth.

## 5. Availability and failure behaviour

| Failure | Behaviour |
| --- | --- |
| Forwarder offline | Disk buffer accumulates up to `max_buffer_events`; exponential backoff on retry; heartbeats fail; server marks it offline after 300 s |
| Invalid agent key | 401, no batch accepted, failed attempts rate-limited |
| LLM unavailable / invalid output | Pydantic validation fails → labelled deterministic fallback; investigation continues |
| Redis/PostgreSQL/Elasticsearch/Wazuh absent | Documented local alternatives; core pipeline keeps working |
| Duplicate event | Acknowledged with `status: duplicate`, never double-counted |
