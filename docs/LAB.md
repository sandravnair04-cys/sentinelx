# SENTINELX lab and test environment

All testing is defensive and local. No external system is scanned, attacked or contacted.

## Recommended topology

| VM | Role | Notes |
| --- | --- | --- |
| SentinelX server | API + React dashboard + SQLite/PostgreSQL | 127.0.0.1 / internal network only |
| Windows 11 VM | SXUF forwarder | Security/System/Application Event Logs |
| Kali Linux VM | SXUF forwarder | auth.log / journald (read-only tailing) |

A single host with the bundled simulated datasets is sufficient for most portfolio demonstrations.

## Automated test suite

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```

Coverage includes: ingestion auth, dedupe, batch limits, heartbeat, credential rotation/revocation, viewer RBAC, log search, saved searches, MITRE catalogue, JSON/PDF reports, retention, forwarder config safety, buffer/ack/requeue, parser extraction, transport retries, forwarder→ingestion→detection end-to-end, plus the original 42 backend tests.

## Manual scenarios (synthetic only)

Use **System Settings → Safe Lab Simulation** or `POST /api/simulation/run`:

1. `brute_force_login` — repeated failures from one IP
2. `login_after_failures` — success after a failure burst
3. `suspicious_privileged_activity`
4. `unusual_network_connections`
5. `suspicious_process_execution`
6. `correlated_attack` — full chain

Then:

1. Run detection (`POST /api/detection/run`).
2. Run correlation (`POST /api/incidents/correlate`).
3. Start an investigation from the AI Investigation Centre.
4. Record approve/reject at the approval checkpoint as `analyst`; try a high-impact approval as `analyst` (403) and as `admin` (allowed, still simulated).
5. Generate a PDF and JSON report and verify the SHA-256 record.

## Failure-injection checks

| Case | How to exercise | Expected |
| --- | --- | --- |
| Offline forwarder | Stop the forwarder and wait > `FORWARDER_OFFLINE_AFTER_SECONDS` | Status becomes `offline`; buffer depth rises locally |
| Failed ingestion | Point SXUF at an unreachable URL with `max_retries: 0` | Events stay in `state/buffer.jsonl`, health `degraded` |
| Duplicate ingestion | Send the same event ID twice | Second response `status: duplicate`, no new event |
| Invalid agent auth | Wrong `X-Agent-Key` | 401; repeated failures rate-limited |
| AI failure | Leave `LLM_API_KEY` empty | `llm_mode: fallback`, investigation still completes |
| Human rejection | Reject at approval gate | Decision recorded in audit trail, report notes rejection |

## Boundaries

Do not collect logs from systems you do not own or are not authorised to monitor. Bundled samples are labelled simulated. Real response integrations are intentionally not implemented.
