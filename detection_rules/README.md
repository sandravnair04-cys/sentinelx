# Detection rules

Sigma-compatible rules in this directory are loaded by the backend (`POST /api/detection/sigma/reload`) and are copies of the canonical versions in `app/../data/sigma/`.

Supported subset: field equality plus `contains` / `startswith` / `endswith`, `and` conditions, and `count() >|>=|<|<=|= N [by field]` with `timeframe`. Unsupported Sigma features are rejected with a clear error rather than silently ignored.

Built-in rules (brute force, password spraying, login-after-failures, privilege escalation, suspicious process, network anomalies) live in `app/detection/rules.py` and are configurable via `PATCH /api/detection/rules/{id}`.

Every alert includes a detection ID, name, description, related events, severity, MITRE mapping, timestamp and supporting evidence. A rule match is a lead, not proof of compromise.
