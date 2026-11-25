# SXUF — SentinelX Universal Log Forwarder

Standalone Python 3.10+ service that collects only explicitly configured security logs and forwards them to the central ingestion API.

## Design

- **Sources:** `file` (auth.log, syslog), `journal` (systemd journal via `journalctl`), `windows_event` (Event Log via pywin32 when available, `wevtutil` fallback).
- **Privacy:** a deny-list rejects sensitive paths (`.ssh`, `id_rsa`, browser profiles, credential files). No passwords, keystrokes or browser data are collected.
- **Checkpointing:** file byte offsets, journal cursors and Windows record IDs. Checkpoints advance only after the server accepts the batch.
- **Duplicates:** stable UUID per `(agent_id, source, pointer, text)` plus a persistent SQLite receipt ledger.
- **Buffering:** `state/buffer.jsonl`, bounded by `runtime.max_buffer_events`. Server outages cause bounded exponential-backoff retries; events stay on disk.
- **Security:** HTTPS with certificate verification by default, agent ID + key headers, TLS opt-out requires `SXUF_ALLOW_INSECURE_TLS=1`, fixed non-shell subprocess arguments.
- **Health:** `state/health.json` plus server heartbeats. Graceful SIGINT/SIGTERM shutdown flushes and closes state cleanly.

## Automated Windows setup

From the project root, run `scripts/setup_sxuf_windows.ps1` (admin token defaults to the lab account). It registers this host as `sxuf-win-<hostname>`, writes `forwarder/config.yaml`, stores the one-time key in a protected `forwarder/agent.key` (via `key_file`), and prints the next commands. Then run `python sxuf.py run` from `forwarder/` (or install the service described in `install-windows.md`).

## Quick start (lab)

```bash
cd forwarder
python -m pip install -r requirements.txt
copy config.example.yaml config.yaml
# register the agent on the server first (admin):
#   POST /api/agents/register {"agent_id":"sxuf-01","hostname":"LAB-01"}
# set SXUF_AGENT_KEY to the returned one-time key
python sxuf.py verify-config
python sxuf.py once
python sxuf.py run
python sxuf.py status
```

Commands: `run` (continuous, default), `once` (single collection/flush cycle), `status`, `verify-config`, `version`.

## Windows / Linux installation

See `forwarder/install-windows.md` and `forwarder/install-linux.md`.

## Wire format

```json
{
  "event_id": "uuid",
  "timestamp": "2026-11-22T09:12:01Z",
  "hostname": "WIN-LAB-01",
  "source": "windows-security",
  "event_type": "failed_login",
  "source_ip": "203.0.113.77",
  "username": "administrator",
  "severity": "high",
  "raw_event": "EventID=4625 ...",
  "normalized_event": { "event_code": "4625" },
  "agent_id": "sxuf-win-01"
}
```

## Known limitations

- Windows native Event Log reading is implemented but was not executed on a live Windows host in the build environment; the `wevtutil` fallback and cross-platform file-source path are covered by automated tests.
- Syslog lines have no year; the local parser uses the current year (documented in the backend README too).
- Forwarder state files are local and must be protected with OS permissions.
