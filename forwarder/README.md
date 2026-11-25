# SXUF — SentinelX Universal Log Forwarder

A lightweight Python service that forwards explicitly configured Windows/Linux security logs to a SentinelX server.

```text
forwarder/
├── sxuf.py                 # entry point
├── sxuf/
│   ├── cli.py              # run | once | status | verify-config | version
│   ├── agent.py            # collection loop, flush, heartbeat, graceful shutdown
│   ├── config.py           # YAML config + safety validation
│   ├── models.py           # wire format
│   ├── parser.py           # untrusted log text → fields (no execution)
│   ├── dedupe.py           # persistent SQLite event-ID ledger
│   ├── buffer.py           # disk-backed JSONL queue with ack/requeue
│   ├── transport.py        # HTTPS + retries + agent auth
│   ├── health.py           # local health.json
│   └── collectors/         # file, journald, windows_event
├── config.example.yaml
├── requirements.txt
├── install-windows.md
├── install-linux.md
└── tests/
```

See `docs/FORWARDER.md` in the project root for design details, and the install guides for platform steps.

Run tests from the project root: `pytest -q` (forwarder tests are included in `pytest.ini`).
