# Synthetic sample logs

All files here are **fabricated for lab demonstration** and contain no real credentials or personal data.

- `windows_security_sample.log` — Windows Security event text summaries (4624, 4625, 4672, …)
- `linux_auth_sample.log` — sshd/pam authentication lines
- `wazuh_alert_sample.json` — Wazuh-style alert records

Load one via `POST /api/collect/sample` with `{"name": "windows_security_sample.log", "platform": "windows"}` (platforms: `windows`, `linux`, `wazuh`). The canonical copies used by the API live in `data/samples/`.
