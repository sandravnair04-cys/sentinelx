# Log Explorer search syntax

Endpoint: `GET /api/events/search`

Terms are separated by whitespace and combined with **implicit AND**. Quoted values match literal phrases. A leading `-` negates a term. Field names are case-insensitive.

## Fields

| Field | Aliases | Matches |
| --- | --- | --- |
| `host` | `hostname` | Endpoint hostname |
| `ip` | `source_ip`, `src` | Source IP address |
| `user` | `username` | Account name |
| `severity` | `level` | `normalised_event.severity` from forwarded events |
| `type` | `event_type` | Event type such as `failed_login` |
| `source` | — | Source type (`windows`, `linux`, `wazuh`, `simulation`) |
| `code` | `event_code` | Event ID (e.g. `4625`) |
| `action` | — | Normalised action (`failure`, `success`, `privilege`, …) |
| `agent` | `agent_id` | SXUF agent ID |
| `event` | `event_id` | Forwarder event ID or SENTINELX event UID |

Bare terms search message, raw event, event code, host, username, source IP and normalised JSON.

## Examples

```text
failed password                  # both words anywhere
"failed password"                # exact phrase
user:administrator               # field match
severity:high user:administrator # both conditions
host:WIN-01 -action:success      # WIN-01 events that are not successes
ip:203.0.113.77 type:failed_login
event:evt-001
```

## Additional parameters

`host`, `source_ip`, `username`, `severity`, `event_type`, `start`, `end` (ISO-8601), `limit` (1–500), `offset`.

Example:

```text
GET /api/events/search?q=severity:high%20user:administrator&start=2026-11-22T00:00:00Z&limit=50
```

## Saved searches

`POST /api/searches` with `{ "name": "...", "query_text": "...", "filters": {} }`.
Saved searches are scoped to the owning analyst; admins can see all shared searches. `GET /api/searches`, `DELETE /api/searches/{id}`.

> All values are applied as bound SQL parameters. Search input cannot alter SQL structure.
