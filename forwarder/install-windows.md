# Installing SXUF on Windows 11

> Collect only logs you are authorised to monitor. SXUF never reads browser data, keystrokes or credentials.

## 1. Register the agent on the SentinelX server

Sign in as an administrator, then:

```powershell
$body = @{ agent_id = 'sxuf-win-01'; hostname = $env:COMPUTERNAME } | ConvertTo-Json
Invoke-RestMethod -Uri 'https://sentinelx.example.com/api/agents/register' `
  -Method Post -Headers @{ Authorization = "Bearer $TOKEN"; 'Content-Type' = 'application/json' } `
  -Body $body
```

Save the returned `agent_key` securely. It is shown only once; the server keeps only its hash.

## 2. Install Python and dependencies

```powershell
py -3.12 -m venv C:\SXUF\venv
C:\SXUF\venv\Scripts\pip.exe install -r requirements.txt
```

Optional native Event Log API support:

```powershell
C:\SXUF\venv\Scripts\pip.exe install pywin32
```

Without pywin32, SXUF uses `wevtutil` (included with Windows) with a fixed argument list.

## 3. Configure

```powershell
copy config.example.yaml C:\SXUF\config.yaml
notepad C:\SXUF\config.yaml
```

- Set `agent.id` to the registered ID.
- Set `server.url` to your HTTPS endpoint.
- Keep `sources` limited to the channels you need (Security 4624/4625/4672/4688, System, Application).
- Set the key as a machine/user environment variable rather than writing it into YAML:

```powershell
[Environment]::SetEnvironmentVariable('SXUF_AGENT_KEY','sxuf_...','Machine')
```

## 4. Verify and run

```powershell
cd C:\SXUF
.\venv\Scripts\python.exe sxuf.py verify-config
.\venv\Scripts\python.exe sxuf.py once
.\venv\Scripts\python.exe sxuf.py run
```

## 5. Install as a Windows service

Use [NSSM](https://nssm.cc/) (example):

```powershell
nssm install SentinelXForwarder "C:\SXUF\venv\Scripts\python.exe" "C:\SXUF\sxuf.py run"
nssm set SentinelXForwarder AppDirectory "C:\SXUF"
nssm set SentinelXForwarder Start SERVICE_AUTO_START
nssm start SentinelXForwarder
```

Service control:

```powershell
nssm stop SentinelXForwarder
nssm status SentinelXForwarder
```

## 6. Health and troubleshooting

- `C:\SXUF\state\health.json` — status, last success, error, buffer depth.
- `sxuf.py status` — same information on stdout.
- Check the server's **Forwarder Management** page for heartbeat and events sent.
- If you rotate the key in the dashboard, update `SXUF_AGENT_KEY` before restarting.

## Uninstall

```powershell
nssm stop SentinelXForwarder
nssm remove SentinelXForwarder confirm
```
