# Installing SXUF on Linux

> Collect only logs you are authorised to monitor. SXUF reads only configured paths and never accesses browser data, keystrokes or credential files.

## 1. Register the agent on the server

```bash
curl -X POST https://sentinelx.example.com/api/agents/register \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"agent_id":"sxuf-linux-01","hostname":"'"$(hostname)"'"}'
```

Store the returned `agent_key` in the systemd environment file (next step). It is shown once.

## 2. Install

```bash
sudo useradd --system --home /opt/sxuf --shell /usr/sbin/nologin sxuf
sudo mkdir -p /opt/sxuf /var/lib/sxuf
python3 -m venv /opt/sxuf/venv
sudo /opt/sxuf/venv/bin/pip install -r requirements.txt
sudo cp config.example.yaml /opt/sxuf/config.yaml
sudo chown -R sxuf:sxuf /opt/sxuf /var/lib/sxuf
```

Edit `/opt/sxuf/config.yaml`: set `agent.id`, `server.url`, and the sources you are authorised to read (`/var/log/auth.log`, `/var/log/syslog`, or `journal`).

Create `/etc/sxuf.env` with `0600` permissions:

```bash
echo 'SXUF_AGENT_KEY=sxuf_...' | sudo tee /etc/sxuf.env
sudo chmod 600 /etc/sxuf.env
```

Grant read access to the configured log files, e.g. `sudo usermod -aG adm sxuf` on Debian/Ubuntu.

## 3. Verify

```bash
cd /opt/sxuf
sudo -u sxuf env SXUF_AGENT_KEY="$(cat /etc/sxuf.env | cut -d= -f2)" ./venv/bin/python sxuf.py verify-config
sudo -u sxuf env SXUF_AGENT_KEY="$(cat /etc/sxuf.env | cut -d= -f2)" ./venv/bin/python sxuf.py once
```

## 4. systemd service

`/etc/systemd/system/sxuf.service`:

```ini
[Unit]
Description=SentinelX Universal Log Forwarder
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sxuf
Group=sxuf
WorkingDirectory=/opt/sxuf
EnvironmentFile=/etc/sxuf.env
ExecStart=/opt/sxuf/venv/bin/python /opt/sxuf/sxuf.py run
Restart=always
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=30
ProtectSystem=strict
ReadWritePaths=/var/lib/sxuf
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

In `config.yaml`, set `runtime.state_dir: /var/lib/sxuf`.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sxuf
sudo systemctl status sxuf
journalctl -u sxuf -f
```

## 5. Health

- `/var/lib/sxuf/health.json`
- `sudo -u sxuf ./venv/bin/python sxuf.py status`
- Server **Forwarder Management** page: heartbeat, version, events sent, buffer depth.

## Uninstall

```bash
sudo systemctl disable --now sxuf
sudo rm /etc/systemd/system/sxuf.service
```
