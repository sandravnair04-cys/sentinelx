# SentinelX React dashboard

Primary SOC UI for SENTINELX: React 18 + TypeScript + Tailwind CSS + Recharts + Lucide icons, built with Vite.

## Development

```bash
npm install
npm run dev        # http://localhost:5173, proxies /api to localhost:8000
npm run typecheck
npm run build      # outputs dist/
```

Start the FastAPI backend separately (`python run.py` from the project root). The built `dist/` directory is served automatically by FastAPI at `/` with SPA fallback; the original zero-build dashboard remains available at `/static/index.html`.

## Pages

SOC Overview · Live Monitoring · **Submit Event** · Log Explorer · Endpoint Management · Forwarder Management · Threat Detection · AI Investigation Centre · Incident Management · Incident Response Centre · Agent Monitoring · Threat Intelligence · MITRE ATT&CK Explorer · Security Reports · System Settings.

The Submit Event page accepts raw log text or a structured event, auto-runs detection + correlation, and links directly to the resulting alerts and incidents.

## Notes

- JWT is stored in `localStorage` under `sentinelx.token`; all API calls include the bearer token.
- Analyst/admin-only controls are hidden for viewers; the backend enforces the same rules.
- All data comes from real API endpoints. No placeholder metrics are generated in the browser.
