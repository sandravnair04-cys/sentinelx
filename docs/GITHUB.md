# Publishing SENTINELX to GitHub

## 0. Install Git (one time, Windows)

Option A — winget (recommended):

```powershell
winget install --id Git.Git -e --source winget
```

Option B — download from https://git-scm.com/download/win and run the installer.

Close and reopen PowerShell, then verify:

```powershell
git --version
```

Configure your identity:

```powershell
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```

## 1. Create the GitHub repository

1. Go to https://github.com/new
2. Repository name: `sentinelx`
3. **Do not** tick "Add a README", ".gitignore" or a license — this repo already has them.
4. Set visibility (public recommended for a portfolio).
5. Copy the repository URL, e.g. `https://github.com/<username>/sentinelx.git`.

## 2. Initialise locally from the correct folder

The project lives in the `sentinelx/` subfolder. **Do not run git in the parent folder** — it contains an unrelated project.

```powershell
cd "C:\Users\sandr\OneDrive\Documents\Default Project\sentinelx"
git init -b main
```

## 3. Pre-flight secret check

`.gitignore` already excludes `.env`, `*.db`, `data/reports/`, `forwarder/agent.key`, `forwarder/config.yaml`, `forwarder/state/`, `node_modules/`, `frontend/dist/`, `*.bak` and logs.

Stage everything, then inspect exactly what will be committed:

```powershell
git add .
git status --short
```

Confirm you do **not** see:

- `.env` or any API key
- `data/sentinelx.db`, `*.db-wal`, `*.db-shm`, `data/reports/`
- `forwarder/agent.key`, `forwarder/config.yaml`, `forwarder/state/`
- `frontend/node_modules/`, `frontend/dist/`
- any `*.bak` file

You can prove an individual file is ignored:

```powershell
git check-ignore -v forwarder/agent.key data/sentinelx.db
```

If a secret was ever committed by mistake, rotate it immediately (agent key: `POST /api/agents/{id}/rotate`; LLM/VT keys: regenerate at the provider) and remove it from history with `git filter-repo`.

## 4. Commit and push

```powershell
git commit -m "feat: SENTINELX agentic AI SOC platform with SXUF forwarder and React dashboard"
git remote add origin https://github.com/<username>/sentinelx.git
git push -u origin main
```

If a remote already exists:

```powershell
git remote set-url origin https://github.com/<username>/sentinelx.git
git push -u origin main
```

GitHub may ask for a Personal Access Token instead of your password (password authentication was removed). Create one at **Settings → Developer settings → Personal access tokens → Tokens (classic)** with `repo` scope.

## 5. After publishing

Recommended repository settings:

- **Topics:** `security`, `soc`, `blueteam`, `siem`, `fastapi`, `langgraph`, `ai-agents`, `mitre-attacks`, `sigma`, `cybersecurity`
- **Branch protection** on `main` (require pull request)
- Enable **Dependabot** and **secret scanning**
- Add a short description linking to the screenshots section of the README

Screenshots are intentionally not bundled. Generate them from the running app and add them to `docs/screenshots/`, then commit:

```powershell
git add docs/screenshots
git commit -m "docs: add SOC dashboard screenshots"
git push
```

## 6. Notes for people cloning the repo

Built frontend output and local credentials are intentionally absent. On a fresh clone:

```powershell
cd sentinelx
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python scripts/init_db.py
python run.py
```

For the React SPA:

```powershell
cd frontend
npm install
npm run build
```

Then register a new SXUF agent from the dashboard and run `scripts/setup_sxuf_windows.ps1` to create a fresh `agent.key`. Docker builds the frontend automatically via the multi-stage Dockerfile.
