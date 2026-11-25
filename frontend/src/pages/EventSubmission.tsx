import { useState } from 'react';
import { ArrowRight, Bolt, ClipboardPaste, FileCode2, Play, ShieldAlert } from 'lucide-react';
import { Link } from 'react-router-dom';
import { api, post } from '../services/api';
import { Badge, ErrorBox, Panel } from '../components/ui';
import { PageHeader } from '../components/Layout';

const BRUTE_FORCE = Array.from({ length: 6 }, (_, index) => {
  const stamp = new Date(Date.now() - index * 30_000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  return `${stamp} EventID=4625 Account Name=administrator Source Network Address=203.0.113.222 Computer=WIN-SUBMIT failed logon`;
}).join('\n');

const SUSPICIOUS_PROCESS =
  `${new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')} EventID=4688 Account Name=svc_web Computer=WIN-SUBMIT ` +
  `powershell.exe -enc SGVsbG8gV29ybGQ= (simulated)`;

const LINUX_FAILURE =
  `Nov 23 09:12:01 lab sshd[123]: Failed password for invalid user admin from 198.51.100.77 port 22 ssh2`;

export default function EventSubmission() {
  const [mode, setMode] = useState<'raw' | 'structured'>('raw');
  const [format, setFormat] = useState('windows');
  const [sourceName, setSourceName] = useState('manual-submission');
  const [host, setHost] = useState('');
  const [text, setText] = useState('');
  const [autoProcess, setAutoProcess] = useState(true);
  const [structured, setStructured] = useState({
    source_type: 'linux',
    event_code: 'sshd',
    action: 'failure',
    username: 'admin',
    source_ip: '198.51.100.77',
    host: 'LAB-LINUX-01',
    message: 'Failed password for admin from 198.51.100.77',
  });
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    setError('');
    setResult(null);
    try {
      const body: any = { mode, format, source_name: sourceName, auto_process: autoProcess };
      if (mode === 'raw') {
        body.text = text;
        body.host = host || undefined;
      } else {
        body.event = structured;
      }
      setResult(await post<any>('/events/submit', body));
    } catch (exc: any) {
      setError(exc.message || String(exc));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader
        title="Submit Event"
        description="Paste a security log event and immediately run detection, correlation and risk scoring."
        actions={<Badge>human submission · no agent required</Badge>}
      />
      {error && <ErrorBox error={error} />}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        <Panel title="Event input" className="xl:col-span-3">
          <div className="mb-4 flex gap-2">
            <button className={`btn ${mode === 'raw' ? 'btn-primary' : ''}`} onClick={() => setMode('raw')}>
              <ClipboardPaste className="h-4 w-4" /> Raw log
            </button>
            <button className={`btn ${mode === 'structured' ? 'btn-primary' : ''}`} onClick={() => setMode('structured')}>
              <FileCode2 className="h-4 w-4" /> Structured event
            </button>
          </div>

          {mode === 'raw' ? (
            <>
              <div className="mb-3 grid grid-cols-1 gap-3 sm:grid-cols-3">
                <div>
                  <label className="label">Log format</label>
                  <select className="input" value={format} onChange={(e) => setFormat(e.target.value)}>
                    <option value="windows">Windows Event Log</option>
                    <option value="linux">Linux auth.log / syslog</option>
                    <option value="wazuh">Wazuh JSON alert</option>
                  </select>
                </div>
                <div>
                  <label className="label">Source name</label>
                  <input className="input" value={sourceName} onChange={(e) => setSourceName(e.target.value)} />
                </div>
                <div>
                  <label className="label">Hostname (optional)</label>
                  <input className="input" placeholder="WIN-SUBMIT" value={host} onChange={(e) => setHost(e.target.value)} />
                </div>
              </div>
              <label className="label">Log text — one event per line</label>
              <textarea
                className="input h-56 font-mono text-xs"
                placeholder="Paste a Windows Event ID line or Linux auth.log line…"
                value={text}
                onChange={(e) => setText(e.target.value)}
              />
              <div className="mt-3 flex flex-wrap gap-2">
                <button className="btn px-2 py-1 text-xs" onClick={() => { setFormat('windows'); setText(BRUTE_FORCE); }}>
                  Example: brute force chain
                </button>
                <button className="btn px-2 py-1 text-xs" onClick={() => { setFormat('windows'); setText(SUSPICIOUS_PROCESS); }}>
                  Example: suspicious process
                </button>
                <button className="btn px-2 py-1 text-xs" onClick={() => { setFormat('linux'); setText(LINUX_FAILURE); }}>
                  Example: Linux failed login
                </button>
              </div>
            </>
          ) : (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {Object.entries(structured).map(([key, value]) => (
                <div key={key}>
                  <label className="label">{key}</label>
                  <input
                    className="input"
                    value={value}
                    onChange={(e) => setStructured({ ...structured, [key]: e.target.value })}
                  />
                </div>
              ))}
            </div>
          )}

          <div className="mt-4 flex flex-wrap items-center gap-4">
            <label className="flex items-center gap-2 text-sm text-slate-300">
              <input type="checkbox" checked={autoProcess} onChange={(e) => setAutoProcess(e.target.checked)} />
              Auto-run detection + correlation
            </label>
            <button className="btn btn-primary" disabled={busy || (mode === 'raw' && !text.trim())} onClick={submit}>
              <Play className="h-4 w-4" /> {busy ? 'Processing…' : 'Submit event'}
            </button>
          </div>
        </Panel>

        <Panel title="Processing result" className="xl:col-span-2" subtitle="Deterministic pipeline — no LLM decision required">
          {!result ? (
            <p className="text-sm text-slate-500">
              Submit an event to see ingestion, detection and correlation results here.
            </p>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="rounded-lg bg-navy-950/60 p-3">
                  <p className="text-[10px] uppercase tracking-wider text-slate-500">Events stored</p>
                  <p className="text-xl font-bold text-white">{result.ingestion.inserted}</p>
                  <p className="text-xs text-slate-500">{result.ingestion.duplicates} duplicates</p>
                </div>
                <div className="rounded-lg bg-navy-950/60 p-3">
                  <p className="text-[10px] uppercase tracking-wider text-slate-500">Alerts created</p>
                  <p className="text-xl font-bold text-amber-300">{result.alerts_created}</p>
                  <p className="text-xs text-slate-500">{result.detection?.events_evaluated ?? 0} events evaluated</p>
                </div>
              </div>

              {result.incidents_created?.length > 0 && (
                <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3">
                  <p className="flex items-center gap-2 text-sm font-semibold text-emerald-300">
                    <ShieldAlert className="h-4 w-4" /> Correlated into incident
                  </p>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {result.incidents_created.map((id: string) => (
                      <Link key={id} className="font-mono text-xs text-sky-300 hover:underline" to="/incidents">
                        {id} <ArrowRight className="inline h-3 w-3" />
                      </Link>
                    ))}
                  </div>
                </div>
              )}

              {result.detection && (
                <div className="rounded-lg border border-slate-700/60 bg-navy-950/50 p-3 text-xs text-slate-400">
                  <p>Rules evaluated: {result.detection.evaluated}</p>
                  <p>Alerts created: {result.detection.created}</p>
                  <p>Total alerts: {result.detection.alerts_total}</p>
                </div>
              )}

              {result.correlation && (
                <div className="rounded-lg border border-slate-700/60 bg-navy-950/50 p-3 text-xs text-slate-400">
                  <p>Correlations found: {result.correlation.correlations}</p>
                  <p>Incidents created: {result.correlation.incidents_created}</p>
                </div>
              )}

              {result.event_uids?.length > 0 && (
                <details className="text-xs">
                  <summary className="cursor-pointer text-sky-300">Event UIDs ({result.event_uids.length})</summary>
                  <pre className="mt-2 max-h-40 overflow-auto rounded bg-navy-950 p-2 font-mono text-emerald-300">
                    {result.event_uids.join('\n')}
                  </pre>
                </details>
              )}

              <div className="flex flex-wrap gap-2 pt-1">
                <Link className="btn px-2 py-1 text-xs" to="/detection"><Bolt className="h-3 w-3" /> View alerts</Link>
                <Link className="btn px-2 py-1 text-xs" to="/logs">Open Log Explorer</Link>
              </div>
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}
