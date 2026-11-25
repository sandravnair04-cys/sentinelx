import { useEffect, useState } from 'react';
import { Bot, CheckCircle2, Circle, GitBranch, Play, XCircle } from 'lucide-react';
import { api, post } from '../services/api';
import { useAuth } from '../state/AuthContext';
import { Badge, DataTable, ErrorBox, Loading, Panel, fmtTime, useLoader } from '../components/ui';
import { PageHeader } from '../components/Layout';

const STEPS = [
  'log_analysis', 'threat_detection', 'investigation',
  'risk_assessment', 'incident_response', 'report_generation',
];

export default function Investigation() {
  const { user } = useAuth();
  const { data, loading, error, reload } = useLoader(async () => {
    const [sessions, incidents] = await Promise.all([
      api<any>('/investigations'),
      api<any>('/incidents?limit=100'),
    ]);
    return { sessions, incidents };
  }, []);
  const [sessionUid, setSessionUid] = useState('');
  const [detail, setDetail] = useState<any>(null);
  const [incidentId, setIncidentId] = useState('');
  const [decision, setDecision] = useState('approved');
  const [reason, setReason] = useState('');
  const [message, setMessage] = useState('');

  useEffect(() => {
    if (sessionUid) {
      api<any>(`/investigations/${sessionUid}`).then(setDetail).catch((e) => setMessage(e.message));
    }
  }, [sessionUid]);

  if (loading) return <Loading />;
  if (error || !data) return <ErrorBox error={error} onRetry={reload} />;

  const start = async () => {
    if (!incidentId) return;
    try {
      const result = await post<any>('/investigations/start', { incident_id: incidentId, started_by: user?.username || 'analyst' });
      setMessage(`Investigation started: ${result.session_uid || result.status}`);
      await reload();
      setSessionUid(result.session_uid);
    } catch (exc: any) {
      setMessage(`Error: ${exc.message}`);
    }
  };

  const resume = async () => {
    if (!sessionUid) return;
    try {
      const result = await post<any>(`/investigations/${sessionUid}/resume`, {
        decision, analyst: user?.username || 'analyst', role: user?.role || 'analyst', reason,
      });
      setMessage(`Decision recorded: ${result.status}`);
      setDetail(await api<any>(`/investigations/${sessionUid}`));
      await reload();
    } catch (exc: any) {
      setMessage(`Error: ${exc.message}`);
    }
  };

  const executions: any[] = detail?.executions || [];
  const executed = new Set(executions.map((item) => item.agent_key));

  return (
    <>
      <PageHeader
        title="AI Investigation Centre"
        description="Six specialised agents investigate with structured outputs and a mandatory human approval checkpoint."
      />
      {message && <p className="mb-3 text-sm text-sky-300">{message}</p>}
      <div className="mb-4 flex flex-wrap items-end gap-3 rounded-xl border border-slate-700/60 bg-navy-900/70 p-4">
        <div className="min-w-[260px] flex-1">
          <label className="label">Select incident to investigate</label>
          <select className="input" value={incidentId} onChange={(e) => setIncidentId(e.target.value)}>
            <option value="">— choose incident —</option>
            {data.incidents.items.map((incident: any) => (
              <option key={incident.incident_id} value={incident.incident_id}>
                {incident.incident_id} — {incident.title.slice(0, 60)}
              </option>
            ))}
          </select>
        </div>
        <button className="btn btn-primary" onClick={start} disabled={!incidentId}>
          <Play className="h-4 w-4" /> Start investigation
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel title="Investigation Sessions">
          <DataTable
            rows={data.sessions.items}
            empty="No investigations yet"
            columns={[
              { key: 'session_uid', label: 'Session', render: (r) => <button className="font-mono text-xs text-sky-300 hover:underline" onClick={() => setSessionUid(r.session_uid)}>{r.session_uid.slice(0, 16)}</button> },
              { key: 'incident_id', label: 'Incident' },
              { key: 'status', label: 'Status', render: (r) => <Badge>{r.status}</Badge> },
              { key: 'llm_mode', label: 'Mode', render: (r) => <Badge>{r.llm_mode}</Badge> },
              { key: 'started_at', label: 'Started', render: (r) => fmtTime(r.started_at) },
            ]}
          />
        </Panel>

        <Panel title="Agent Workflow" className="xl:col-span-2">
          {!detail ? (
            <p className="text-sm text-slate-500">Select a session to inspect agent findings.</p>
          ) : (
            <>
              <div className="mb-5 grid grid-cols-2 gap-2 md:grid-cols-3">
                {STEPS.map((step, index) => {
                  const execution = executions.find((item) => item.agent_key === step);
                  return (
                    <div key={step} className={`rounded-lg border p-3 ${execution?.success ? 'border-emerald-500/30 bg-emerald-500/5' : execution ? 'border-red-500/30 bg-red-500/5' : 'border-slate-700/60 bg-navy-950/40'}`}>
                      <div className="flex items-center gap-2">
                        {execution?.success ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : execution ? <XCircle className="h-4 w-4 text-red-400" /> : <Circle className="h-4 w-4 text-slate-600" />}
                        <span className="text-xs font-semibold text-slate-300">{index + 1}. {step.replace(/_/g, ' ')}</span>
                      </div>
                      {execution && <p className="mt-1 text-[11px] text-slate-500">{execution.duration_ms} ms</p>}
                    </div>
                  );
                })}
              </div>

              <div className="mb-4 flex flex-wrap items-center gap-3 rounded-lg border border-slate-700/60 bg-navy-950/50 p-3">
                <GitBranch className="h-5 w-5 text-sky-400" />
                <div className="flex-1">
                  <p className="text-sm text-slate-200">Session {detail.session_uid.slice(0, 20)} — <Badge>{detail.status}</Badge></p>
                  <p className="text-xs text-slate-500">Current step: {detail.current_step || '—'} · Mode: {detail.llm_mode}</p>
                </div>
                {detail.status === 'waiting_approval' && (
                  <div className="flex flex-wrap items-center gap-2">
                    <select className="input w-32" value={decision} onChange={(e) => setDecision(e.target.value)}>
                      <option value="approved">Approve</option>
                      <option value="rejected">Reject</option>
                    </select>
                    <input className="input w-48" placeholder="Reason" value={reason} onChange={(e) => setReason(e.target.value)} />
                    <button className="btn btn-primary" onClick={resume}><Bot className="h-4 w-4" /> Record decision</button>
                  </div>
                )}
              </div>

              {executions.length > 0 && (
                <div className="space-y-2">
                  {executions.map((execution, index) => (
                    <details key={index} className="rounded-lg border border-slate-700/60 bg-navy-950/40 p-3">
                      <summary className="cursor-pointer text-sm text-slate-300">
                        <span className="font-semibold text-white">{execution.agent_name}</span> — {execution.role}
                      </summary>
                      <p className="mt-2 text-xs text-slate-500">{execution.error || 'Structured output validated; stored in investigation state.'}</p>
                    </details>
                  ))}
                </div>
              )}
              {detail.state && Object.keys(detail.state).length > 0 && (
                <pre className="mt-4 max-h-96 overflow-auto rounded-lg bg-navy-950 p-3 font-mono text-xs text-emerald-300">
                  {JSON.stringify(detail.state, null, 2).slice(0, 20000)}
                </pre>
              )}
            </>
          )}
        </Panel>
      </div>
    </>
  );
}
