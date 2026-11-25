import { useEffect, useState } from 'react';
import { RefreshCw, ShieldCheck, Waypoints } from 'lucide-react';
import { api, patch, post } from '../services/api';
import { Badge, DataTable, ErrorBox, Loading, Panel, fmtTime, useLoader } from '../components/ui';
import { PageHeader } from '../components/Layout';
import { RiskGauge } from '../charts/Charts';

const STATUSES = ['New', 'Investigating', 'Pending Approval', 'Contained', 'Resolved', 'False Positive'];

export default function Incidents() {
  const { data, loading, error, reload } = useLoader(async () => api<any>('/incidents?limit=200'), []);
  const [selectedId, setSelectedId] = useState('');
  const [detail, setDetail] = useState<any>(null);
  const [message, setMessage] = useState('');

  useEffect(() => {
    if (selectedId) api<any>(`/incidents/${selectedId}`).then(setDetail).catch((e) => setMessage(e.message));
  }, [selectedId]);

  if (loading) return <Loading />;
  if (error || !data) return <ErrorBox error={error} onRetry={reload} />;

  const correlate = async () => {
    try {
      const result = await post<any>('/incidents/correlate');
      setMessage(`Correlation: ${JSON.stringify(result).slice(0, 180)}`);
      await reload();
    } catch (exc: any) {
      setMessage(`Error: ${exc.message}`);
    }
  };

  const updateStatus = async (status: string) => {
    if (!selectedId) return;
    try {
      await patch(`/incidents/${selectedId}`, { status });
      setDetail(await api<any>(`/incidents/${selectedId}`));
      await reload();
    } catch (exc: any) {
      setMessage(`Error: ${exc.message}`);
    }
  };

  return (
    <>
      <PageHeader
        title="Incident Management"
        description="Correlated cases with risk scores, evidence, timelines and audit trail."
        actions={<button className="btn btn-primary" onClick={correlate}><Waypoints className="h-4 w-4" /> Run correlation</button>}
      />
      {message && <p className="mb-3 text-sm text-sky-300">{message}</p>}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        <Panel title="Incidents" className="xl:col-span-3">
          <DataTable
            rows={data.items}
            empty="No incidents — run detection and correlation first"
            columns={[
              { key: 'incident_id', label: 'ID', render: (r) => <button className="font-mono text-xs text-sky-300 hover:underline" onClick={() => setSelectedId(r.incident_id)}>{r.incident_id}</button> },
              { key: 'title', label: 'Title', render: (r) => <span className="line-clamp-1">{r.title}</span> },
              { key: 'severity', label: 'Severity', render: (r) => <Badge>{r.severity}</Badge> },
              { key: 'risk_score', label: 'Risk', render: (r) => Math.round(r.risk_score) },
              { key: 'status', label: 'Status', render: (r) => <Badge>{r.status}</Badge> },
              { key: 'detection_time', label: 'Detected', render: (r) => fmtTime(r.detection_time) },
            ]}
          />
        </Panel>

        <Panel title="Incident Detail" className="xl:col-span-2">
          {!detail ? (
            <p className="text-sm text-slate-500">Select an incident to inspect evidence, timeline and audit trail.</p>
          ) : (
            <div className="space-y-4">
              <div>
                <p className="font-mono text-xs text-sky-400">{detail.incident_id}</p>
                <h3 className="mt-1 text-lg font-bold text-white">{detail.title}</h3>
                <div className="mt-2 flex flex-wrap gap-2">
                  <Badge>{detail.severity}</Badge><Badge>{detail.status}</Badge>
                  {detail.simulation && <Badge>Simulated</Badge>}
                </div>
              </div>
              <div className="grid grid-cols-3 gap-2 text-sm">
                <div className="rounded bg-navy-950/60 p-2"><p className="text-[10px] uppercase text-slate-500">Source IP</p><p className="text-slate-200">{detail.source_ip || '—'}</p></div>
                <div className="rounded bg-navy-950/60 p-2"><p className="text-[10px] uppercase text-slate-500">User</p><p className="text-slate-200">{detail.username || '—'}</p></div>
                <div className="rounded bg-navy-950/60 p-2"><p className="text-[10px] uppercase text-slate-500">Host</p><p className="text-slate-200">{detail.host || '—'}</p></div>
              </div>
              <RiskGauge score={detail.risk_score || 0} />
              {detail.finding_summary && <p className="text-sm text-slate-300">{detail.finding_summary}</p>}
              <div>
                <p className="label">Update status</p>
                <div className="flex flex-wrap gap-2">
                  {STATUSES.map((status) => (
                    <button key={status} className={`btn px-2 py-1 text-xs ${detail.status === status ? 'btn-primary' : ''}`} onClick={() => updateStatus(status)}>
                      <RefreshCw className="h-3 w-3" /> {status}
                    </button>
                  ))}
                </div>
              </div>
              {detail.timeline?.length > 0 && (
                <div>
                  <p className="label">Timeline</p>
                  <ol className="space-y-2 border-l border-slate-700 pl-3 text-xs">
                    {detail.timeline.slice(0, 20).map((event: any, index: number) => (
                      <li key={index} className="text-slate-300">
                        <span className="text-sky-400">{fmtTime(event.timestamp || event.time)}</span> — {event.description || event.summary || JSON.stringify(event).slice(0, 120)}
                      </li>
                    ))}
                  </ol>
                </div>
              )}
              {detail.mitre?.length > 0 && (
                <div>
                  <p className="label">MITRE ATT&CK</p>
                  <div className="flex flex-wrap gap-1">{detail.mitre.map((item: any, i: number) => <Badge key={i}>{typeof item === 'string' ? item : item.id || item.name}</Badge>)}</div>
                </div>
              )}
              <div className="flex flex-wrap gap-2">
                <a className="btn btn-primary" href={`/api/reports/${detail.incident_id}/json`} onClick={async (e) => {
                  e.preventDefault();
                  const token = localStorage.getItem('sentinelx.token');
                  const response = await fetch(`/api/reports/${detail.incident_id}/json`, { headers: { Authorization: `Bearer ${token}` } });
                  const blob = await response.blob();
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a'); a.href = url; a.download = `${detail.incident_id}.json`; a.click(); URL.revokeObjectURL(url);
                }}><ShieldCheck className="h-4 w-4" /> Export JSON</a>
              </div>
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}
