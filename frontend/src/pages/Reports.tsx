import { useState } from 'react';
import { Download, FileJson, FileText, RefreshCw } from 'lucide-react';
import { api, download, post } from '../services/api';
import { Badge, DataTable, ErrorBox, Loading, Panel, fmtTime, useLoader } from '../components/ui';
import { PageHeader } from '../components/Layout';

export default function Reports() {
  const { data, loading, error, reload } = useLoader(async () => {
    const [reports, incidents] = await Promise.all([
      api<any>('/reports?limit=100'),
      api<any>('/incidents?limit=100'),
    ]);
    return { reports, incidents };
  }, []);
  const [incidentId, setIncidentId] = useState('');
  const [message, setMessage] = useState('');

  if (loading) return <Loading />;
  if (error || !data) return <ErrorBox error={error} onRetry={reload} />;

  const generate = async () => {
    if (!incidentId) return;
    try {
      const result = await post<any>(`/reports/generate/${incidentId}`);
      setMessage(`Generated ${result.file_name} (SHA-256 ${result.sha256?.slice(0, 16)}…)`);
      await reload();
    } catch (exc: any) {
      setMessage(`Error: ${exc.message}`);
    }
  };

  return (
    <>
      <PageHeader title="Security Reports" description="Branded PDF and JSON investigation exports with SHA-256 integrity records." />
      {message && <p className="mb-3 text-sm text-emerald-300">{message}</p>}
      <Panel title="Generate a report" className="mb-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[280px] flex-1">
            <label className="label">Incident</label>
            <select className="input" value={incidentId} onChange={(e) => setIncidentId(e.target.value)}>
              <option value="">— choose incident —</option>
              {data.incidents.items.map((item: any) => (
                <option key={item.incident_id} value={item.incident_id}>{item.incident_id} — {item.title.slice(0, 50)}</option>
              ))}
            </select>
          </div>
          <button className="btn btn-primary" onClick={generate} disabled={!incidentId}><RefreshCw className="h-4 w-4" /> Generate PDF</button>
          {incidentId && (
            <button className="btn" onClick={async () => {
              try { await download(`/reports/${incidentId}/json`, `${incidentId}.json`); }
              catch (exc: any) { setMessage(`Error: ${exc.message}`); }
            }}><FileJson className="h-4 w-4" /> Export JSON</button>
          )}
        </div>
      </Panel>
      <Panel title="Generated Reports">
        <DataTable
          rows={data.reports.items}
          empty="No reports generated yet"
          columns={[
            { key: 'created_at', label: 'Generated', render: (r) => fmtTime(r.created_at) },
            { key: 'incident_id', label: 'Incident', render: (r) => <Badge>{r.incident_id}</Badge> },
            { key: 'file_name', label: 'File', render: (r) => <span className="flex items-center gap-1"><FileText className="h-4 w-4 text-sky-400" />{r.file_name}</span> },
            { key: 'generated_by', label: 'By' },
            { key: 'sha256', label: 'SHA-256', render: (r) => <code className="text-xs text-emerald-300">{r.sha256?.slice(0, 20)}…</code> },
            { key: 'download', label: '', render: (r) => <button className="btn px-2 py-1" onClick={async () => {
              try { await download(`/reports/${r.incident_id}/download`, r.file_name); }
              catch (exc: any) { setMessage(`Error: ${exc.message}`); }
            }}><Download className="h-4 w-4" /></button> },
          ]}
        />
      </Panel>
    </>
  );
}
