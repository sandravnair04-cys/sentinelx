import { useCallback, useEffect, useState } from 'react';
import { Bot, Pause, Play, Radar, RefreshCw, Waypoints } from 'lucide-react';
import { api, post } from '../services/api';
import { Badge, DataTable, ErrorBox, fmtTime } from '../components/ui';
import { PageHeader } from '../components/Layout';

export default function Monitoring() {
  const [events, setEvents] = useState<any[]>([]);
  const [filter, setFilter] = useState('');
  const [auto, setAuto] = useState(true);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const query = filter ? `&search=${encodeURIComponent(filter)}` : '';
      const result = await api<any>(`/events?limit=100${query}`);
      setEvents(result.items);
      setError('');
    } catch (exc: any) {
      setError(exc.message || String(exc));
    }
  }, [filter]);

  useEffect(() => {
    load();
    if (!auto) return;
    const timer = setInterval(load, 6000);
    return () => clearInterval(timer);
  }, [load, auto]);

  const run = async (path: string, label: string, body?: unknown) => {
    setBusy(true);
    setMessage('');
    try {
      const result = await post<any>(path, body ?? {});
      setMessage(`${label}: ${result.inserted ?? result.created ?? result.total ?? result.alerts_created ?? 'completed'}`);
      await load();
    } catch (exc: any) {
      setError(exc.message || String(exc));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader
        title="Live Security Monitoring"
        description="Auto-refreshing event stream with manual detection and correlation triggers."
        actions={
          <>
            <button className="btn" onClick={() => setAuto(!auto)}>
              {auto ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
              {auto ? 'Pause' : 'Resume'} auto-refresh
            </button>
            <button className="btn" onClick={load}><RefreshCw className="h-4 w-4" /> Refresh</button>
            <button className="btn btn-primary" disabled={busy} onClick={() => run('/detection/run', 'Detection')}>
              <Radar className="h-4 w-4" /> Run detection
            </button>
            <button className="btn btn-primary" disabled={busy} onClick={() => run('/incidents/correlate', 'Correlation')}>
              <Waypoints className="h-4 w-4" /> Correlate
            </button>
            <button className="btn btn-primary" disabled={busy} onClick={() => run('/simulation/run', 'Simulation', { scenario: 'correlated_attack', count: 5 })}>
              <Bot className="h-4 w-4" /> Simulate attack
            </button>
          </>
        }
      />
      {error && <ErrorBox error={error} />}
      {message && <p className="mb-3 text-sm text-emerald-300">{message}</p>}
      <div className="panel p-4">
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <input
            className="input max-w-sm"
            placeholder="Filter by keyword, IP, host or user…"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
          />
          <span className="text-xs text-slate-500">{events.length} most recent events · refresh every 6 s</span>
        </div>
        <DataTable
          rows={events}
          columns={[
            { key: 'timestamp', label: 'Time', render: (r) => fmtTime(r.timestamp) },
            { key: 'source_type', label: 'Source', render: (r) => <Badge>{r.source_type}</Badge> },
            { key: 'event_code', label: 'Event ID' },
            { key: 'action', label: 'Action', render: (r) => <Badge>{r.action}</Badge> },
            { key: 'host', label: 'Host' },
            { key: 'username', label: 'User' },
            { key: 'source_ip', label: 'Source IP' },
            { key: 'message', label: 'Message', render: (r) => <span className="line-clamp-1">{r.message}</span> },
          ]}
        />
      </div>
    </>
  );
}
