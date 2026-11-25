import { useState } from 'react';
import { Activity, Play, Shield, Trash2, Users } from 'lucide-react';
import { api, post } from '../services/api';
import { useAuth } from '../state/AuthContext';
import { Badge, DataTable, ErrorBox, Loading, Panel, StatCard, fmtTime, useLoader } from '../components/ui';
import { PageHeader } from '../components/Layout';

export default function Settings() {
  const { isAdmin } = useAuth();
  const { data, loading, error, reload } = useLoader(async () => {
    const [settings, health, scenarios] = await Promise.all([
      api<any>('/settings'),
      api<any>('/health'),
      api<any>('/simulation/scenarios'),
    ]);
    const users = isAdmin ? await api<any>('/users') : { items: [] };
    const audit = isAdmin ? await api<any>('/audit?limit=50') : { items: [] };
    return { settings, health, scenarios, users, audit };
  }, [isAdmin]);
  const [scenario, setScenario] = useState('brute_force_login');
  const [days, setDays] = useState(90);
  const [message, setMessage] = useState('');

  if (loading) return <Loading />;
  if (error || !data) return <ErrorBox error={error} onRetry={reload} />;

  const runScenario = async () => {
    try {
      const result = await post<any>('/simulation/run', { scenario, count: 5 });
      setMessage(`Simulation: ${JSON.stringify(result).slice(0, 200)}`);
    } catch (exc: any) {
      setMessage(`Error: ${exc.message}`);
    }
  };

  const retention = async (dryRun: boolean) => {
    try {
      const result = await post<any>('/retention', { days, dry_run: dryRun });
      setMessage(`Retention ${dryRun ? 'preview' : 'applied'}: ${JSON.stringify(result.deleted)}`);
    } catch (exc: any) {
      setMessage(`Error: ${exc.message}`);
    }
  };

  return (
    <>
      <PageHeader title="System Settings" description="Runtime status, integrations, safe simulations, users, audit trail and data retention." />
      {message && <p className="mb-3 text-sm text-sky-300">{message}</p>}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="Runtime Configuration">
          <div className="grid grid-cols-2 gap-3 text-sm">
            {Object.entries(data.settings).map(([key, value]) => (
              <div key={key} className="rounded-lg bg-navy-950/60 p-2">
                <p className="text-[10px] uppercase tracking-wider text-slate-500">{key}</p>
                <p className="break-all text-slate-200">{typeof value === 'object' ? JSON.stringify(value).slice(0, 80) : String(value)}</p>
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="Service Health">
          <div className="grid grid-cols-2 gap-3 text-sm">
            {Object.entries(data.health).map(([key, value]) => (
              <div key={key} className="rounded-lg bg-navy-950/60 p-2">
                <p className="text-[10px] uppercase tracking-wider text-slate-500">{key}</p>
                <p className="text-slate-200">{String(value)}</p>
              </div>
            ))}
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            <Badge>LLM: {String(data.settings.llm_mode)}</Badge>
            <Badge>Database: {String(data.health.database)}</Badge>
          </div>
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="Safe Lab Simulation" subtitle="Generates synthetic events only — no external systems are contacted">
          <div className="flex flex-wrap items-end gap-3">
            <div className="min-w-[240px] flex-1">
              <label className="label">Scenario</label>
              <select className="input" value={scenario} onChange={(e) => setScenario(e.target.value)}>
                {(() => {
                  const raw = data.scenarios.scenarios ?? data.scenarios.items ?? {};
                  const items: string[] = Array.isArray(raw)
                    ? raw.map((item: any) => (typeof item === 'string' ? item : item.name || item.id))
                    : Object.keys(raw);
                  return items.map((value) => <option key={value} value={value}>{value}</option>);
                })()}
              </select>
            </div>
            <button className="btn btn-primary" onClick={runScenario}><Play className="h-4 w-4" /> Run scenario</button>
          </div>
        </Panel>
        <Panel title="Data Retention" subtitle="Audit logs and incidents are preserved">
          <div className="flex flex-wrap items-end gap-3">
            <div className="w-40">
              <label className="label">Older than (days)</label>
              <input className="input" type="number" min={1} value={days} onChange={(e) => setDays(Number(e.target.value))} />
            </div>
            {isAdmin ? (
              <>
                <button className="btn" onClick={() => retention(true)}>Preview</button>
                <button className="btn btn-danger" onClick={() => retention(false)}><Trash2 className="h-4 w-4" /> Apply</button>
              </>
            ) : <span className="text-sm text-slate-500">Administrator access required</span>}
          </div>
        </Panel>
      </div>

      {isAdmin && (
        <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
          <Panel title="Users">
            <DataTable
              rows={data.users.items}
              columns={[
                { key: 'username', label: 'Username', render: (r) => <span className="flex items-center gap-1"><Users className="h-4 w-4 text-sky-400" />{r.username}</span> },
                { key: 'email', label: 'Email' },
                { key: 'role', label: 'Role', render: (r) => <Badge>{r.role}</Badge> },
                { key: 'is_active', label: 'Active', render: (r) => <Badge>{r.is_active ? 'Active' : 'Inactive'}</Badge> },
              ]}
            />
          </Panel>
          <Panel title="Audit Log">
            <DataTable
              rows={data.audit.items}
              columns={[
                { key: 'created_at', label: 'Time', render: (r) => fmtTime(r.created_at) },
                { key: 'actor', label: 'Actor' },
                { key: 'action', label: 'Action' },
                { key: 'target_id', label: 'Target' },
                { key: 'ip_address', label: 'IP' },
              ]}
            />
          </Panel>
        </div>
      )}
      <div className="mt-4 flex items-center gap-2 text-xs text-slate-600"><Shield className="h-4 w-4" /> <Activity className="h-4 w-4" /> SENTINELX lab — configure HTTPS, PostgreSQL and Redis before any real deployment.</div>
    </>
  );
}
