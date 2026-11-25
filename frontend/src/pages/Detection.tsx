import { useState } from 'react';
import { FileCode2, Play, Radar, ShieldAlert } from 'lucide-react';
import { api, patch, post } from '../services/api';
import { useAuth } from '../state/AuthContext';
import { Badge, DataTable, ErrorBox, Loading, Panel, StatCard, fmtTime, useLoader } from '../components/ui';
import { PageHeader } from '../components/Layout';

export default function Detection() {
  const { isAdmin } = useAuth();
  const { data, loading, error, reload } = useLoader(async () => {
    const [rules, alerts] = await Promise.all([
      api<any>('/detection/rules'),
      api<any>('/alerts?limit=200'),
    ]);
    return { rules, alerts };
  }, []);
  const [selected, setSelected] = useState<any>(null);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);

  if (loading) return <Loading />;
  if (error || !data) return <ErrorBox error={error} onRetry={reload} />;

  const runAction = async (path: string, label: string) => {
    setBusy(true);
    try {
      const result = await post<any>(path);
      setMessage(`${label}: ${JSON.stringify(result).slice(0, 200)}`);
      await reload();
    } catch (exc: any) {
      setMessage(`Error: ${exc.message}`);
    } finally {
      setBusy(false);
    }
  };

  const toggleRule = async (rule: any) => {
    try {
      await patch(`/detection/rules/${rule.id}`, { enabled: !rule.enabled });
      await reload();
    } catch (exc: any) {
      setMessage(`Error: ${exc.message}`);
    }
  };

  const critical = data.alerts.items.filter((a: any) => a.severity === 'CRITICAL').length;
  const high = data.alerts.items.filter((a: any) => a.severity === 'HIGH').length;

  return (
    <>
      <PageHeader
        title="Threat Detection"
        description="Configurable rule engine, Sigma-compatible rules and explainable alerts."
        actions={
          <>
            <button className="btn btn-primary" disabled={busy} onClick={() => runAction('/detection/run', 'Detection run')}>
              <Play className="h-4 w-4" /> Run detection
            </button>
            {isAdmin && (
              <button className="btn" disabled={busy} onClick={() => runAction('/detection/sigma/reload', 'Sigma reload')}>
                <FileCode2 className="h-4 w-4" /> Reload Sigma rules
              </button>
            )}
          </>
        }
      />
      {message && <p className="mb-3 text-sm text-sky-300">{message}</p>}
      <div className="mb-4 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard label="Active Rules" value={data.rules.items.filter((r: any) => r.enabled).length} icon={<Radar className="h-5 w-5" />} tone="blue" />
        <StatCard label="High Alerts" value={high} icon={<ShieldAlert className="h-5 w-5" />} tone="amber" />
        <StatCard label="Critical Alerts" value={critical} icon={<ShieldAlert className="h-5 w-5" />} tone="red" />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="Detection Rules">
          <DataTable
            rows={data.rules.items}
            columns={[
              { key: 'name', label: 'Rule', render: (r) => <span className="text-white">{r.name}</span> },
              { key: 'category', label: 'Category' },
              { key: 'severity', label: 'Severity', render: (r) => <Badge>{r.severity}</Badge> },
              { key: 'source', label: 'Source', render: (r) => <Badge>{r.source}</Badge> },
              {
                key: 'enabled', label: 'Enabled', render: (r) => (
                  <button disabled={!isAdmin} onClick={() => toggleRule(r)} title={isAdmin ? 'Toggle rule' : 'Admin only'}>
                    <Badge>{r.enabled ? 'Active' : 'Disabled'}</Badge>
                  </button>
                ),
              },
            ]}
          />
        </Panel>
        <Panel title="Alerts" subtitle="Rule matches are leads, not confirmed compromise">
          <DataTable
            rows={data.alerts.items}
            empty="No alerts yet — run detection after ingesting events"
            columns={[
              { key: 'created_at', label: 'Time', render: (r) => fmtTime(r.created_at) },
              { key: 'rule_name', label: 'Rule', render: (r) => <span className="line-clamp-1">{r.rule_name}</span> },
              { key: 'severity', label: 'Severity', render: (r) => <Badge>{r.severity}</Badge> },
              { key: 'source_ip', label: 'Source IP' },
              { key: 'username', label: 'User' },
              { key: 'host', label: 'Host' },
              { key: 'evidence', label: '', render: (r) => <button className="text-xs text-sky-400 hover:underline" onClick={() => setSelected(r)}>evidence</button> },
            ]}
          />
        </Panel>
      </div>

      {selected && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/70 p-4" onClick={() => setSelected(null)}>
          <div className="panel max-h-[80vh] w-full max-w-2xl overflow-y-auto p-5" onClick={(e) => e.stopPropagation()}>
            <h3 className="mb-2 text-lg font-bold text-white">{selected.title}</h3>
            <p className="mb-4 text-sm text-slate-400">{selected.description}</p>
            <h4 className="text-sm font-semibold text-sky-300">MITRE ATT&CK</h4>
            <div className="mb-4 mt-2 flex flex-wrap gap-2">{selected.mitre?.map((m: string) => <Badge key={m}>{m}</Badge>)}</div>
            <h4 className="text-sm font-semibold text-sky-300">Supporting evidence</h4>
            <pre className="mt-2 max-h-96 overflow-auto rounded-lg bg-navy-950 p-3 font-mono text-xs text-emerald-300">
              {JSON.stringify(selected.evidence, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </>
  );
}
