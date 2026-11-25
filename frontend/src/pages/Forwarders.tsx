import { useState } from 'react';
import { KeyRound, RotateCcw, Server, ShieldOff, UserPlus } from 'lucide-react';
import { api, post } from '../services/api';
import { useAuth } from '../state/AuthContext';
import { Badge, DataTable, ErrorBox, Loading, Panel, StatCard, fmtTime, useLoader } from '../components/ui';
import { PageHeader } from '../components/Layout';

export default function Forwarders() {
  const { isAdmin } = useAuth();
  const { data, loading, error, reload } = useLoader(async () => {
    const [forwarders, credentials] = await Promise.all([
      api<any>('/forwarders'),
      isAdmin ? api<any>('/agents/credentials') : Promise.resolve({ items: [] }),
    ]);
    return { forwarders, credentials };
  }, [isAdmin]);

  const [newAgent, setNewAgent] = useState({ agent_id: '', hostname: '' });
  const [oneTimeKey, setOneTimeKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState('');

  if (loading) return <Loading />;
  if (error || !data) return <ErrorBox error={error} onRetry={reload} />;

  const act = async (path: string, body?: unknown) => {
    setBusy(true);
    setActionError('');
    try {
      const result = await post<any>(path, body ?? {});
      if (result.agent_key) setOneTimeKey(result.agent_key);
      await reload();
    } catch (exc: any) {
      setActionError(exc.message || String(exc));
    } finally {
      setBusy(false);
    }
  };

  const online = data.forwarders.items.filter((f: any) => f.status === 'online').length;
  const totalEvents = data.forwarders.items.reduce((sum: number, f: any) => sum + (f.events_sent || 0), 0);

  return (
    <>
      <PageHeader
        title="Forwarder Management"
        description="SXUF agent registry, credentials, heartbeat status and version tracking."
      />
      {actionError && <ErrorBox error={actionError} />}

      <div className="mb-4 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Forwarders" value={data.forwarders.total} icon={<Server className="h-5 w-5" />} tone="blue" />
        <StatCard label="Online" value={online} icon={<Server className="h-5 w-5" />} tone="green" />
        <StatCard label="Events Sent" value={totalEvents} icon={<Server className="h-5 w-5" />} tone="slate" />
        <StatCard label="Active Credentials" value={data.credentials.items.filter((c: any) => c.status === 'active').length} icon={<KeyRound className="h-5 w-5" />} tone="green" />
      </div>

      {isAdmin && (
        <Panel title="Register a new SXUF agent" className="mb-4">
          <div className="flex flex-wrap items-end gap-3">
            <div className="min-w-[200px] flex-1">
              <label className="label">Agent ID</label>
              <input className="input" placeholder="sxuf-win-02" value={newAgent.agent_id} onChange={(e) => setNewAgent({ ...newAgent, agent_id: e.target.value })} />
            </div>
            <div className="min-w-[200px] flex-1">
              <label className="label">Hostname</label>
              <input className="input" placeholder="WIN-LAB-02" value={newAgent.hostname} onChange={(e) => setNewAgent({ ...newAgent, hostname: e.target.value })} />
            </div>
            <button className="btn btn-primary" disabled={busy || !newAgent.agent_id || !newAgent.hostname}
              onClick={async () => {
                const result = await act('/agents/register', newAgent);
                void result;
                setNewAgent({ agent_id: '', hostname: '' });
              }}>
              <UserPlus className="h-4 w-4" /> Register agent
            </button>
          </div>
          {oneTimeKey && (
            <div className="mt-4 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-200">
              <p className="font-semibold">Copy this key now — it will never be shown again.</p>
              <code className="mt-2 block break-all rounded bg-navy-950 p-2 font-mono text-xs text-amber-300">{oneTimeKey}</code>
              <button className="mt-2 text-xs underline" onClick={() => setOneTimeKey('')}>Dismiss</button>
            </div>
          )}
        </Panel>
      )}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="Forwarders">
          <DataTable
            rows={data.forwarders.items}
            empty="No forwarders registered"
            columns={[
              { key: 'agent_id', label: 'Agent ID', render: (r) => <span className="font-mono text-xs">{r.agent_id}</span> },
              { key: 'hostname', label: 'Hostname' },
              { key: 'version', label: 'Version' },
              { key: 'status', label: 'Status', render: (r) => <Badge>{r.status}</Badge> },
              { key: 'events_sent', label: 'Events' },
              { key: 'buffer_depth', label: 'Buffer' },
              { key: 'last_heartbeat', label: 'Heartbeat', render: (r) => fmtTime(r.last_heartbeat) },
            ]}
          />
        </Panel>
        <Panel title="Agent Credentials" subtitle={isAdmin ? 'Keys are hashed at rest; only prefixes are shown' : 'Administrator access required'}>
          {isAdmin ? (
            <DataTable
              rows={data.credentials.items}
              empty="No credentials"
              columns={[
                { key: 'agent_id', label: 'Agent ID', render: (r) => <span className="font-mono text-xs">{r.agent_id}</span> },
                { key: 'key_prefix', label: 'Key prefix', render: (r) => <code className="text-xs text-sky-300">{r.key_prefix}…</code> },
                { key: 'scopes', label: 'Scopes', render: (r) => r.scopes?.join(', ') },
                { key: 'status', label: 'Status', render: (r) => <Badge>{r.status}</Badge> },
                { key: 'last_used_at', label: 'Last used', render: (r) => fmtTime(r.last_used_at) },
                {
                  key: 'actions', label: 'Actions', render: (r) => (
                    <div className="flex gap-2">
                      <button className="btn px-2 py-1" disabled={busy} onClick={() => act(`/agents/${r.agent_id}/rotate`)} title="Rotate key">
                        <RotateCcw className="h-3.5 w-3.5" />
                      </button>
                      <button className="btn btn-danger px-2 py-1" disabled={busy} onClick={() => act(`/agents/${r.agent_id}/revoke`)} title="Revoke">
                        <ShieldOff className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  ),
                },
              ]}
            />
          ) : <p className="text-sm text-slate-500">Administrator role required to view credentials.</p>}
        </Panel>
      </div>
    </>
  );
}
