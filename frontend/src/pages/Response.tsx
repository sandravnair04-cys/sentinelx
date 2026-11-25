import { useState } from 'react';
import { CheckCircle2, History, ShieldCheck, XCircle } from 'lucide-react';
import { api, post } from '../services/api';
import { useAuth } from '../state/AuthContext';
import { Badge, DataTable, ErrorBox, Loading, Panel, fmtTime, useLoader } from '../components/ui';
import { PageHeader } from '../components/Layout';

export default function Response() {
  const { user } = useAuth();
  const { data, loading, error, reload } = useLoader(async () => {
    const [recommendations, history] = await Promise.all([
      api<any>('/response/recommendations?limit=200'),
      api<any>('/response/history'),
    ]);
    return { recommendations, history };
  }, []);
  const [reasons, setReasons] = useState<Record<number, string>>({});
  const [message, setMessage] = useState('');

  if (loading) return <Loading />;
  if (error || !data) return <ErrorBox error={error} onRetry={reload} />;

  const decide = async (id: number, decision: 'approved' | 'rejected') => {
    try {
      const result = await post<any>(`/response/recommendations/${id}/${decision}`, {
        decision,
        analyst: user?.username || 'analyst',
        role: user?.role || 'analyst',
        reason: reasons[id] || `${decision} via SOC dashboard`,
      });
      setMessage(`${result.title || 'Action'} — ${decision}`);
      await reload();
    } catch (exc: any) {
      setMessage(`Error: ${exc.message}`);
    }
  };

  const pending = data.recommendations.items.filter((item: any) => item.status === 'pending');

  return (
    <>
      <PageHeader
        title="Incident Response Centre"
        description="Human-approved response. All executions are simulated; high-impact actions require an administrator."
      />
      {message && <p className="mb-3 text-sm text-sky-300">{message}</p>}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel title="Pending Recommendations" className="xl:col-span-2">
          <DataTable
            rows={pending}
            empty="No pending response actions"
            columns={[
              { key: 'title', label: 'Action', render: (r) => <span className="font-medium text-white">{r.title}</span> },
              { key: 'action_type', label: 'Type', render: (r) => <Badge>{r.action_type}</Badge> },
              { key: 'target', label: 'Target' },
              { key: 'priority', label: 'Priority', render: (r) => <Badge>{r.priority}</Badge> },
              { key: 'execution_mode', label: 'Mode', render: (r) => <Badge>{r.execution_mode}</Badge> },
              {
                key: 'reason', label: 'Decision reason', render: (r) => (
                  <input className="input min-w-[140px] text-xs" placeholder="Optional reason" value={reasons[r.id] || ''} onChange={(e) => setReasons({ ...reasons, [r.id]: e.target.value })} />
                ),
              },
              {
                key: 'decision', label: 'Decision', render: (r) => (
                  <div className="flex gap-1">
                    <button className="btn btn-primary px-2 py-1" onClick={() => decide(r.id, 'approved')} title="Approve"><CheckCircle2 className="h-4 w-4" /></button>
                    <button className="btn btn-danger px-2 py-1" onClick={() => decide(r.id, 'rejected')} title="Reject"><XCircle className="h-4 w-4" /></button>
                  </div>
                ),
              },
            ]}
          />
          {pending.length > 0 && (
            <div className="mt-4 rounded-lg border border-slate-700/60 bg-navy-950/50 p-3 text-xs text-slate-400">
              <ShieldCheck className="mr-1 inline h-4 w-4 text-sky-400" />
              Approving records your identity and reason in the audit trail. No real system change is performed.
            </div>
          )}
        </Panel>
        <Panel title="Decision History">
          <DataTable
            rows={data.history.items}
            empty="No decisions recorded"
            columns={[
              { key: 'created_at', label: 'Time', render: (r) => fmtTime(r.created_at) },
              { key: 'action', label: 'Decision', render: (r) => <Badge>{r.action}</Badge> },
              { key: 'analyst', label: 'Analyst' },
              { key: 'analyst_role', label: 'Role' },
              { key: 'reason', label: 'Reason', render: (r) => <span className="line-clamp-1">{r.reason || '—'}</span> },
            ]}
          />
          <div className="mt-3 flex items-center gap-2 text-xs text-slate-500"><History className="h-4 w-4" /> Immutable-style audit records</div>
        </Panel>
      </div>
    </>
  );
}
