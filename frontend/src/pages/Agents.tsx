import { useState } from 'react';
import { Bot, CheckCircle2, Clock, XCircle } from 'lucide-react';
import { api } from '../services/api';
import { Badge, DataTable, ErrorBox, Loading, Panel, StatCard, fmtTime, useLoader } from '../components/ui';
import { PageHeader } from '../components/Layout';

export default function Agents() {
  const { data, loading, error, reload } = useLoader(async () => api<any>('/agents'), []);
  const [key, setKey] = useState('');
  const [executions, setExecutions] = useState<any[]>([]);

  if (loading) return <Loading />;
  if (error || !data) return <ErrorBox error={error} onRetry={reload} />;

  const select = async (agentKey: string) => {
    setKey(agentKey);
    try {
      setExecutions((await api<any>(`/agents/${agentKey}/executions?limit=50`)).items);
    } catch {
      setExecutions([]);
    }
  };

  const total = data.agents.reduce((sum: number, a: any) => sum + a.total_executions, 0);
  const successes = data.agents.reduce((sum: number, a: any) => sum + a.successes, 0);
  const failures = data.agents.reduce((sum: number, a: any) => sum + a.failures, 0);

  return (
    <>
      <PageHeader
        title="AI Agent Monitoring"
        description="Real execution records, success rates and durations — never fabricated metrics."
        actions={<Badge>{data.llm_mode === 'api' ? 'LLM API MODE' : 'DETERMINISTIC FALLBACK MODE'}</Badge>}
      />
      <div className="mb-4 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total Executions" value={total} icon={<Bot className="h-5 w-5" />} tone="blue" />
        <StatCard label="Successful" value={successes} icon={<CheckCircle2 className="h-5 w-5" />} tone="green" />
        <StatCard label="Failed" value={failures} icon={<XCircle className="h-5 w-5" />} tone="red" />
        <StatCard label="Specialised Agents" value={data.agents.length} icon={<Bot className="h-5 w-5" />} tone="slate" />
      </div>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        <Panel title="Agents" className="xl:col-span-3">
          <DataTable
            rows={data.agents}
            columns={[
              { key: 'workflow_step', label: '#', render: (r) => r.workflow_step },
              { key: 'name', label: 'Agent', render: (r) => <button className="text-left font-medium text-sky-300 hover:underline" onClick={() => select(r.key)}>{r.name}</button> },
              { key: 'status', label: 'Status', render: (r) => <Badge>{r.status}</Badge> },
              { key: 'total_executions', label: 'Runs' },
              { key: 'successes', label: 'OK' },
              { key: 'failures', label: 'Fail' },
              { key: 'avg_duration_ms', label: 'Avg ms', render: (r) => Math.round(r.avg_duration_ms) },
              { key: 'last_execution', label: 'Last run', render: (r) => fmtTime(r.last_execution) },
            ]}
          />
        </Panel>
        <Panel title={key ? `Executions — ${key}` : 'Execution History'} className="xl:col-span-2">
          {!key ? <p className="text-sm text-slate-500">Select an agent to view its execution history.</p> : (
            <DataTable
              rows={executions}
              empty="No executions recorded"
              columns={[
                { key: 'started_at', label: 'Time', render: (r) => fmtTime(r.started_at) },
                { key: 'status', label: 'Status', render: (r) => <Badge>{r.status}</Badge> },
                { key: 'duration_ms', label: 'Duration', render: (r) => <span className="flex items-center gap-1"><Clock className="h-3 w-3" /> {r.duration_ms} ms</span> },
                { key: 'error', label: 'Error', render: (r) => <span className="line-clamp-1 text-xs text-red-300">{r.error || '—'}</span> },
              ]}
            />
          )}
        </Panel>
      </div>
    </>
  );
}
