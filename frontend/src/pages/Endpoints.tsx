import { Monitor } from 'lucide-react';
import { api } from '../services/api';
import { Badge, DataTable, ErrorBox, Loading, Panel, StatCard, fmtTime, useLoader } from '../components/ui';
import { PageHeader } from '../components/Layout';

export default function Endpoints() {
  const { data, loading, error, reload } = useLoader(async () => api<any>('/endpoints'), []);
  if (loading) return <Loading />;
  if (error || !data) return <ErrorBox error={error} onRetry={reload} />;

  const online = data.items.filter((item: any) => item.status === 'online').length;
  const windows = data.items.filter((item: any) => item.os_type === 'windows').length;
  const totalEvents = data.items.reduce((sum: number, item: any) => sum + (item.events_received || 0), 0);

  return (
    <>
      <PageHeader title="Endpoint Management" description="Monitored hosts, operating systems, agent identity and health." />
      <div className="mb-4 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total Endpoints" value={data.total} icon={<Monitor className="h-5 w-5" />} tone="blue" />
        <StatCard label="Online" value={online} icon={<Monitor className="h-5 w-5" />} tone="green" />
        <StatCard label="Windows Hosts" value={windows} icon={<Monitor className="h-5 w-5" />} tone="blue" />
        <StatCard label="Events Received" value={totalEvents} icon={<Monitor className="h-5 w-5" />} tone="slate" />
      </div>
      <Panel title="Registered Endpoints">
        <DataTable
          rows={data.items}
          empty="No endpoints have reported yet — register a SXUF forwarder to begin"
          columns={[
            { key: 'hostname', label: 'Hostname', render: (r) => <span className="font-medium text-white">{r.hostname}</span> },
            { key: 'os_type', label: 'OS', render: (r) => <Badge>{r.os_type}</Badge> },
            { key: 'os_version', label: 'Version' },
            { key: 'ip_address', label: 'IP Address' },
            { key: 'agent_id', label: 'Agent ID', render: (r) => <span className="font-mono text-xs">{r.agent_id || '—'}</span> },
            { key: 'status', label: 'Status', render: (r) => <Badge>{r.status}</Badge> },
            { key: 'events_received', label: 'Events' },
            { key: 'last_heartbeat', label: 'Last Heartbeat', render: (r) => fmtTime(r.last_heartbeat) },
          ]}
        />
      </Panel>
    </>
  );
}
