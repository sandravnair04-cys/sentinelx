import { Link } from 'react-router-dom';
import { Activity, AlertOctagon, Bot, Radio, Server, ShieldAlert, ShieldCheck, TrendingUp } from 'lucide-react';
import { api } from '../services/api';
import { Badge, DataTable, ErrorBox, Loading, Panel, StatCard, fmtTime, useLoader } from '../components/ui';
import { PageHeader } from '../components/Layout';
import { ActivityChart, SeverityDoughnut } from '../charts/Charts';

export default function Overview() {
  const { data, loading, error, reload } = useLoader(async () => {
    const [stats, activity, recent, health, endpoints] = await Promise.all([
      api<any>('/dashboard/stats'),
      api<any>('/dashboard/activity?hours=24'),
      api<any>('/dashboard/recent?limit=8'),
      api<any>('/ingest/health'),
      api<any>('/endpoints'),
    ]);
    return { stats, activity, recent, health, endpoints };
  }, []);

  if (loading) return <Loading />;
  if (error || !data) return <ErrorBox error={error} onRetry={reload} />;

  const { stats, activity, recent, health, endpoints } = data;
  const onlineForwarders = endpoints.items?.filter((item: any) => item.status === 'online').length || 0;

  return (
    <>
      <PageHeader
        title="SOC Overview"
        description="Real-time posture from ingested events, detections, investigations and forwarder health."
        actions={
          <span className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-xs text-amber-300">
            SIMULATED LAB DATA
          </span>
        }
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total Events" value={stats.total_events} icon={<Activity className="h-5 w-5" />} tone="blue" hint="All ingested security events" />
        <StatCard label="Total Alerts" value={stats.total_alerts} icon={<ShieldAlert className="h-5 w-5" />} tone="amber" hint="Rule matches — leads, not proof" />
        <StatCard label="Critical Threats" value={stats.critical_threats} icon={<AlertOctagon className="h-5 w-5" />} tone="red" hint="Critical severity incidents" />
        <StatCard label="High-Risk Incidents" value={stats.high_risk_incidents} icon={<TrendingUp className="h-5 w-5" />} tone="red" hint="Risk score ≥ 60" />
        <StatCard label="Active Investigations" value={stats.active_investigations} icon={<Bot className="h-5 w-5" />} tone="blue" />
        <StatCard label="Resolved Incidents" value={stats.resolved_incidents} icon={<ShieldCheck className="h-5 w-5" />} tone="green" />
        <StatCard label="Forwarders Online" value={`${health.forwarders_online} / ${health.forwarders_online + health.forwarders_offline}`} icon={<Server className="h-5 w-5" />} tone="green" hint={`${onlineForwarders} endpoints reporting`} />
        <StatCard label="Events (5 min)" value={health.events_last_5m} icon={<Radio className="h-5 w-5" />} tone="blue" hint="Ingestion pipeline throughput" />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel title="Event Activity — 24 hours" className="xl:col-span-2">
          <ActivityChart series={activity.series} />
        </Panel>
        <Panel title="Alert Severity Distribution">
          <SeverityDoughnut data={stats.severity_distribution} />
          <div className="mt-2 grid grid-cols-2 gap-2 text-center text-xs">
            {Object.entries(stats.severity_distribution || {}).map(([key, value]) => (
              <div key={key} className="rounded-lg bg-navy-950/60 py-2">
                <p className="text-slate-400">{key}</p>
                <p className="font-bold text-white">{String(value)}</p>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="Recent Security Activity" actions={<Link className="text-xs text-sky-400 hover:underline" to="/logs">Open Log Explorer →</Link>}>
          <DataTable
            rows={recent.events}
            columns={[
              { key: 'timestamp', label: 'Time', render: (r) => fmtTime(r.timestamp) },
              { key: 'action', label: 'Action', render: (r) => <Badge>{r.action}</Badge> },
              { key: 'host', label: 'Host' },
              { key: 'username', label: 'User' },
              { key: 'source_ip', label: 'Source IP' },
              { key: 'message', label: 'Message', render: (r) => <span className="line-clamp-1">{r.message}</span> },
            ]}
          />
        </Panel>
        <Panel title="Recent Incidents" actions={<Link className="text-xs text-sky-400 hover:underline" to="/incidents">View all →</Link>}>
          <DataTable
            rows={recent.incidents}
            columns={[
              { key: 'incident_id', label: 'ID' },
              { key: 'title', label: 'Title', render: (r) => <span className="line-clamp-1">{r.title}</span> },
              { key: 'severity', label: 'Severity', render: (r) => <Badge>{r.severity}</Badge> },
              { key: 'risk_score', label: 'Risk', render: (r) => Math.round(r.risk_score) },
              { key: 'status', label: 'Status', render: (r) => <Badge>{r.status}</Badge> },
            ]}
          />
        </Panel>
      </div>
    </>
  );
}
