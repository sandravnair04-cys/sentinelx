import { useState } from 'react';
import { Crosshair, Search } from 'lucide-react';
import { api, post } from '../services/api';
import { Badge, DataTable, ErrorBox, Loading, Panel, StatCard, fmtTime, useLoader } from '../components/ui';
import { PageHeader } from '../components/Layout';

export default function ThreatIntel() {
  const { data, loading, error, reload } = useLoader(async () => {
    const [status, results] = await Promise.all([
      api<any>('/threat-intel/status'),
      api<any>('/threat-intel/results?limit=100'),
    ]);
    return { status, results };
  }, []);
  const [indicator, setIndicator] = useState('');
  const [kind, setKind] = useState('ip');
  const [message, setMessage] = useState('');

  if (loading) return <Loading />;
  if (error || !data) return <ErrorBox error={error} onRetry={reload} />;

  const lookup = async () => {
    if (!indicator) return;
    try {
      const result = await post<any>('/threat-intel/lookup', { indicator, indicator_type: kind });
      setMessage(`${indicator}: ${result.verdict || JSON.stringify(result).slice(0, 160)}`);
      await reload();
    } catch (exc: any) {
      setMessage(`Error: ${exc.message}`);
    }
  };

  return (
    <>
      <PageHeader
        title="Threat Intelligence"
        description="Optional reputation lookups with caching and explicit unknown results. No local log content is uploaded."
      />
      {message && <p className="mb-3 text-sm text-sky-300">{message}</p>}
      <div className="mb-4 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard label="Lookup Status" value={data.status.enabled ? 'Enabled' : 'Local only'} icon={<Crosshair className="h-5 w-5" />} tone={data.status.enabled ? 'green' : 'slate'} />
        <StatCard label="Cached Results" value={data.results.items.length} icon={<Crosshair className="h-5 w-5" />} tone="blue" />
        <StatCard label="Malicious Verdicts" value={data.results.items.filter((r: any) => r.verdict === 'malicious').length} icon={<Crosshair className="h-5 w-5" />} tone="red" />
      </div>
      <Panel title="Reputation Lookup" className="mb-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[240px] flex-1">
            <label className="label">Indicator (IP, domain or hash)</label>
            <input className="input" value={indicator} onChange={(e) => setIndicator(e.target.value)} placeholder="203.0.113.77" />
          </div>
          <div>
            <label className="label">Type</label>
            <select className="input" value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="ip">IP address</option>
              <option value="domain">Domain</option>
              <option value="md5">MD5</option>
              <option value="sha1">SHA-1</option>
              <option value="sha256">SHA-256</option>
            </select>
          </div>
          <button className="btn btn-primary" onClick={lookup}><Search className="h-4 w-4" /> Look up</button>
        </div>
      </Panel>
      <Panel title="Recent Results">
        <DataTable
          rows={data.results.items}
          empty="No reputation lookups yet"
          columns={[
            { key: 'indicator', label: 'Indicator', render: (r) => <code className="text-xs text-sky-300">{r.indicator}</code> },
            { key: 'indicator_type', label: 'Type' },
            { key: 'provider', label: 'Provider' },
            { key: 'verdict', label: 'Verdict', render: (r) => <Badge>{r.verdict}</Badge> },
            { key: 'score', label: 'Score', render: (r) => Math.round(r.score) },
            { key: 'cached_at', label: 'Cached', render: (r) => fmtTime(r.cached_at) },
          ]}
        />
      </Panel>
    </>
  );
}
