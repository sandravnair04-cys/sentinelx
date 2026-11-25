import { useState } from 'react';
import { Network } from 'lucide-react';
import { api } from '../services/api';
import { Badge, ErrorBox, Loading, Panel, StatCard, useLoader } from '../components/ui';
import { PageHeader } from '../components/Layout';
import { MitreBar } from '../charts/Charts';

export default function MitreExplorer() {
  const { data, loading, error, reload } = useLoader(async () => {
    const [tactics, techniques, coverage] = await Promise.all([
      api<any>('/mitre/tactics'),
      api<any>('/mitre/techniques'),
      api<any>('/mitre/coverage'),
    ]);
    return { tactics, techniques, coverage };
  }, []);
  const [tactic, setTactic] = useState('');
  const [search, setSearch] = useState('');

  if (loading) return <Loading />;
  if (error || !data) return <ErrorBox error={error} onRetry={reload} />;

  const filtered = data.techniques.items.filter((item: any) => {
    const matchesTactic = !tactic || item.tactics?.includes(tactic);
    const needle = search.toLowerCase();
    const matchesSearch = !needle || item.id.toLowerCase().includes(needle) || item.name.toLowerCase().includes(needle);
    return matchesTactic && matchesSearch;
  });

  return (
    <>
      <PageHeader
        title="MITRE ATT&CK Explorer"
        description="Curated technique subset mapped to SENTINELX detections, with local observation coverage."
      />
      <div className="mb-4 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard label="Tactics" value={data.tactics.items.length} icon={<Network className="h-5 w-5" />} tone="blue" />
        <StatCard label="Techniques" value={data.techniques.total} icon={<Network className="h-5 w-5" />} tone="slate" />
        <StatCard label="Local Coverage" value={`${data.coverage.coverage_percent}%`} icon={<Network className="h-5 w-5" />} tone="green" hint={`${data.coverage.covered_count} techniques observed`} />
      </div>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel title="Tactics" className="xl:col-span-1">
          <div className="space-y-1">
            <button className={`block w-full rounded-lg px-3 py-2 text-left text-sm ${!tactic ? 'bg-sky-500/15 text-sky-200' : 'text-slate-400 hover:bg-slate-700/30'}`} onClick={() => setTactic('')}>All tactics</button>
            {data.tactics.items.map((item: any) => (
              <button key={item.id} className={`block w-full rounded-lg px-3 py-2 text-left text-sm ${tactic === item.id ? 'bg-sky-500/15 text-sky-200' : 'text-slate-400 hover:bg-slate-700/30'}`} onClick={() => setTactic(item.id)}>
                <span className="font-mono text-xs text-slate-500">{item.id}</span> {item.name}
              </button>
            ))}
          </div>
        </Panel>
        <Panel title="Techniques" className="xl:col-span-2">
          <div className="mb-3 flex flex-wrap gap-2">
            <input className="input max-w-xs" placeholder="Search technique or ID…" value={search} onChange={(e) => setSearch(e.target.value)} />
            <span className="self-center text-xs text-slate-500">{filtered.length} techniques</span>
          </div>
          <div className="max-h-[560px] space-y-2 overflow-y-auto pr-1">
            {filtered.map((item: any) => (
              <details key={item.id} className="rounded-lg border border-slate-700/60 bg-navy-950/40 p-3">
                <summary className="cursor-pointer text-sm text-slate-200">
                  <span className="mr-2 font-mono text-xs text-sky-400">{item.id}</span>{item.name}
                </summary>
                <p className="mt-2 text-xs text-slate-400">{item.description}</p>
                <div className="mt-2 flex flex-wrap gap-1">
                  {item.tactics?.map((value: string) => <Badge key={value}>{value}</Badge>)}
                  {item.sentinelx_rules?.map((rule: string) => <Badge key={rule}>{rule}</Badge>)}
                </div>
              </details>
            ))}
          </div>
        </Panel>
      </div>
      <Panel title="Observed Technique Coverage" className="mt-4" subtitle="Derived from local alerts and incidents">
        {data.coverage.items.length ? <MitreBar data={data.coverage.items} /> : <p className="text-sm text-slate-500">No MITRE-mapped alerts or incidents observed yet.</p>}
      </Panel>
    </>
  );
}
