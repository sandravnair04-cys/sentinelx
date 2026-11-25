import { useCallback, useEffect, useState } from 'react';
import { Bookmark, BookmarkPlus, Search, X } from 'lucide-react';
import { api, del, post } from '../services/api';
import { Badge, DataTable, ErrorBox, Loading, fmtTime } from '../components/ui';
import { PageHeader } from '../components/Layout';

const SYNTAX = 'field:value  ·  "exact phrase"  ·  -term (exclude)  ·  fields: host, ip, user, severity, type, source, code, action, agent';

export default function LogExplorer() {
  const [query, setQuery] = useState('');
  const [filters, setFilters] = useState({ host: '', source_ip: '', username: '', severity: '', event_type: '' });
  const [range, setRange] = useState({ start: '', end: '' });
  const [result, setResult] = useState<any>(null);
  const [saved, setSaved] = useState<any[]>([]);
  const [saveName, setSaveName] = useState('');
  const [selected, setSelected] = useState<any>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const search = useCallback(async () => {
    const params = new URLSearchParams({ q: query, limit: '100' });
    Object.entries(filters).forEach(([key, value]) => {
      if (value) params.set(key, value);
    });
    if (range.start) params.set('start', new Date(range.start).toISOString());
    if (range.end) params.set('end', new Date(range.end).toISOString());
    setBusy(true);
    try {
      setResult(await api<any>(`/events/search?${params}`));
      setError('');
    } catch (exc: any) {
      setError(exc.message || String(exc));
    } finally {
      setBusy(false);
    }
  }, [query, filters, range]);

  const loadSaved = useCallback(async () => {
    try {
      setSaved((await api<any>('/searches')).items);
    } catch {
      // saved searches are optional
    }
  }, []);

  useEffect(() => {
    search();
    loadSaved();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const save = async () => {
    if (!saveName.trim()) return;
    try {
      await post('/searches', { name: saveName, query_text: query, filters });
      setSaveName('');
      await loadSaved();
    } catch (exc: any) {
      setError(exc.message || String(exc));
    }
  };

  return (
    <>
      <PageHeader
        title="Log Explorer"
        description="SIEM-style search across normalised security events with raw evidence inspection."
      />
      {error && <ErrorBox error={error} />}

      <div className="panel mb-4 space-y-4 p-4">
        <div className="flex flex-wrap gap-2">
          <div className="relative min-w-[280px] flex-1">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
            <input
              className="input pl-9"
              placeholder="Search logs — e.g. severity:high user:administrator"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && search()}
            />
          </div>
          <button className="btn btn-primary" onClick={search} disabled={busy}>
            <Search className="h-4 w-4" /> Search
          </button>
        </div>
        <p className="font-mono text-[11px] text-slate-500">{SYNTAX}</p>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
          {(['host', 'source_ip', 'username', 'severity', 'event_type'] as const).map((key) => (
            <div key={key}>
              <label className="label">{key}</label>
              <input
                className="input"
                value={filters[key]}
                placeholder={key === 'event_type' ? 'failed_login' : 'any'}
                onChange={(e) => setFilters({ ...filters, [key]: e.target.value })}
              />
            </div>
          ))}
        </div>
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label className="label">From</label>
            <input className="input" type="datetime-local" value={range.start} onChange={(e) => setRange({ ...range, start: e.target.value })} />
          </div>
          <div>
            <label className="label">To</label>
            <input className="input" type="datetime-local" value={range.end} onChange={(e) => setRange({ ...range, end: e.target.value })} />
          </div>
          <div className="flex items-end gap-2">
            <input className="input w-48" placeholder="Save as…" value={saveName} onChange={(e) => setSaveName(e.target.value)} />
            <button className="btn" onClick={save}><BookmarkPlus className="h-4 w-4" /> Save</button>
          </div>
          {saved.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <Bookmark className="h-4 w-4 text-slate-500" />
              {saved.map((item) => (
                <span key={item.id} className="inline-flex items-center gap-1 rounded-full bg-slate-700/50 px-2 py-1 text-xs">
                  <button onClick={() => { setQuery(item.query_text); setFilters(item.filters || {}); }}>{item.name}</button>
                  <button title="Delete" onClick={async () => { await del(`/searches/${item.id}`); loadSaved(); }}>
                    <X className="h-3 w-3 text-slate-400" />
                  </button>
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="panel p-4">
        <div className="mb-3 flex items-center justify-between text-xs text-slate-400">
          <span>{busy ? 'Searching…' : `${result?.total ?? 0} matching events`}</span>
          {result?.facets && (
            <span className="flex flex-wrap gap-2">
              {Object.entries(result.facets.severity || {}).map(([key, value]) => (
                <span key={key} className="rounded bg-slate-700/50 px-2 py-0.5">{key}: {String(value)}</span>
              ))}
            </span>
          )}
        </div>
        {!result && busy ? (
          <Loading />
        ) : (
          <DataTable
            rows={result?.items || []}
            empty="No events match these filters"
            columns={[
              { key: 'timestamp', label: 'Time', render: (r) => fmtTime(r.timestamp) },
              { key: 'source_type', label: 'Source', render: (r) => <Badge>{r.source_type}</Badge> },
              { key: 'event_code', label: 'ID' },
              { key: 'action', label: 'Action', render: (r) => <Badge>{r.action}</Badge> },
              { key: 'host', label: 'Host' },
              { key: 'username', label: 'User' },
              { key: 'source_ip', label: 'Source IP' },
              { key: 'message', label: 'Message', render: (r) => <button className="text-left text-sky-300 hover:underline" onClick={() => setSelected(r)}>{r.message?.slice(0, 80)}</button> },
            ]}
          />
        )}
      </div>

      {selected && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/70 p-4" onClick={() => setSelected(null)}>
          <div className="panel max-h-[85vh] w-full max-w-3xl overflow-y-auto p-5" onClick={(e) => e.stopPropagation()}>
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-lg font-bold text-white">Event {selected.event_uid?.slice(0, 16)}</h3>
              <button onClick={() => setSelected(null)}><X className="h-5 w-5 text-slate-400" /></button>
            </div>
            <div className="grid grid-cols-2 gap-3 text-sm md:grid-cols-3">
              {Object.entries(selected).filter(([key]) => key !== 'normalized' && key !== 'raw_event').map(([key, value]) => (
                <div key={key} className="rounded-lg bg-navy-950/60 p-2">
                  <p className="text-[10px] uppercase tracking-wider text-slate-500">{key}</p>
                  <p className="break-all text-slate-300">{String(value ?? '—')}</p>
                </div>
              ))}
            </div>
            <h4 className="mt-5 text-sm font-semibold text-sky-300">Normalised event (JSON)</h4>
            <pre className="mt-2 max-h-60 overflow-auto rounded-lg bg-navy-950 p-3 font-mono text-xs text-emerald-300">
              {JSON.stringify(selected.normalized, null, 2)}
            </pre>
            <h4 className="mt-4 text-sm font-semibold text-sky-300">Raw event</h4>
            <pre className="mt-2 max-h-60 overflow-auto whitespace-pre-wrap rounded-lg bg-navy-950 p-3 font-mono text-xs text-amber-200">
              {selected.raw_event || '—'}
            </pre>
          </div>
        </div>
      )}
    </>
  );
}
