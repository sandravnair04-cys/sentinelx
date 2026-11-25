import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { AlertTriangle, Loader2, RefreshCw } from 'lucide-react';
import { ApiError } from '../services/api';

export function Panel({
  title,
  subtitle,
  actions,
  children,
  className = '',
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-header">
        <div>
          <h2 className="panel-title">{title}</h2>
          {subtitle && <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p>}
        </div>
        {actions}
      </div>
      <div className="p-4">{children}</div>
    </section>
  );
}

export function StatCard({
  label,
  value,
  icon,
  tone = 'blue',
  hint,
}: {
  label: string;
  value: string | number;
  icon: ReactNode;
  tone?: 'blue' | 'green' | 'amber' | 'red' | 'slate';
  hint?: string;
}) {
  const tones: Record<string, string> = {
    blue: 'text-sky-400 bg-sky-500/10 border-sky-500/20',
    green: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    amber: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
    red: 'text-red-400 bg-red-500/10 border-red-500/20',
    slate: 'text-slate-400 bg-slate-500/10 border-slate-500/20',
  };
  return (
    <div className="panel flex items-center gap-4 p-4">
      <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border ${tones[tone]}`}>
        {icon}
      </div>
      <div className="min-w-0">
        <p className="truncate text-xs font-semibold uppercase tracking-wider text-slate-400">{label}</p>
        <p className="mt-1 text-2xl font-bold text-white">{value}</p>
        {hint && <p className="mt-0.5 truncate text-xs text-slate-500">{hint}</p>}
      </div>
    </div>
  );
}

export function Badge({ children, tone = 'slate' }: { children: ReactNode; tone?: string }) {
  const value = String(children ?? '').toUpperCase();
  const resolved =
    ['CRITICAL', 'HIGH', 'RED', 'FAILED', 'REJECTED', 'OFFLINE', 'REVOKED'].includes(value)
      ? 'red'
      : ['MEDIUM', 'AMBER', 'PENDING', 'WAITING_APPROVAL', 'DEGRADED', 'INVESTIGATING'].includes(value)
        ? 'amber'
        : ['LOW', 'GREEN', 'ONLINE', 'ACTIVE', 'ACCEPTED', 'APPROVED', 'RESOLVED', 'COMPLETED', 'HEALTHY', 'SUCCESS'].includes(value)
          ? 'green'
          : ['INFO', 'BLUE', 'RUNNING'].includes(value)
            ? 'blue'
            : 'slate';
  const tones: Record<string, string> = {
    red: 'bg-red-500/15 text-red-300 ring-1 ring-red-500/30',
    amber: 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30',
    green: 'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30',
    blue: 'bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/30',
    slate: 'bg-slate-500/15 text-slate-300 ring-1 ring-slate-500/30',
  };
  return <span className={`badge ${tones[resolved]}`}>{children}</span>;
}

export type Column = {
  key: string;
  label: string;
  render?: (row: any) => ReactNode;
  className?: string;
};

export function DataTable({
  columns,
  rows,
  empty = 'No records found',
}: {
  columns: Column[];
  rows: any[];
  empty?: string;
}) {
  if (!rows.length) return <EmptyState message={empty} />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse">
        <thead>
          <tr className="border-b border-slate-700/60">
            {columns.map((column) => (
              <th key={column.key} className={`th ${column.className || ''}`}>{column.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index} className="border-b border-slate-800/70 transition hover:bg-sky-500/5">
              {columns.map((column) => (
                <td key={column.key} className={`td ${column.className || ''}`}>
                  {column.render ? column.render(row) : String((row as any)?.[column.key] ?? '—')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-12 text-center text-slate-500">
      <AlertTriangle className="h-6 w-6" />
      <p className="text-sm">{message}</p>
    </div>
  );
}

export function Loading() {
  return (
    <div className="flex items-center justify-center gap-2 py-12 text-sky-300">
      <Loader2 className="h-5 w-5 animate-spin" />
      <span className="text-sm">Loading…</span>
    </div>
  );
}

export function ErrorBox({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-start gap-3 rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">
      <span>{error}</span>
      {onRetry && (
        <button className="btn btn-danger" onClick={onRetry}>
          <RefreshCw className="h-4 w-4" /> Retry
        </button>
      )}
    </div>
  );
}

export function useLoader<T>(loader: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const load = useCallback(loader, deps);

  const reload = useCallback(() => {
    setLoading(true);
    setError('');
    load()
      .then(setData)
      .catch((exc: unknown) => setError(exc instanceof ApiError ? exc.message : String(exc)))
      .finally(() => setLoading(false));
  }, [load]);

  useEffect(() => {
    reload();
  }, [reload]);

  return { data, loading, error, reload, setData };
}

export function fmtTime(value?: string | null): string {
  if (!value) return '—';
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

export function fmtNum(value?: number): string {
  return typeof value === 'number' ? value.toLocaleString() : '—';
}
