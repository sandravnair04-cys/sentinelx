import { useState, type FormEvent, type ReactNode } from 'react';
import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  Activity, Bot, Crosshair, FilePlus2, FileText, FolderOpen, LayoutDashboard, LogOut, Menu,
  Monitor, Network, Radio, Search, Server, Settings, ShieldAlert, ShieldCheck, X,
} from 'lucide-react';
import { useAuth } from '../state/AuthContext';
import { api } from '../services/api';

export const NAV = [
  { to: '/', label: 'SOC Overview', icon: LayoutDashboard, end: true },
  { to: '/monitoring', label: 'Live Monitoring', icon: Radio },
  { to: '/submit', label: 'Submit Event', icon: FilePlus2 },
  { to: '/logs', label: 'Log Explorer', icon: Search },
  { to: '/endpoints', label: 'Endpoint Management', icon: Monitor },
  { to: '/forwarders', label: 'Forwarder Management', icon: Server },
  { to: '/detection', label: 'Threat Detection', icon: ShieldAlert },
  { to: '/investigation', label: 'AI Investigation', icon: Bot },
  { to: '/incidents', label: 'Incident Management', icon: FolderOpen },
  { to: '/response', label: 'Response Centre', icon: ShieldCheck },
  { to: '/agents', label: 'Agent Monitoring', icon: Activity },
  { to: '/intel', label: 'Threat Intelligence', icon: Crosshair },
  { to: '/mitre', label: 'MITRE ATT&CK', icon: Network },
  { to: '/reports', label: 'Security Reports', icon: FileText },
  { to: '/settings', label: 'System Settings', icon: Settings },
];

export function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);

  const doLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="flex min-h-screen">
      <aside
        className={`fixed inset-y-0 left-0 z-30 flex w-64 flex-col border-r border-slate-700/60 bg-navy-900/95 transition-transform lg:static lg:translate-x-0 ${
          open ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex h-16 items-center justify-between border-b border-slate-700/60 px-5">
          <Link to="/" className="flex items-center gap-2" onClick={() => setOpen(false)}>
            <ShieldCheck className="h-6 w-6 text-sky-400" />
            <div>
              <p className="text-base font-bold tracking-wide text-white">SENTINELX</p>
              <p className="text-[10px] uppercase tracking-[0.2em] text-sky-400/80">Agentic AI SOC</p>
            </div>
          </Link>
          <button className="lg:hidden" onClick={() => setOpen(false)} aria-label="Close navigation">
            <X className="h-5 w-5 text-slate-400" />
          </button>
        </div>
        <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 py-4">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              onClick={() => setOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition ${
                  isActive
                    ? 'bg-sky-500/15 font-semibold text-sky-200 ring-1 ring-sky-500/25'
                    : 'text-slate-400 hover:bg-slate-700/30 hover:text-slate-100'
                }`
              }
            >
              <Icon className="h-4 w-4 shrink-0" />
              <span className="truncate">{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-slate-700/60 p-4">
          <div className="mb-3 flex items-center justify-between">
            <div className="min-w-0">
              <p className="truncate text-sm font-medium text-slate-200">{user?.username || 'Analyst'}</p>
              <p className="text-xs uppercase tracking-wider text-sky-400">{user?.role}</p>
            </div>
            <button className="btn px-2 py-1" onClick={doLogout} title="Sign out">
              <LogOut className="h-4 w-4" />
            </button>
          </div>
          <p className="text-[10px] leading-relaxed text-slate-600">
            Intelligent Security. Automated Investigation. Human-Controlled Response.
          </p>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-16 shrink-0 items-center gap-4 border-b border-slate-700/60 bg-navy-900/60 px-4 backdrop-blur">
          <button className="lg:hidden" onClick={() => setOpen(true)} aria-label="Open navigation">
            <Menu className="h-5 w-5 text-slate-300" />
          </button>
          <div className="min-w-0 flex-1">
            <h1 className="truncate text-sm font-semibold text-slate-300">
              Security Operations Centre
            </h1>
            <p className="text-xs text-slate-500">Lab environment — all response actions are simulated</p>
          </div>
          <div className="hidden items-center gap-2 rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-3 py-1.5 sm:flex">
            <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" />
            <span className="text-xs font-medium text-emerald-300">SYSTEM OPERATIONAL</span>
          </div>
        </header>
        <main className="min-w-0 flex-1 overflow-x-hidden p-4 lg:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      await login(username, password);
      navigate('/');
    } catch (exc: any) {
      setError(exc?.message || 'Login failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="mb-8 text-center">
          <ShieldCheck className="mx-auto h-12 w-12 text-sky-400" />
          <h1 className="mt-4 text-3xl font-bold tracking-wide text-white">SENTINELX</h1>
          <p className="mt-1 text-sm uppercase tracking-[0.25em] text-sky-400">Agentic AI SOC Analyst</p>
          <p className="mt-4 text-xs text-slate-500">Intelligent Security. Automated Investigation. Human-Controlled Response.</p>
        </div>
        <form onSubmit={submit} className="panel space-y-4 p-6">
          <div>
            <label className="label">Username</label>
            <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
          </div>
          <div>
            <label className="label">Password</label>
            <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          {error && <p className="text-sm text-red-400">{error}</p>}
          <button className="btn btn-primary w-full justify-center" disabled={busy} type="submit">
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
          <p className="text-center text-xs text-slate-500">
            Lab accounts: admin / Admin@123! · analyst / Analyst@123!
          </p>
        </form>
      </div>
    </div>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 className="text-xl font-bold text-white">{title}</h2>
        {description && <p className="mt-1 text-sm text-slate-400">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}
