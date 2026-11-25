import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  RadialBar,
  RadialBarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

const tooltipStyle = {
  backgroundColor: '#0a1226',
  border: '1px solid #1a2f57',
  borderRadius: 8,
  fontSize: 12,
};

export function SeverityDoughnut({ data }: { data: Record<string, number> }) {
  const rows = Object.entries(data || {}).map(([name, value]) => ({ name, value }));
  const colors: Record<string, string> = {
    LOW: '#38bdf8',
    MEDIUM: '#fbbf24',
    HIGH: '#fb923c',
    CRITICAL: '#f87171',
  };
  return (
    <ResponsiveContainer width="100%" height={230}>
      <PieChart>
        <Pie data={rows} dataKey="value" nameKey="name" innerRadius={58} outerRadius={88} paddingAngle={3}>
          {rows.map((entry) => (
            <Cell key={entry.name} fill={colors[entry.name] || '#64748b'} />
          ))}
        </Pie>
        <Tooltip contentStyle={tooltipStyle} />
      </PieChart>
    </ResponsiveContainer>
  );
}

export function ActivityChart({ series }: { series: any[] }) {
  const rows = (series || []).map((item) => ({
    ...item,
    hour: new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
  }));
  return (
    <ResponsiveContainer width="100%" height={260}>
      <AreaChart data={rows} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="eventsFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.45} />
            <stop offset="100%" stopColor="#38bdf8" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="#1a2f57" strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="hour" tick={{ fill: '#64748b', fontSize: 10 }} minTickGap={24} />
        <YAxis tick={{ fill: '#64748b', fontSize: 10 }} allowDecimals={false} />
        <Tooltip contentStyle={tooltipStyle} />
        <Area type="monotone" dataKey="events" name="Events" stroke="#38bdf8" fill="url(#eventsFill)" strokeWidth={2} />
        <Area type="monotone" dataKey="failures" name="Failures" stroke="#f87171" fill="transparent" strokeWidth={1.5} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function RiskGauge({ score }: { score: number }) {
  const color = score >= 80 ? '#f87171' : score >= 60 ? '#fb923c' : score >= 30 ? '#fbbf24' : '#34d399';
  const data = [{ name: 'risk', value: Math.max(0, Math.min(100, score)), fill: color }];
  return (
    <div className="relative">
      <ResponsiveContainer width="100%" height={190}>
        <RadialBarChart
          innerRadius="78%"
          outerRadius="100%"
          data={data}
          startAngle={220}
          endAngle={-40}
        >
          <RadialBar dataKey="value" cornerRadius={8} background={{ fill: '#1a2f57' }} />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold text-white">{Math.round(score)}</span>
        <span className="text-xs uppercase tracking-widest text-slate-400">Risk / 100</span>
      </div>
    </div>
  );
}

export function MitreBar({ data }: { data: { id: string; name: string; observations: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={Math.max(200, data.length * 38)}>
      <BarChart data={data} layout="vertical" margin={{ left: 10, right: 20 }}>
        <CartesianGrid stroke="#1a2f57" strokeDasharray="3 3" horizontal={false} />
        <XAxis type="number" tick={{ fill: '#64748b', fontSize: 10 }} allowDecimals={false} />
        <YAxis type="category" dataKey="id" width={72} tick={{ fill: '#94a3b8', fontSize: 10 }} />
        <Tooltip contentStyle={tooltipStyle} />
        <Bar dataKey="observations" name="Observations" fill="#38bdf8" radius={[0, 4, 4, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
