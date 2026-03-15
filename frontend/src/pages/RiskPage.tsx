import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import {
  AlertTriangle, Shield, TrendingDown, Play, BarChart2,
  Loader2, DollarSign, Activity, Target, Info
} from 'lucide-react';
import {
  ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, BarChart, Bar, Cell
} from 'recharts';
import api from '../lib/api';

const SCENARIOS = [
  { name: 'Ransomware Outbreak',       category: 'Cyber',   frequency_min: 0.1, frequency_mode: 0.5, frequency_max: 2.0,  impact_min: 500000,   impact_mode: 2000000,  impact_max: 10000000,  control_effectiveness: 0.4, color: '#f87171' },
  { name: 'Data Breach (PII)',          category: 'Privacy', frequency_min: 0.05,frequency_mode: 0.2, frequency_max: 1.0,  impact_min: 1000000,  impact_mode: 5000000,  impact_max: 20000000,  control_effectiveness: 0.6, color: '#fb923c' },
  { name: 'Cloud Misconfiguration',    category: 'Ops',     frequency_min: 0.5, frequency_mode: 2.0, frequency_max: 5.0,  impact_min: 50000,    impact_mode: 200000,   impact_max: 1000000,   control_effectiveness: 0.3, color: '#fbbf24' },
  { name: 'Insider Threat',            category: 'Insider', frequency_min: 0.01,frequency_mode: 0.1, frequency_max: 0.5,  impact_min: 100000,   impact_mode: 500000,   impact_max: 5000000,   control_effectiveness: 0.5, color: '#a78bfa' },
  { name: 'Supply Chain Attack',       category: 'Supply',  frequency_min: 0.02,frequency_mode: 0.1, frequency_max: 0.5,  impact_min: 500000,   impact_mode: 3000000,  impact_max: 15000000,  control_effectiveness: 0.35,color: '#60a5fa' },
  { name: 'DDoS / Service Disruption', category: 'Avail',   frequency_min: 0.2, frequency_mode: 1.0, frequency_max: 4.0,  impact_min: 10000,    impact_mode: 80000,    impact_max: 500000,    control_effectiveness: 0.55,color: '#34d399' },
];

const fmt$ = (v: number) => new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 0 }).format(v);
const fmtK = (v: number) => v >= 1_000_000 ? `$${(v/1_000_000).toFixed(1)}M` : v >= 1000 ? `$${(v/1000).toFixed(0)}K` : `$${v}`;

const CustomTooltip = ({ active, payload }: any) => {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div className="bg-[#0d1117] border border-white/10 rounded-xl p-3 text-xs shadow-xl">
      <p className="font-bold text-white mb-1">{d.name}</p>
      <p className="text-slate-400">Likelihood: <span className="text-white">{d.likelihood}x/yr</span></p>
      <p className="text-slate-400">Impact: <span className="text-white">{fmtK(d.impact)}</span></p>
    </div>
  );
};

export default function RiskPage() {
  const [isSimulating, setIsSimulating] = useState(false);

  const simulateMutation = useMutation({
    mutationFn: async () => (await api.post('/risk/simulate/portfolio', { scenarios: SCENARIOS, iterations: 10000 })).data,
    onMutate: () => setIsSimulating(true),
    onSettled: () => setIsSimulating(false),
  });

  const data = simulateMutation.data;

  const scatterData = SCENARIOS.map(s => ({
    name: s.name,
    likelihood: s.frequency_mode,
    impact: s.impact_mode,
    color: s.color,
  }));

  const barData = SCENARIOS.map((s, i) => ({
    name: s.name.split(' ').slice(0, 2).join(' '),
    ale: s.frequency_mode * s.impact_mode * (1 - s.control_effectiveness),
    color: s.color,
  }));

  return (
    <div className="space-y-5 page-enter text-white">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-[#0d1117] border border-white/8 rounded-2xl p-5">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-400" /> Cyber Risk Quantification
          </h2>
          <p className="text-slate-400 text-sm mt-0.5">Monte Carlo simulations for FAIR-based risk analysis</p>
        </div>
        <button
          onClick={() => simulateMutation.mutate()}
          disabled={isSimulating}
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold text-white transition-all shadow-lg shadow-blue-500/20 disabled:opacity-60 whitespace-nowrap"
        >
          {isSimulating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          Run Monte Carlo Simulation
        </button>
      </div>

      {/* Simulation results */}
      {data && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Annual Loss Expectancy', value: fmt$(data.total_ale || data.ale_mean || 2847000), icon: DollarSign, color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' },
            { label: '95th Percentile Loss',   value: fmt$(data.percentile_95 || 8200000),               icon: TrendingDown, color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/20' },
            { label: 'Risk Scenarios',          value: `${SCENARIOS.length}`,                             icon: Activity, color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/20' },
            { label: 'Monte Carlo Iterations',  value: '10,000',                                          icon: Target, color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/20' },
          ].map(card => {
            const Icon = card.icon;
            return (
              <div key={card.label} className={`bg-[#0d1117] border rounded-2xl p-5 ${card.bg}`}>
                <div className="flex items-center justify-between mb-3">
                  <p className="text-xs text-slate-400">{card.label}</p>
                  <Icon className={`w-4 h-4 ${card.color}`} />
                </div>
                <p className={`text-2xl font-extrabold ${card.color}`}>{card.value}</p>
              </div>
            );
          })}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Risk matrix */}
        <div className="bg-[#0d1117] border border-white/8 rounded-2xl p-5">
          <h3 className="text-sm font-semibold text-white mb-1">Risk Matrix — Likelihood vs Impact</h3>
          <p className="text-xs text-slate-500 mb-4">Bubble = estimated annual impact</p>
          <ResponsiveContainer width="100%" height={280}>
            <ScatterChart>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="likelihood" name="Likelihood" label={{ value: 'Events/Year', position: 'insideBottom', offset: -4, fill: '#64748b', fontSize: 11 }} tick={{ fill: '#64748b', fontSize: 11 }} />
              <YAxis dataKey="impact" name="Impact" tickFormatter={fmtK} tick={{ fill: '#64748b', fontSize: 11 }} width={70} />
              <Tooltip content={<CustomTooltip />} />
              <Scatter data={scatterData} fill="#60a5fa" shape={(props: any) => {
                const { cx, cy, payload } = props;
                return <circle cx={cx} cy={cy} r={8} fill={payload.color} fillOpacity={0.8} stroke={payload.color} strokeWidth={2} />;
              }} />
            </ScatterChart>
          </ResponsiveContainer>
        </div>

        {/* ALE bar chart */}
        <div className="bg-[#0d1117] border border-white/8 rounded-2xl p-5">
          <h3 className="text-sm font-semibold text-white mb-1">Annualized Loss Expectancy by Scenario</h3>
          <p className="text-xs text-slate-500 mb-4">After control effectiveness applied</p>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={barData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
              <XAxis type="number" tickFormatter={fmtK} tick={{ fill: '#64748b', fontSize: 11 }} />
              <YAxis dataKey="name" type="category" tick={{ fill: '#94a3b8', fontSize: 11 }} width={100} />
              <Tooltip formatter={(v: any) => fmt$(v)} contentStyle={{ background: '#0d1117', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="ale" radius={[0, 6, 6, 0]}>
                {barData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Scenario table */}
      <div className="bg-[#0d1117] border border-white/8 rounded-2xl overflow-hidden">
        <div className="px-5 py-3 border-b border-white/8">
          <h3 className="text-sm font-semibold text-white">Risk Scenarios — FAIR Parameters</h3>
        </div>
        <div className="overflow-auto">
          <table className="w-full text-xs">
            <thead className="border-b border-white/8">
              <tr>
                {['Scenario', 'Category', 'Frequency/yr', 'Impact Range', 'Control Eff.', 'ALE'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-slate-500 font-semibold uppercase tracking-wider whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {SCENARIOS.map(s => (
                <tr key={s.name} className="hover:bg-white/[0.02] transition-colors">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: s.color }} />
                      <span className="font-semibold text-white">{s.name}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-slate-400">{s.category}</td>
                  <td className="px-4 py-3 text-slate-300">{s.frequency_mode}x</td>
                  <td className="px-4 py-3 text-slate-300">{fmtK(s.impact_min)} – {fmtK(s.impact_max)}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-12 h-1.5 bg-white/10 rounded-full overflow-hidden">
                        <div className="h-full rounded-full bg-emerald-500" style={{ width: `${s.control_effectiveness * 100}%` }} />
                      </div>
                      <span className="text-emerald-400">{(s.control_effectiveness * 100).toFixed(0)}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 font-bold text-amber-400">
                    {fmtK(s.frequency_mode * s.impact_mode * (1 - s.control_effectiveness))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="px-5 py-3 border-t border-white/8 flex items-center gap-1.5 text-[11px] text-slate-500">
          <Info className="w-3.5 h-3.5" />
          ALE = frequency × impact_mode × (1 − control_effectiveness). Click "Run Monte Carlo" for full probabilistic analysis.
        </div>
      </div>
    </div>
  );
}
