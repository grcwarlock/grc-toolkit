import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  HardDrive, Search, AlertTriangle, CheckCircle, RefreshCw,
  Database, Cloud, Code, FileText, MessageSquare, Shield,
  ChevronDown, ChevronRight, Zap, Eye, Filter, Loader2
} from 'lucide-react';
import api from '../lib/api';

interface Finding { type: string; count: number; severity: string; description: string; }
interface DataSilo {
  id: string; name: string; source_type: string; provider: string;
  connected: boolean; last_scanned: string | null; status: string;
  risk_level: string; total_objects: number; flagged_objects: number;
  data_types: string[]; frameworks: string[]; findings: Finding[];
}
interface SiloSummary {
  total_silos: number; connected: number; total_flagged: number;
  critical_findings: number; high_risk_silos: number; silos: DataSilo[];
}

const SOURCE_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  cloud_storage: Cloud, source_control: Code, database: Database,
  document_store: FileText, data_warehouse: HardDrive, messaging: MessageSquare,
  default: HardDrive,
};

const RISK_CLASSES: Record<string, { card: string; badge: string }> = {
  critical: { card: 'border-red-500/30',    badge: 'bg-red-500/15 text-red-400 border-red-500/20' },
  high:     { card: 'border-orange-500/30', badge: 'bg-orange-500/15 text-orange-400 border-orange-500/20' },
  medium:   { card: 'border-amber-500/30',  badge: 'bg-amber-500/15 text-amber-400 border-amber-500/20' },
  low:      { card: 'border-emerald-500/30',badge: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20' },
  unknown:  { card: 'border-white/8',       badge: 'bg-slate-500/15 text-slate-400 border-slate-500/20' },
};

const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-amber-500', low: 'bg-blue-500', unknown: 'bg-slate-500',
};

const FW_CLASSES: Record<string, string> = {
  'HIPAA':      'bg-blue-500/10 border-blue-500/20 text-blue-400',
  'SOC 2':      'bg-violet-500/10 border-violet-500/20 text-violet-400',
  'NIST 800-53':'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
  'ISO 27001':  'bg-amber-500/10 border-amber-500/20 text-amber-400',
  'CMMC L2':    'bg-orange-500/10 border-orange-500/20 text-orange-400',
};

export default function DataSilosPage() {
  const queryClient = useQueryClient();
  const [filter, setFilter] = useState<'all' | 'connected' | 'findings'>('all');
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const { data, isLoading } = useQuery<SiloSummary>({
    queryKey: ['data-silos'],
    queryFn: async () => (await api.get('/data-silos/')).data,
    refetchInterval: 30000,
  });

  const scanMutation = useMutation({
    mutationFn: async (siloId: string) => (await api.post(`/data-silos/${siloId}/scan`)).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['data-silos'] }),
  });

  const scanAllMutation = useMutation({
    mutationFn: async () => (await api.post('/data-silos/scan-all')).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['data-silos'] }),
  });

  const silos = data?.silos ?? [];
  const filtered = silos.filter(s => {
    if (filter === 'connected' && !s.connected) return false;
    if (filter === 'findings' && !s.flagged_objects) return false;
    if (search && !s.name.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="space-y-5 page-enter text-white">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-[#0d1117] border border-white/8 rounded-2xl p-5">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <HardDrive className="w-5 h-5 text-amber-400" /> Data Silos
          </h2>
          <p className="text-slate-400 text-sm mt-0.5">PII, PHI, and secrets discovery across your entire data landscape</p>
        </div>
        <button
          onClick={() => scanAllMutation.mutate()}
          disabled={scanAllMutation.isPending}
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold transition-all shadow-lg shadow-blue-500/20 disabled:opacity-60 whitespace-nowrap"
        >
          {scanAllMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
          Scan All Connected
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Data Sources',    value: data?.total_silos ?? 0,       sub: `${data?.connected ?? 0} connected`,         icon: Database,      cls: 'text-blue-400',   border: 'border-blue-500/20' },
          { label: 'Total Flagged',   value: data?.total_flagged ?? 0,     sub: 'objects with sensitive data',               icon: Eye,           cls: 'text-amber-400',  border: 'border-amber-500/20' },
          { label: 'Critical Findings',value: data?.critical_findings ?? 0,sub: 'need immediate action',                     icon: AlertTriangle, cls: 'text-red-400',    border: 'border-red-500/20' },
          { label: 'High Risk Silos',  value: data?.high_risk_silos ?? 0,  sub: 'require remediation',                       icon: Shield,        cls: 'text-orange-400', border: 'border-orange-500/20' },
        ].map(s => {
          const Icon = s.icon;
          return (
            <div key={s.label} className={`bg-[#0d1117] border ${s.border} rounded-2xl p-5`}>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs text-slate-400">{s.label}</p>
                <Icon className={`w-4 h-4 ${s.cls}`} />
              </div>
              <p className={`text-3xl font-extrabold ${s.cls} mb-0.5`}>{s.value.toLocaleString()}</p>
              <p className="text-[11px] text-slate-500">{s.sub}</p>
            </div>
          );
        })}
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="flex gap-1 bg-[#0d1117] border border-white/8 p-1 rounded-xl">
          {(['all', 'connected', 'findings'] as const).map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all capitalize ${filter === f ? 'bg-white/10 text-white' : 'text-slate-500 hover:text-slate-300'}`}
            >
              {f === 'findings' ? 'With Findings' : f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text" value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search data sources…"
            className="w-full bg-[#0d1117] border border-white/8 rounded-xl pl-9 pr-4 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20"
          />
        </div>
      </div>

      {/* Silo cards */}
      <div className="space-y-3">
        {isLoading ? (
          Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="bg-[#0d1117] border border-white/8 rounded-2xl p-5 animate-pulse">
              <div className="h-4 bg-white/5 rounded w-1/3 mb-3" />
              <div className="h-3 bg-white/5 rounded w-2/3" />
            </div>
          ))
        ) : filtered.map(silo => {
          const SrcIcon = SOURCE_ICONS[silo.source_type] ?? HardDrive;
          const risk = silo.risk_level?.toLowerCase() ?? 'unknown';
          const riskCls = RISK_CLASSES[risk] ?? RISK_CLASSES.unknown;
          const isExpanded = expanded[silo.id];
          const isScanning = scanMutation.isPending && scanMutation.variables === silo.id;

          return (
            <div key={silo.id} className={`bg-[#0d1117] border ${riskCls.card} rounded-2xl overflow-hidden transition-all`}>
              <div className="p-5">
                <div className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/8 flex items-center justify-center flex-shrink-0">
                    <SrcIcon className="w-5 h-5 text-blue-400" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <h3 className="font-bold text-white text-sm">{silo.name}</h3>
                      {silo.connected && <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-emerald-500/15 border border-emerald-500/20 text-emerald-400 font-semibold">Connected</span>}
                      {risk !== 'unknown' && <span className={`text-[10px] px-1.5 py-0.5 rounded-full border font-bold capitalize ${riskCls.badge}`}>{risk} Risk</span>}
                    </div>
                    <p className="text-xs text-slate-500">
                      {silo.total_objects?.toLocaleString()} objects scanned ·{' '}
                      {silo.flagged_objects > 0 && <span className="text-amber-400 font-semibold">{silo.flagged_objects} flagged</span>}
                      {silo.last_scanned && <span className="ml-1">· Last scan {new Date(silo.last_scanned).toLocaleString()}</span>}
                    </p>
                    {silo.data_types?.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2">
                        {silo.data_types.map(dt => (
                          <span key={dt} className="text-[10px] px-1.5 py-0.5 rounded bg-violet-500/10 border border-violet-500/20 text-violet-400">{dt}</span>
                        ))}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <button
                      onClick={() => scanMutation.mutate(silo.id)}
                      disabled={!silo.connected || isScanning}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 text-xs font-semibold text-slate-300 transition-colors disabled:opacity-40"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} /> Scan
                    </button>
                    {silo.findings?.length > 0 && (
                      <button
                        onClick={() => setExpanded(p => ({ ...p, [silo.id]: !p[silo.id] }))}
                        className="p-1.5 rounded-xl bg-white/5 border border-white/10 text-slate-400 hover:text-white transition-colors"
                      >
                        {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                      </button>
                    )}
                  </div>
                </div>
              </div>

              {/* Findings expansion */}
              {isExpanded && silo.findings?.length > 0 && (
                <div className="border-t border-white/5 px-5 pb-5">
                  <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider py-3">
                    Findings — {silo.findings.length} categories
                  </p>
                  <div className="space-y-2">
                    {silo.findings.map((finding, i) => (
                      <div key={i} className="flex items-center justify-between py-2 px-3 rounded-xl bg-white/[0.02] border border-white/5 group">
                        <div className="flex items-center gap-3">
                          <div className={`w-2 h-2 rounded-full flex-shrink-0 ${SEV_DOT[finding.severity] ?? SEV_DOT.unknown}`} />
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-white text-xs">{finding.type}</span>
                              <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border capitalize ${RISK_CLASSES[finding.severity]?.badge ?? RISK_CLASSES.unknown.badge}`}>
                                {finding.severity}
                              </span>
                              <span className="text-[11px] text-slate-500">{finding.count} instances</span>
                            </div>
                            <p className="text-[11px] text-slate-500">{finding.description}</p>
                          </div>
                        </div>
                        <button className="text-xs font-semibold text-blue-400 hover:text-blue-300 transition-colors opacity-0 group-hover:opacity-100 whitespace-nowrap ml-4">
                          Remediate →
                        </button>
                      </div>
                    ))}
                  </div>
                  {silo.frameworks?.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mt-3">
                      {silo.frameworks.map(fw => (
                        <span key={fw} className={`text-[10px] px-2 py-0.5 rounded border ${FW_CLASSES[fw] ?? 'bg-slate-500/10 border-slate-500/20 text-slate-400'}`}>{fw}</span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}

        {!isLoading && filtered.length === 0 && (
          <div className="py-16 text-center text-slate-500 bg-[#0d1117] border border-white/8 rounded-2xl">
            <HardDrive className="w-10 h-10 mx-auto mb-3 opacity-30" />
            <p className="text-sm">No data sources found</p>
          </div>
        )}
      </div>
    </div>
  );
}
