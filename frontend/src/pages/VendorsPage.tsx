import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Users, Shield, Search, AlertTriangle, CheckCircle, Calendar, ExternalLink } from 'lucide-react';
import api from '../lib/api';

interface VendorResponse {
  id: string;
  name: string;
  category: string;
  criticality: string;
  contract_end: string;
  risk_score: number | null;
  risk_level: string | null;
  certifications: string[];
  last_assessment_date: string | null;
  is_active: boolean;
}

const RISK_CLASSES: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/20',
  high:     'bg-orange-500/15 text-orange-400 border-orange-500/20',
  medium:   'bg-amber-500/15 text-amber-400 border-amber-500/20',
  low:      'bg-emerald-500/15 text-emerald-400 border-emerald-500/20',
};

const CATEGORY_ICONS: Record<string, string> = {
  cloud_infrastructure: '☁️',
  source_control: '🐙',
  identity_access_management: '🔐',
  security_monitoring: '📊',
  endpoint_security: '🛡️',
  observability: '🔭',
  application_security: '🔍',
  crm: '👥',
  payment_processing: '💳',
  communications: '📱',
  database: '🗄️',
  cdn_security: '🌐',
  incident_management: '🚨',
  project_management: '📋',
};

export default function VendorsPage() {
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState('');

  const { data: vendors, isLoading } = useQuery<VendorResponse[]>({
    queryKey: ['vendors'],
    queryFn: async () => (await api.get('/vendors/')).data,
  });

  const filtered = (vendors ?? []).filter(v =>
    (!search || v.name.toLowerCase().includes(search.toLowerCase()) || v.category.includes(search.toLowerCase())) &&
    (!riskFilter || (v.risk_level ?? v.criticality) === riskFilter)
  );

  const critCount = vendors?.filter(v => (v.risk_level ?? v.criticality) === 'critical').length ?? 0;
  const highCount = vendors?.filter(v => (v.risk_level ?? v.criticality) === 'high').length ?? 0;
  const totalActive = vendors?.filter(v => v.is_active).length ?? 0;

  return (
    <div className="space-y-5 page-enter text-white">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-[#0d1117] border border-white/8 rounded-2xl p-5">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Users className="w-5 h-5 text-violet-400" /> Vendor Risk Management
          </h2>
          <p className="text-slate-400 text-sm mt-0.5">Third-party security posture across your supply chain</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold transition-all shadow-lg shadow-blue-500/20">
          + Add Vendor
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Vendors', value: vendors?.length ?? 0, icon: Users, cls: 'text-blue-400', border: 'border-blue-500/20' },
          { label: 'Critical',      value: critCount,             icon: AlertTriangle, cls: 'text-red-400', border: 'border-red-500/20' },
          { label: 'High Risk',     value: highCount,             icon: Shield, cls: 'text-orange-400', border: 'border-orange-500/20' },
          { label: 'Active',        value: totalActive,           icon: CheckCircle, cls: 'text-emerald-400', border: 'border-emerald-500/20' },
        ].map(s => {
          const Icon = s.icon;
          return (
            <div key={s.label} className={`bg-[#0d1117] border ${s.border} rounded-2xl p-5`}>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs text-slate-400">{s.label}</p>
                <Icon className={`w-4 h-4 ${s.cls}`} />
              </div>
              <p className={`text-3xl font-extrabold ${s.cls}`}>{s.value}</p>
            </div>
          );
        })}
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search vendors…"
            className="w-full bg-[#0d1117] border border-white/8 rounded-xl pl-9 pr-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20"
          />
        </div>
        <select
          value={riskFilter}
          onChange={e => setRiskFilter(e.target.value)}
          className="bg-[#0d1117] border border-white/8 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20"
        >
          <option value="" className="bg-[#0d1117]">All Risk Levels</option>
          {['critical', 'high', 'medium', 'low'].map(r => (
            <option key={r} value={r} className="bg-[#0d1117] capitalize">{r.charAt(0).toUpperCase() + r.slice(1)}</option>
          ))}
        </select>
      </div>

      {/* Vendor grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {isLoading
          ? Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="bg-[#0d1117] border border-white/8 rounded-2xl p-5 animate-pulse">
                <div className="h-4 bg-white/5 rounded w-2/3 mb-3" />
                <div className="h-3 bg-white/5 rounded w-1/2 mb-4" />
                <div className="h-2 bg-white/5 rounded w-full" />
              </div>
            ))
          : filtered.map(vendor => {
              const riskLevel = (vendor.risk_level ?? vendor.criticality ?? 'unknown').toLowerCase();
              const riskCls = RISK_CLASSES[riskLevel] ?? 'bg-slate-500/15 text-slate-400 border-slate-500/20';
              const daysUntilExpiry = vendor.contract_end
                ? Math.ceil((new Date(vendor.contract_end).getTime() - Date.now()) / (1000 * 60 * 60 * 24))
                : null;

              return (
                <div key={vendor.id} className="group bg-[#0d1117] border border-white/8 hover:border-white/15 rounded-2xl p-5 transition-all hover:bg-white/[0.02]">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/8 flex items-center justify-center text-xl flex-shrink-0">
                        {CATEGORY_ICONS[vendor.category] ?? '🏢'}
                      </div>
                      <div>
                        <h3 className="font-bold text-white text-sm leading-tight">{vendor.name}</h3>
                        <p className="text-[11px] text-slate-500 capitalize mt-0.5">{vendor.category.replace(/_/g, ' ')}</p>
                      </div>
                    </div>
                    <span className={`${riskCls} text-[10px] font-bold px-2 py-0.5 rounded-full border capitalize flex-shrink-0`}>
                      {riskLevel}
                    </span>
                  </div>

                  {vendor.certifications?.length > 0 && (
                    <div className="flex gap-1.5 flex-wrap mb-3">
                      {vendor.certifications.slice(0, 3).map(c => (
                        <span key={c} className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400">{c}</span>
                      ))}
                    </div>
                  )}

                  <div className="flex items-center justify-between text-xs text-slate-500">
                    <span className="flex items-center gap-1">
                      <Calendar className="w-3.5 h-3.5" />
                      {vendor.last_assessment_date
                        ? `Assessed ${new Date(vendor.last_assessment_date).toLocaleDateString()}`
                        : 'Not yet assessed'}
                    </span>
                    {daysUntilExpiry != null && (
                      <span className={daysUntilExpiry < 90 ? 'text-amber-400' : 'text-slate-500'}>
                        Contract: {daysUntilExpiry < 0 ? 'Expired' : `${daysUntilExpiry}d`}
                      </span>
                    )}
                  </div>

                  {vendor.risk_score != null && (
                    <div className="mt-3">
                      <div className="flex items-center justify-between text-[10px] mb-1">
                        <span className="text-slate-500">Risk Score</span>
                        <span className="font-bold text-white">{vendor.risk_score}/100</span>
                      </div>
                      <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${vendor.risk_score > 70 ? 'bg-red-500' : vendor.risk_score > 40 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                          style={{ width: `${vendor.risk_score}%` }}
                        />
                      </div>
                    </div>
                  )}
                </div>
              );
            })
        }
      </div>
    </div>
  );
}
