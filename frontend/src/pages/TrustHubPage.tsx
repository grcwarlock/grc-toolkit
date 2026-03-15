import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Globe, Shield, CheckCircle, Clock, ExternalLink, Settings,
  Eye, Mail, Award, TrendingUp, FileCheck, ChevronRight,
  Save, Loader2
} from 'lucide-react';
import api from '../lib/api';

interface TrustConfig {
  company_name: string; company_tagline: string; show_pass_rates: boolean;
  show_last_audit: boolean; show_evidence_requests: boolean; published: boolean;
  contact_email: string; description: string;
}
interface Certification {
  id: string; name: string; issuer: string; framework: string; status: string;
  valid_from: string | null; valid_until: string | null; report_available: boolean;
  description: string; badge_color: string;
}
interface FrameworkStatus {
  framework: string; display_name: string; pass_rate: number;
  total_controls: number; passing: number; last_assessed: string; trend: string;
}
interface AccessRequest {
  id: string; name: string; email: string; company: string;
  report_id: string; status: string; requested_at: string;
}

const CERT_STATUS: Record<string, { cls: string; label: string }> = {
  certified:   { cls: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20', label: 'Certified' },
  compliant:   { cls: 'bg-blue-500/15 text-blue-400 border-blue-500/20', label: 'Compliant' },
  in_progress: { cls: 'bg-amber-500/15 text-amber-400 border-amber-500/20', label: 'In Progress' },
};

function Toggle({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) {
  return (
    <button onClick={() => onChange(!value)} role="switch" aria-checked={value}
      className={`relative w-11 h-6 rounded-full transition-colors duration-200 flex-shrink-0 ${value ? 'bg-blue-600' : 'bg-white/10'}`}>
      <span className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform duration-200 ${value ? 'translate-x-5' : ''}`} />
    </button>
  );
}

export default function TrustHubPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'overview' | 'certifications' | 'requests' | 'settings'>('overview');

  const { data: publicData, isLoading } = useQuery({
    queryKey: ['trust', 'public'],
    queryFn: async () => (await api.get('/trust/public')).data,
  });
  const { data: requestsData } = useQuery({
    queryKey: ['trust', 'requests'],
    queryFn: async () => (await api.get('/trust/admin/access-requests')).data,
  });
  const { data: config } = useQuery<TrustConfig>({
    queryKey: ['trust', 'config'],
    queryFn: async () => (await api.get('/trust/admin/config')).data,
  });

  const updateConfigMutation = useMutation({
    mutationFn: async (update: Partial<TrustConfig>) => (await api.put('/trust/admin/config', update)).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['trust'] }),
  });
  const updateRequestMutation = useMutation({
    mutationFn: async ({ reqId, status }: { reqId: string; status: string }) =>
      (await api.patch(`/trust/admin/access-requests/${reqId}?status=${status}`)).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['trust', 'requests'] }),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 border-blue-500" />
      </div>
    );
  }

  const certifications: Certification[] = publicData?.certifications ?? [];
  const frameworks: FrameworkStatus[] = publicData?.framework_status ?? [];
  const requests: AccessRequest[] = requestsData?.requests ?? [];
  const pendingCount: number = requestsData?.pending ?? 0;

  const TABS = [
    { id: 'overview',        label: 'Overview',      icon: Eye },
    { id: 'certifications',  label: 'Certifications',icon: Award },
    { id: 'requests',        label: `Requests${pendingCount > 0 ? ` (${pendingCount})` : ''}`, icon: Mail },
    { id: 'settings',        label: 'Settings',       icon: Settings },
  ] as const;

  return (
    <div className="space-y-5 page-enter text-white">
      {/* Hero banner */}
      <div className="relative bg-gradient-to-r from-blue-600/20 via-violet-600/15 to-blue-600/10 border border-blue-500/20 rounded-2xl p-6 overflow-hidden">
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute -top-10 -right-10 w-48 h-48 bg-violet-600/15 rounded-full blur-3xl" />
          <div className="absolute bottom-0 left-0 w-64 h-32 bg-blue-600/10 rounded-full blur-3xl" />
        </div>
        <div className="relative flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <Globe className="w-5 h-5 text-blue-400" />
              <h2 className="text-lg font-bold text-white">Customer Trust Hub</h2>
              {config?.published ? (
                <span className="text-[10px] px-2 py-0.5 bg-emerald-500/20 text-emerald-400 rounded-full border border-emerald-500/30 font-bold">Live</span>
              ) : (
                <span className="text-[10px] px-2 py-0.5 bg-white/10 text-slate-400 rounded-full border border-white/20 font-bold">Draft</span>
              )}
            </div>
            <p className="text-slate-400 text-sm">{config?.company_tagline ?? 'Security compliance, made transparent'}</p>
          </div>
          <a href="/trust" target="_blank" rel="noopener noreferrer"
            className="flex items-center gap-2 px-4 py-2.5 bg-white/10 hover:bg-white/20 text-white text-sm font-semibold rounded-xl border border-white/20 transition-colors whitespace-nowrap">
            <ExternalLink className="w-4 h-4" /> Preview Portal
          </a>
        </div>
        <div className="relative grid grid-cols-3 gap-3 mt-4">
          {[
            { label: 'Active Certifications', value: certifications.filter(c => c.status === 'certified' || c.status === 'compliant').length },
            { label: 'Frameworks Monitored', value: frameworks.length },
            { label: 'Pending Requests', value: pendingCount },
          ].map(s => (
            <div key={s.label} className="bg-white/5 border border-white/10 rounded-xl p-3">
              <div className="text-2xl font-extrabold text-white">{s.value}</div>
              <div className="text-xs text-slate-400 mt-0.5">{s.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-[#0d1117] border border-white/8 p-1 rounded-xl overflow-x-auto scrollbar-hide">
        {TABS.map(tab => {
          const Icon = tab.icon;
          return (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-semibold whitespace-nowrap transition-all ${
                activeTab === tab.id ? 'bg-white/10 text-white' : 'text-slate-500 hover:text-slate-300'
              }`}>
              <Icon className="w-3.5 h-3.5" /> {tab.label}
            </button>
          );
        })}
      </div>

      {/* Overview */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          <div className="bg-[#0d1117] border border-white/8 rounded-2xl overflow-hidden">
            <div className="px-5 py-4 border-b border-white/5 flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-blue-400" />
              <h3 className="font-bold text-white text-sm">Framework Compliance</h3>
            </div>
            <div className="divide-y divide-white/5">
              {frameworks.map(fw => (
                <div key={fw.framework} className="px-5 py-3">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-sm font-semibold text-white">{fw.display_name}</span>
                    <div className="flex items-center gap-2">
                      <span className={`text-[10px] font-bold ${fw.trend === 'improving' ? 'text-emerald-400' : 'text-slate-500'}`}>
                        {fw.trend === 'improving' ? '↑ Improving' : '→ Stable'}
                      </span>
                      <span className={`font-extrabold text-sm ${fw.pass_rate >= 80 ? 'text-emerald-400' : fw.pass_rate >= 60 ? 'text-amber-400' : 'text-red-400'}`}>
                        {fw.pass_rate.toFixed(1)}%
                      </span>
                    </div>
                  </div>
                  <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
                    <div className={`h-full rounded-full transition-all ${fw.pass_rate >= 80 ? 'bg-emerald-500' : fw.pass_rate >= 60 ? 'bg-amber-500' : 'bg-red-500'}`}
                      style={{ width: `${fw.pass_rate}%` }} />
                  </div>
                  <div className="flex items-center justify-between mt-1">
                    <span className="text-[10px] text-slate-600">{fw.passing}/{fw.total_controls} passing</span>
                    <span className="text-[10px] text-slate-600">{new Date(fw.last_assessed).toLocaleDateString()}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-[#0d1117] border border-white/8 rounded-2xl overflow-hidden">
            <div className="px-5 py-4 border-b border-white/5 flex items-center gap-2">
              <Shield className="w-4 h-4 text-blue-400" />
              <h3 className="font-bold text-white text-sm">Security Updates</h3>
            </div>
            <div className="divide-y divide-white/5">
              {(publicData?.security_updates ?? []).map((update: any, i: number) => (
                <div key={i} className="px-5 py-3">
                  <div className="flex items-start gap-3">
                    <div className={`w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 ${
                      update.type === 'certification' ? 'bg-blue-500' :
                      update.type === 'security' ? 'bg-orange-500' : 'bg-emerald-500'
                    }`} />
                    <div>
                      <p className="text-sm font-semibold text-white">{update.title}</p>
                      <p className="text-xs text-slate-500 mt-0.5">{update.description}</p>
                      <p className="text-xs text-slate-600 mt-1">{new Date(update.date).toLocaleDateString()}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Certifications */}
      {activeTab === 'certifications' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {certifications.map(cert => {
            const st = CERT_STATUS[cert.status] ?? CERT_STATUS.in_progress;
            return (
              <div key={cert.id} className="bg-[#0d1117] border border-white/8 rounded-2xl p-5 hover:border-white/15 transition-all">
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <FileCheck className="w-4 h-4 text-blue-400" />
                      <span className="font-bold text-white text-sm">{cert.name}</span>
                    </div>
                    <p className="text-xs text-slate-500">Issued by {cert.issuer}</p>
                  </div>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${st.cls}`}>{st.label}</span>
                </div>
                <p className="text-sm text-slate-400 mb-3 leading-relaxed">{cert.description}</p>
                {cert.valid_from && cert.valid_until && (
                  <div className="flex items-center gap-2 text-xs text-slate-500 mb-3">
                    <Clock className="w-3 h-3" />
                    {new Date(cert.valid_from).toLocaleDateString()} – {new Date(cert.valid_until).toLocaleDateString()}
                  </div>
                )}
                <div className="flex items-center justify-between">
                  {cert.report_available ? (
                    <span className="text-xs text-emerald-400 flex items-center gap-1">
                      <CheckCircle className="w-3 h-3" /> Report available on request
                    </span>
                  ) : (
                    <span className="text-xs text-slate-600">No public report</span>
                  )}
                  <button className="text-xs flex items-center gap-1 text-blue-400 hover:text-blue-300 transition-colors">
                    Details <ChevronRight className="w-3 h-3" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Requests */}
      {activeTab === 'requests' && (
        <div className="bg-[#0d1117] border border-white/8 rounded-2xl overflow-hidden">
          <div className="px-5 py-4 border-b border-white/5 flex items-center justify-between">
            <h3 className="font-bold text-white text-sm">Report Access Requests</h3>
            {pendingCount > 0 && (
              <span className="text-[10px] bg-amber-500/15 text-amber-400 border border-amber-500/20 px-2 py-0.5 rounded-full font-bold">{pendingCount} pending</span>
            )}
          </div>
          {requests.length === 0 ? (
            <div className="px-5 py-12 text-center text-slate-500">
              <Mail className="w-8 h-8 mx-auto mb-2 opacity-30" />
              <p className="text-sm">No access requests yet</p>
              <p className="text-xs mt-1 text-slate-600">Requests from your Trust Hub will appear here</p>
            </div>
          ) : (
            <div className="divide-y divide-white/5">
              {requests.map(req => (
                <div key={req.id} className="px-5 py-4 flex flex-col sm:flex-row sm:items-center gap-4">
                  <div className="flex-1 min-w-0">
                    <p className="font-semibold text-white text-sm">{req.name}</p>
                    <p className="text-xs text-slate-500">{req.email} · {req.company}</p>
                    <p className="text-[11px] text-slate-600 mt-0.5">
                      Requested {new Date(req.requested_at).toLocaleString()}
                    </p>
                  </div>
                  {req.status === 'pending' ? (
                    <div className="flex gap-2 flex-shrink-0">
                      <button
                        onClick={() => updateRequestMutation.mutate({ reqId: req.id, status: 'approved' })}
                        className="px-3 py-1.5 rounded-xl bg-emerald-500/15 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/25 text-xs font-bold transition-colors"
                      >Approve</button>
                      <button
                        onClick={() => updateRequestMutation.mutate({ reqId: req.id, status: 'denied' })}
                        className="px-3 py-1.5 rounded-xl bg-red-500/15 border border-red-500/20 text-red-400 hover:bg-red-500/25 text-xs font-bold transition-colors"
                      >Deny</button>
                    </div>
                  ) : (
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border capitalize flex-shrink-0 ${
                      req.status === 'approved' ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20' :
                      'bg-red-500/15 text-red-400 border-red-500/20'
                    }`}>{req.status}</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Settings */}
      {activeTab === 'settings' && config && (
        <div className="bg-[#0d1117] border border-white/8 rounded-2xl p-6 space-y-5">
          <h3 className="text-base font-bold text-white">Trust Hub Configuration</h3>
          {[
            { key: 'company_name', label: 'Company Name', type: 'text' },
            { key: 'company_tagline', label: 'Tagline', type: 'text' },
            { key: 'contact_email', label: 'Contact Email', type: 'email' },
            { key: 'description', label: 'Description', type: 'text' },
          ].map(field => (
            <div key={field.key}>
              <label className="block text-sm font-semibold text-slate-300 mb-1.5">{field.label}</label>
              <input
                type={field.type}
                defaultValue={(config as any)[field.key] ?? ''}
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20"
              />
            </div>
          ))}
          <div className="space-y-3">
            {[
              { key: 'show_pass_rates', label: 'Show pass rates publicly' },
              { key: 'show_last_audit', label: 'Show last audit date' },
              { key: 'show_evidence_requests', label: 'Allow evidence requests' },
              { key: 'published', label: 'Portal is public (live)' },
            ].map(s => (
              <div key={s.key} className="flex items-center justify-between py-2">
                <span className="text-sm text-slate-300">{s.label}</span>
                <Toggle value={(config as any)[s.key] ?? false}
                  onChange={v => updateConfigMutation.mutate({ [s.key]: v })} />
              </div>
            ))}
          </div>
          <button
            onClick={() => updateConfigMutation.mutate(config)}
            disabled={updateConfigMutation.isPending}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold transition-all shadow-lg shadow-blue-500/20 disabled:opacity-60"
          >
            {updateConfigMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
            Save Settings
          </button>
        </div>
      )}
    </div>
  );
}
