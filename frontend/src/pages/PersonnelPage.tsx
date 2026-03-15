import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Users, Plus, GraduationCap, ShieldCheck, Loader2, UserCheck,
  ChevronDown, ChevronRight, Clock, AlertTriangle, CheckCircle
} from 'lucide-react';
import api from '../lib/api';

const BG_CHECK_CLASSES: Record<string, string> = {
  passed: 'bg-emerald-500/10 text-emerald-400',
  pending: 'bg-amber-500/10 text-amber-400',
  failed: 'bg-red-500/10 text-red-400',
};

export default function PersonnelPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [form, setForm] = useState({ full_name: '', email: '', department: '', role: '', title: '' });

  const { data: personnel = [], isLoading } = useQuery({
    queryKey: ['personnel'],
    queryFn: async () => (await api.get('/personnel/')).data,
  });

  const { data: dashboard } = useQuery({
    queryKey: ['personnel', 'dashboard'],
    queryFn: async () => (await api.get('/personnel/dashboard')).data,
  });

  const createMut = useMutation({
    mutationFn: (data: any) => api.post('/personnel/', data),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['personnel'] }); setShowCreate(false); setForm({ full_name: '', email: '', department: '', role: '', title: '' }); },
  });

  const accessReviewMut = useMutation({
    mutationFn: (id: string) => api.post(`/personnel/${id}/access-review`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['personnel'] }),
  });

  return (
    <div className="space-y-5 page-enter text-white">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-[#0d1117] border border-white/8 rounded-2xl p-5">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Users className="w-5 h-5 text-blue-400" /> Personnel & Training
          </h2>
          <p className="text-slate-400 text-sm mt-0.5">Track training compliance, background checks, and access reviews</p>
        </div>
        <button onClick={() => setShowCreate(!showCreate)} className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold text-white transition-all shadow-lg shadow-blue-500/20">
          <Plus className="w-4 h-4" /> Add Personnel
        </button>
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="bg-[#0d1117] border border-blue-500/20 rounded-2xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-blue-400">Add Personnel</h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {[
              { key: 'full_name', label: 'Full Name', placeholder: 'Jane Smith' },
              { key: 'email', label: 'Email', placeholder: 'jane@example.com' },
              { key: 'department', label: 'Department', placeholder: 'Engineering' },
              { key: 'role', label: 'Role', placeholder: 'Security Engineer' },
              { key: 'title', label: 'Title', placeholder: 'Senior Engineer' },
            ].map(f => (
              <div key={f.key}>
                <label className="text-xs text-slate-500 block mb-1">{f.label}</label>
                <input value={(form as any)[f.key]} onChange={e => setForm({ ...form, [f.key]: e.target.value })} placeholder={f.placeholder} className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500/50" />
              </div>
            ))}
          </div>
          <div className="flex gap-2">
            <button onClick={() => createMut.mutate(form)} disabled={!form.full_name || !form.email || createMut.isPending} className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-sm font-semibold text-white disabled:opacity-40">Create</button>
            <button onClick={() => setShowCreate(false)} className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-sm text-slate-400">Cancel</button>
          </div>
        </div>
      )}

      {/* Dashboard */}
      <div className="grid grid-cols-5 gap-4">
        {[
          { label: 'Active Personnel', value: dashboard?.active_count ?? 0, icon: Users, cls: 'text-blue-400 border-blue-500/20' },
          { label: 'Training Compliance', value: `${(dashboard?.training_compliance_rate ?? 0).toFixed(0)}%`, icon: GraduationCap, cls: 'text-emerald-400 border-emerald-500/20' },
          { label: 'Overdue Reviews', value: dashboard?.overdue_access_reviews ?? 0, icon: Clock, cls: 'text-amber-400 border-amber-500/20' },
          { label: 'Pending BG Checks', value: dashboard?.pending_background_checks ?? 0, icon: ShieldCheck, cls: 'text-violet-400 border-violet-500/20' },
          { label: 'Departments', value: Object.keys(dashboard?.department_breakdown ?? {}).length, icon: UserCheck, cls: 'text-slate-400 border-slate-500/20' },
        ].map(c => {
          const Icon = c.icon;
          return (
            <div key={c.label} className={`bg-[#0d1117] border ${c.cls} rounded-2xl p-4`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-slate-400">{c.label}</span>
                <Icon className={`w-4 h-4 ${c.cls.split(' ')[0]}`} />
              </div>
              <p className={`text-2xl font-extrabold ${c.cls.split(' ')[0]}`}>{c.value}</p>
            </div>
          );
        })}
      </div>

      {/* Personnel list */}
      <div className="bg-[#0d1117] border border-white/8 rounded-2xl overflow-hidden">
        {isLoading ? (
          <div className="py-16 flex flex-col items-center gap-3 text-slate-500"><Loader2 className="w-7 h-7 animate-spin" /></div>
        ) : personnel.length === 0 ? (
          <div className="py-16 flex flex-col items-center gap-3 text-slate-500">
            <Users className="w-10 h-10 text-slate-600" />
            <p className="text-sm font-semibold">No personnel records</p>
            <p className="text-xs">Add personnel to track training and access reviews</p>
          </div>
        ) : (
          <div className="divide-y divide-white/5">
            {personnel.map((p: any) => (
              <div key={p.id}>
                <button onClick={() => setExpandedId(expandedId === p.id ? null : p.id)} className="w-full text-left px-5 py-4 hover:bg-white/[0.02] transition-colors flex items-center gap-4">
                  <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-600/30 to-violet-600/20 border border-blue-500/30 flex items-center justify-center flex-shrink-0">
                    <span className="text-xs font-bold text-blue-400">{p.full_name?.charAt(0) || '?'}</span>
                  </div>
                  <div className="flex-1 grid grid-cols-1 sm:grid-cols-5 gap-3 items-center">
                    <div>
                      <p className="font-semibold text-sm text-white">{p.full_name}</p>
                      <p className="text-xs text-slate-500">{p.email}</p>
                    </div>
                    <div className="text-xs text-slate-400">{p.department || '—'}</div>
                    <div className="text-xs text-slate-400">{p.title || p.role || '—'}</div>
                    <div>
                      <span className={`${BG_CHECK_CLASSES[p.background_check_status] ?? ''} text-[10px] font-semibold px-2 py-0.5 rounded-full capitalize`}>
                        BG: {p.background_check_status}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      {p.training_records?.length > 0 ? (
                        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/20 flex items-center gap-1">
                          <GraduationCap className="w-2.5 h-2.5" /> {p.training_records.length} training
                        </span>
                      ) : (
                        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 flex items-center gap-1">
                          <AlertTriangle className="w-2.5 h-2.5" /> No training
                        </span>
                      )}
                    </div>
                  </div>
                  {expandedId === p.id ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                </button>

                {expandedId === p.id && (
                  <div className="px-5 pb-5 bg-white/[0.015] space-y-3">
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      <div className="bg-white/[0.03] border border-white/8 rounded-xl p-3">
                        <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Manager</p>
                        <p className="text-xs text-slate-300">{p.manager || 'Not assigned'}</p>
                      </div>
                      <div className="bg-white/[0.03] border border-white/8 rounded-xl p-3">
                        <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Start Date</p>
                        <p className="text-xs text-slate-300">{p.start_date ? new Date(p.start_date).toLocaleDateString() : '—'}</p>
                      </div>
                      <div className="bg-white/[0.03] border border-white/8 rounded-xl p-3">
                        <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Last Access Review</p>
                        <p className="text-xs text-slate-300">{p.last_access_review ? new Date(p.last_access_review).toLocaleDateString() : 'Never'}</p>
                      </div>
                      <div className="bg-white/[0.03] border border-white/8 rounded-xl p-3">
                        <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Background Check</p>
                        <p className="text-xs text-slate-300">{p.background_check_date ? new Date(p.background_check_date).toLocaleDateString() : 'Not completed'}</p>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <button onClick={() => accessReviewMut.mutate(p.id)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600/20 border border-emerald-500/20 text-xs font-semibold text-emerald-400 hover:bg-emerald-600/30">
                        <CheckCircle className="w-3 h-3" /> Complete Access Review
                      </button>
                    </div>
                    {p.training_records?.length > 0 && (
                      <div>
                        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">Training Records</p>
                        <div className="space-y-1.5">
                          {p.training_records.map((tr: any, i: number) => (
                            <div key={i} className="flex items-center gap-2 bg-white/[0.03] border border-white/8 rounded-lg px-3 py-2">
                              <GraduationCap className="w-3 h-3 text-emerald-400 flex-shrink-0" />
                              <span className="text-xs text-slate-300 flex-1">{tr.training_name}</span>
                              <span className="text-[10px] text-slate-500 capitalize">{tr.training_type?.replace('_', ' ')}</span>
                              <span className="text-[10px] text-slate-500">{tr.completed_date}</span>
                              {tr.score && <span className="text-[10px] font-bold text-emerald-400">{tr.score}%</span>}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {p.control_mappings?.length > 0 && (
                      <div>
                        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">Control Mappings</p>
                        <div className="flex gap-1.5 flex-wrap">
                          {p.control_mappings.map((cm: string, i: number) => (
                            <span key={i} className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">{cm}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
