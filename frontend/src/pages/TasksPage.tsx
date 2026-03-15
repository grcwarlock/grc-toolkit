import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ListTodo, Plus, CheckCircle, Loader2, AlertTriangle,
  ChevronDown, ChevronRight, MessageSquare, User
} from 'lucide-react';
import api from '../lib/api';

const PRIORITY_CLASSES: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/20',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/20',
  medium: 'bg-amber-500/15 text-amber-400 border-amber-500/20',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/20',
};

const STATUS_CLASSES: Record<string, string> = {
  open: 'bg-red-500/10 text-red-400',
  in_progress: 'bg-amber-500/10 text-amber-400',
  review: 'bg-violet-500/10 text-violet-400',
  completed: 'bg-emerald-500/10 text-emerald-400',
  deferred: 'bg-slate-500/10 text-slate-400',
};

const TASK_TYPES = ['remediation', 'review', 'evidence', 'approval', 'vendor_assessment'];

export default function TasksPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [form, setForm] = useState({ title: '', description: '', task_type: 'remediation', assigned_to: '', priority: 'medium', due_date: '' });
  const [commentForm, setCommentForm] = useState({ author: 'Admin', content: '' });

  const { data: tasks = [], isLoading } = useQuery({
    queryKey: ['tasks', statusFilter],
    queryFn: async () => (await api.get('/tasks/', { params: statusFilter ? { status: statusFilter } : {} })).data,
  });

  const { data: dashboard } = useQuery({
    queryKey: ['tasks', 'dashboard'],
    queryFn: async () => (await api.get('/tasks/dashboard')).data,
  });

  const createMut = useMutation({
    mutationFn: (data: any) => api.post('/tasks/', data),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['tasks'] }); setShowCreate(false); },
  });

  const updateMut = useMutation({
    mutationFn: ({ id, ...data }: any) => api.put(`/tasks/${id}`, data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['tasks'] }),
  });

  const commentMut = useMutation({
    mutationFn: ({ id, ...data }: any) => api.post(`/tasks/${id}/comments`, data),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['tasks'] }); setCommentForm({ author: 'Admin', content: '' }); },
  });

  return (
    <div className="space-y-5 page-enter text-white">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-[#0d1117] border border-white/8 rounded-2xl p-5">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <ListTodo className="w-5 h-5 text-blue-400" /> Task & Workflow Management
          </h2>
          <p className="text-slate-400 text-sm mt-0.5">Assign remediation, reviews, and approvals with due dates & tracking</p>
        </div>
        <button onClick={() => setShowCreate(!showCreate)} className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold text-white transition-all shadow-lg shadow-blue-500/20">
          <Plus className="w-4 h-4" /> New Task
        </button>
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="bg-[#0d1117] border border-blue-500/20 rounded-2xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-blue-400">Create Task</h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="sm:col-span-2">
              <label className="text-xs text-slate-500 block mb-1">Title</label>
              <input value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} placeholder="Remediate AC-2 MFA findings" className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500/50" />
            </div>
            <div>
              <label className="text-xs text-slate-500 block mb-1">Assigned To</label>
              <input value={form.assigned_to} onChange={e => setForm({ ...form, assigned_to: e.target.value })} placeholder="john@example.com" className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500/50" />
            </div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <label className="text-xs text-slate-500 block mb-1">Type</label>
              <select value={form.task_type} onChange={e => setForm({ ...form, task_type: e.target.value })} className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50">
                {TASK_TYPES.map(t => <option key={t} value={t}>{t.replace('_', ' ')}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-slate-500 block mb-1">Priority</label>
              <select value={form.priority} onChange={e => setForm({ ...form, priority: e.target.value })} className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50">
                {['critical', 'high', 'medium', 'low'].map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-slate-500 block mb-1">Due Date</label>
              <input type="date" value={form.due_date} onChange={e => setForm({ ...form, due_date: e.target.value })} className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50" />
            </div>
          </div>
          <div>
            <label className="text-xs text-slate-500 block mb-1">Description</label>
            <textarea value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} rows={2} placeholder="Detailed instructions…" className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500/50" />
          </div>
          <div className="flex gap-2">
            <button onClick={() => createMut.mutate(form)} disabled={!form.title || !form.assigned_to || createMut.isPending} className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-sm font-semibold text-white disabled:opacity-40">
              {createMut.isPending ? 'Creating…' : 'Create Task'}
            </button>
            <button onClick={() => setShowCreate(false)} className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-sm text-slate-400">Cancel</button>
          </div>
        </div>
      )}

      {/* Dashboard summary */}
      <div className="grid grid-cols-5 gap-4">
        {[
          { label: 'Open', value: dashboard?.by_status?.open ?? 0, cls: 'text-red-400 border-red-500/20' },
          { label: 'In Progress', value: dashboard?.by_status?.in_progress ?? 0, cls: 'text-amber-400 border-amber-500/20' },
          { label: 'In Review', value: dashboard?.by_status?.review ?? 0, cls: 'text-violet-400 border-violet-500/20' },
          { label: 'Completed', value: dashboard?.by_status?.completed ?? 0, cls: 'text-emerald-400 border-emerald-500/20' },
          { label: 'Overdue', value: dashboard?.overdue ?? 0, cls: 'text-red-400 border-red-500/20' },
        ].map(c => (
          <div key={c.label} className={`bg-[#0d1117] border ${c.cls} rounded-2xl p-4`}>
            <span className="text-xs text-slate-400">{c.label}</span>
            <p className={`text-2xl font-extrabold ${c.cls.split(' ')[0]} mt-1`}>{c.value}</p>
          </div>
        ))}
      </div>

      {/* Filter */}
      <div className="flex gap-2 flex-wrap">
        {['', 'open', 'in_progress', 'review', 'completed', 'deferred'].map(s => (
          <button key={s} onClick={() => setStatusFilter(s)} className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-colors border ${statusFilter === s ? 'bg-blue-500/20 border-blue-500/30 text-blue-400' : 'bg-white/[0.03] border-white/8 text-slate-400 hover:border-white/15'}`}>
            {s === '' ? 'All' : s.replace('_', ' ')}
          </button>
        ))}
      </div>

      {/* Task list */}
      <div className="bg-[#0d1117] border border-white/8 rounded-2xl overflow-hidden">
        {isLoading ? (
          <div className="py-16 flex flex-col items-center gap-3 text-slate-500"><Loader2 className="w-7 h-7 animate-spin" /></div>
        ) : tasks.length === 0 ? (
          <div className="py-16 flex flex-col items-center gap-3 text-slate-500">
            <ListTodo className="w-10 h-10 text-slate-600" />
            <p className="text-sm font-semibold">No tasks</p>
          </div>
        ) : (
          <div className="divide-y divide-white/5">
            {tasks.map((t: any) => (
              <div key={t.id}>
                <button onClick={() => setExpandedId(expandedId === t.id ? null : t.id)} className="w-full text-left px-5 py-4 hover:bg-white/[0.02] transition-colors flex items-center gap-4">
                  <div className="flex-1 grid grid-cols-1 sm:grid-cols-5 gap-3 items-center">
                    <div>
                      <p className="font-semibold text-sm text-white">{t.title}</p>
                      <p className="text-xs text-slate-500 capitalize">{t.task_type.replace('_', ' ')}</p>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <User className="w-3 h-3 text-slate-500" />
                      <span className="text-xs text-slate-400">{t.assigned_to}</span>
                    </div>
                    <div>
                      <span className={`${PRIORITY_CLASSES[t.priority] ?? ''} text-[10px] font-bold px-1.5 py-0.5 rounded border capitalize`}>{t.priority}</span>
                    </div>
                    <div className="text-xs text-slate-400">
                      {t.due_date ? (
                        <span className={new Date(t.due_date) < new Date() && t.status !== 'completed' ? 'text-red-400 font-semibold' : ''}>
                          {new Date(t.due_date) < new Date() && t.status !== 'completed' && <AlertTriangle className="w-3 h-3 inline mr-1" />}
                          Due {new Date(t.due_date).toLocaleDateString()}
                        </span>
                      ) : 'No due date'}
                    </div>
                    <div>
                      <span className={`${STATUS_CLASSES[t.status] ?? ''} text-[10px] font-semibold px-2 py-0.5 rounded-full capitalize`}>{t.status.replace('_', ' ')}</span>
                    </div>
                  </div>
                  {expandedId === t.id ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                </button>

                {expandedId === t.id && (
                  <div className="px-5 pb-5 bg-white/[0.015] space-y-3">
                    {t.description && <p className="text-xs text-slate-300 leading-relaxed bg-white/[0.03] border border-white/8 rounded-xl p-3">{t.description}</p>}
                    <div className="flex gap-2 flex-wrap">
                      {['open', 'in_progress', 'review', 'completed', 'deferred'].map(s => (
                        <button key={s} onClick={() => updateMut.mutate({ id: t.id, status: s })} className={`px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-colors ${t.status === s ? 'bg-blue-500/20 border-blue-500/30 text-blue-400' : 'bg-white/[0.03] border-white/8 text-slate-500 hover:border-white/15'}`}>
                          {s === 'completed' && <CheckCircle className="w-3 h-3 inline mr-1" />}
                          {s.replace('_', ' ')}
                        </button>
                      ))}
                    </div>
                    {/* Comments */}
                    {t.comments?.length > 0 && (
                      <div className="space-y-2">
                        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Comments</p>
                        {t.comments.map((c: any, i: number) => (
                          <div key={i} className="bg-white/[0.03] border border-white/8 rounded-lg p-2.5 flex gap-2">
                            <MessageSquare className="w-3 h-3 text-slate-600 mt-0.5 flex-shrink-0" />
                            <div>
                              <p className="text-xs text-slate-300">{c.content}</p>
                              <p className="text-[10px] text-slate-600 mt-1">{c.author} • {c.timestamp ? new Date(c.timestamp).toLocaleString() : ''}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                    <div className="flex gap-2">
                      <input value={commentForm.content} onChange={e => setCommentForm({ ...commentForm, content: e.target.value })} placeholder="Add a comment…" className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-blue-500/50" />
                      <button onClick={() => { commentMut.mutate({ id: t.id, ...commentForm }); }} disabled={!commentForm.content} className="px-3 py-1.5 rounded-lg bg-blue-600/20 border border-blue-500/20 text-xs font-semibold text-blue-400 disabled:opacity-40 hover:bg-blue-600/30">
                        <MessageSquare className="w-3 h-3" />
                      </button>
                    </div>
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
