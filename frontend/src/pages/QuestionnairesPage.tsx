import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  FileQuestion, Plus, Sparkles, Loader2,
  ChevronDown, ChevronRight, Zap
} from 'lucide-react';
import api from '../lib/api';

const TYPE_OPTIONS = ['SIG', 'SIG_Lite', 'CAIQ', 'DDQ', 'VSAQ', 'Custom'];
const STATUS_CLASSES: Record<string, string> = {
  pending: 'bg-slate-500/10 text-slate-400',
  in_progress: 'bg-amber-500/10 text-amber-400',
  completed: 'bg-emerald-500/10 text-emerald-400',
  sent: 'bg-blue-500/10 text-blue-400',
};

const SAMPLE_QUESTIONS = [
  { question: "Does your organization encrypt data at rest and in transit?", category: "encryption" },
  { question: "Is multi-factor authentication required for all user accounts?", category: "mfa" },
  { question: "Do you have a documented incident response plan?", category: "incident response" },
  { question: "How do you manage access control and least privilege?", category: "access control" },
  { question: "Do you perform regular vulnerability scanning and penetration testing?", category: "vulnerability" },
  { question: "Do you maintain SOC 2 Type II certification?", category: "soc 2" },
  { question: "What is your data retention and deletion policy?", category: "data retention" },
  { question: "How do you handle change management for production systems?", category: "change management" },
  { question: "Do you have business continuity and disaster recovery plans?", category: "business continuity" },
  { question: "What logging and monitoring capabilities do you have?", category: "logging" },
  { question: "How do you manage subprocessors and third-party access?", category: "subprocessor" },
  { question: "What are your password policies?", category: "password" },
  { question: "Do you perform regular backup testing?", category: "backup" },
  { question: "Are you GDPR compliant?", category: "gdpr" },
];

export default function QuestionnairesPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [form, setForm] = useState({ title: '', requester: '', requester_email: '', questionnaire_type: 'DDQ', due_date: '', questions: [] as any[], notes: '' });

  const { data: questionnaires = [], isLoading } = useQuery({
    queryKey: ['questionnaires'],
    queryFn: async () => (await api.get('/questionnaires/')).data,
  });

  const { data: detail } = useQuery({
    queryKey: ['questionnaires', selectedId],
    queryFn: async () => (await api.get(`/questionnaires/${selectedId}`)).data,
    enabled: !!selectedId,
  });

  const createMut = useMutation({
    mutationFn: (data: any) => api.post('/questionnaires/', data),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['questionnaires'] }); setShowCreate(false); },
  });

  const autoAnswerMut = useMutation({
    mutationFn: (id: string) => api.post(`/questionnaires/${id}/auto-answer`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['questionnaires'] }),
  });

  const completionRate = (q: any) => q.total_questions > 0 ? Math.round(q.answered_questions / q.total_questions * 100) : 0;

  const handleCreateWithSample = () => {
    const questions = SAMPLE_QUESTIONS.map((sq, i) => ({
      id: `q-${i + 1}`,
      question: sq.question,
      category: sq.category,
      answer: '',
      auto_answered: false,
    }));
    setForm({ ...form, questions });
  };

  return (
    <div className="space-y-5 page-enter text-white">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-[#0d1117] border border-white/8 rounded-2xl p-5">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <FileQuestion className="w-5 h-5 text-blue-400" /> Security Questionnaires
          </h2>
          <p className="text-slate-400 text-sm mt-0.5">AI-powered questionnaire management — auto-answer from your compliance data</p>
        </div>
        <button onClick={() => setShowCreate(!showCreate)} className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold text-white transition-all shadow-lg shadow-blue-500/20">
          <Plus className="w-4 h-4" /> New Questionnaire
        </button>
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="bg-[#0d1117] border border-blue-500/20 rounded-2xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-blue-400">New Questionnaire</h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <label className="text-xs text-slate-500 block mb-1">Title</label>
              <input value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} placeholder="Acme Corp DDQ Q1 2026" className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500/50" />
            </div>
            <div>
              <label className="text-xs text-slate-500 block mb-1">Requester</label>
              <input value={form.requester} onChange={e => setForm({ ...form, requester: e.target.value })} placeholder="Acme Corp" className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500/50" />
            </div>
            <div>
              <label className="text-xs text-slate-500 block mb-1">Type</label>
              <select value={form.questionnaire_type} onChange={e => setForm({ ...form, questionnaire_type: e.target.value })} className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50">
                {TYPE_OPTIONS.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={handleCreateWithSample} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-violet-600/20 border border-violet-500/20 text-xs font-semibold text-violet-400 hover:bg-violet-600/30">
              <Sparkles className="w-3 h-3" /> Load Sample Questions ({SAMPLE_QUESTIONS.length})
            </button>
            {form.questions.length > 0 && (
              <span className="text-xs text-slate-400">{form.questions.length} questions loaded</span>
            )}
          </div>
          <div className="flex gap-2">
            <button onClick={() => createMut.mutate(form)} disabled={!form.title || !form.requester || createMut.isPending} className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-sm font-semibold text-white disabled:opacity-40">
              {createMut.isPending ? 'Creating…' : 'Create'}
            </button>
            <button onClick={() => setShowCreate(false)} className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-sm text-slate-400">Cancel</button>
          </div>
        </div>
      )}

      {/* Summary */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Total', value: questionnaires.length, cls: 'text-blue-400 border-blue-500/20' },
          { label: 'Pending', value: questionnaires.filter((q: any) => q.status === 'pending').length, cls: 'text-slate-400 border-slate-500/20' },
          { label: 'In Progress', value: questionnaires.filter((q: any) => q.status === 'in_progress').length, cls: 'text-amber-400 border-amber-500/20' },
          { label: 'Completed', value: questionnaires.filter((q: any) => q.status === 'completed' || q.status === 'sent').length, cls: 'text-emerald-400 border-emerald-500/20' },
        ].map(c => (
          <div key={c.label} className={`bg-[#0d1117] border ${c.cls} rounded-2xl p-4`}>
            <span className="text-xs text-slate-400">{c.label}</span>
            <p className={`text-3xl font-extrabold ${c.cls.split(' ')[0]} mt-1`}>{isLoading ? '—' : c.value}</p>
          </div>
        ))}
      </div>

      {/* Questionnaire list */}
      <div className="bg-[#0d1117] border border-white/8 rounded-2xl overflow-hidden">
        {isLoading ? (
          <div className="py-16 flex flex-col items-center gap-3 text-slate-500">
            <Loader2 className="w-7 h-7 animate-spin" />
          </div>
        ) : questionnaires.length === 0 ? (
          <div className="py-16 flex flex-col items-center gap-3 text-slate-500">
            <FileQuestion className="w-10 h-10 text-slate-600" />
            <p className="text-sm font-semibold">No questionnaires yet</p>
            <p className="text-xs">Create one to start auto-answering from your compliance data</p>
          </div>
        ) : (
          <div className="divide-y divide-white/5">
            {questionnaires.map((q: any) => (
              <div key={q.id}>
                <button onClick={() => setSelectedId(selectedId === q.id ? null : q.id)} className="w-full text-left px-5 py-4 hover:bg-white/[0.02] transition-colors flex items-center gap-4">
                  <div className="flex-1 grid grid-cols-1 sm:grid-cols-5 gap-3 items-center">
                    <div>
                      <p className="font-semibold text-sm text-white">{q.title}</p>
                      <p className="text-xs text-slate-500">{q.requester} • {q.questionnaire_type}</p>
                    </div>
                    <div>
                      <span className={`${STATUS_CLASSES[q.status] ?? ''} text-[10px] font-semibold px-2 py-0.5 rounded-full capitalize`}>
                        {q.status.replace('_', ' ')}
                      </span>
                    </div>
                    <div className="text-xs text-slate-400">
                      {q.due_date ? `Due: ${new Date(q.due_date).toLocaleDateString()}` : 'No deadline'}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden">
                          <div className="h-full bg-gradient-to-r from-blue-500 to-violet-500 rounded-full transition-all" style={{ width: `${completionRate(q)}%` }} />
                        </div>
                        <span className="text-xs text-slate-400 w-10 text-right">{completionRate(q)}%</span>
                      </div>
                      <p className="text-[10px] text-slate-600 mt-0.5">{q.answered_questions}/{q.total_questions} answered ({q.auto_answered} AI)</p>
                    </div>
                    <div className="flex items-center gap-2 justify-end">
                      {q.auto_answered > 0 && (
                        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-400 border border-violet-500/20 flex items-center gap-1">
                          <Sparkles className="w-2.5 h-2.5" /> {q.auto_answered} AI
                        </span>
                      )}
                    </div>
                  </div>
                  {selectedId === q.id ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                </button>

                {selectedId === q.id && (
                  <div className="px-5 pb-5 bg-white/[0.015] space-y-3">
                    <div className="flex gap-2">
                      <button onClick={() => autoAnswerMut.mutate(q.id)} disabled={autoAnswerMut.isPending} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-violet-600/20 to-blue-600/20 border border-violet-500/20 text-xs font-semibold text-violet-400 hover:border-violet-500/40">
                        <Zap className="w-3 h-3" /> {autoAnswerMut.isPending ? 'Auto-Answering…' : 'Auto-Answer with AI'}
                      </button>
                    </div>
                    {detail?.questions?.length > 0 && (
                      <div className="space-y-2 max-h-[400px] overflow-y-auto">
                        {detail.questions.map((dq: any, i: number) => (
                          <div key={i} className={`rounded-xl p-3 border ${dq.auto_answered ? 'bg-violet-500/5 border-violet-500/20' : 'bg-white/[0.02] border-white/8'}`}>
                            <div className="flex items-start gap-2">
                              <span className="text-[10px] font-bold text-slate-600 mt-0.5">Q{i + 1}</span>
                              <div className="flex-1">
                                <p className="text-xs text-slate-200 font-medium">{dq.question}</p>
                                {dq.answer ? (
                                  <div className="mt-2">
                                    <p className="text-xs text-slate-400 leading-relaxed">{dq.answer}</p>
                                    {dq.auto_answered && (
                                      <div className="flex items-center gap-2 mt-1.5">
                                        <span className="text-[9px] font-bold text-violet-400 bg-violet-500/10 px-1.5 py-0.5 rounded flex items-center gap-1">
                                          <Sparkles className="w-2.5 h-2.5" /> AI • {Math.round((dq.confidence || 0) * 100)}% confidence
                                        </span>
                                        {dq.source_controls && (
                                          <span className="text-[9px] text-slate-500">Controls: {dq.source_controls.join(', ')}</span>
                                        )}
                                      </div>
                                    )}
                                  </div>
                                ) : (
                                  <p className="text-xs text-slate-600 mt-1 italic">Not yet answered</p>
                                )}
                              </div>
                            </div>
                          </div>
                        ))}
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
