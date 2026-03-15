import { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import {
  Layers, ChevronDown, ChevronRight, CheckCircle, AlertTriangle,
  XCircle, Filter, X, BookOpen, Wrench, ExternalLink, ClipboardList, Loader2
} from 'lucide-react';
import api from '../lib/api';

interface AssessmentResult {
  id: string;
  control_id: string;
  check_id: string;
  assertion: string;
  status: string;
  severity: string;
  provider: string;
  region: string;
  findings: string[];
  remediation: string | null;
  assessed_at: string;
}

interface RemediationGuide {
  title: string;
  steps: string[];
  references: string[];
  raw: string | null;
}

const FRAMEWORKS = [
  { id: 'nist_800_53', name: 'NIST 800-53', desc: 'Security and Privacy Controls for Federal Information Systems' },
  { id: 'soc2',        name: 'SOC 2',        desc: 'Service Organization Control 2 — Trust Services Criteria' },
  { id: 'iso27001',    name: 'ISO 27001',    desc: 'Information Security Management Systems Requirements' },
  { id: 'hipaa',       name: 'HIPAA',        desc: 'Health Insurance Portability and Accountability Act' },
  { id: 'cmmc_l2',     name: 'CMMC L2',      desc: 'Cybersecurity Maturity Model Certification Level 2' },
];

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, pass: 4 };

function StatusBadge({ status, severity }: { status: string; severity: string }) {
  if (status === 'pass') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/20">
        <CheckCircle className="w-3 h-3" /> Pass
      </span>
    );
  }
  if (severity === 'critical' || severity === 'high') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/15 text-red-400 border border-red-500/20 capitalize">
        <XCircle className="w-3 h-3" /> {severity}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/15 text-amber-400 border border-amber-500/20 capitalize">
      <AlertTriangle className="w-3 h-3" /> {severity || 'medium'}
    </span>
  );
}

function ControlDetailPanel({ control, remediation, remLoading, onClose }: {
  control: AssessmentResult;
  remediation?: RemediationGuide;
  remLoading: boolean;
  onClose: () => void;
}) {
  const isCritical = control.severity === 'critical' || control.severity === 'high';

  return (
    <div className="bg-[#0d1117] border border-white/10 rounded-2xl overflow-hidden sticky top-4 max-h-[calc(100vh-8rem)] flex flex-col shadow-2xl shadow-black/40">
      <div className={`px-4 py-3 border-b flex items-start justify-between gap-2 ${
        isCritical ? 'bg-red-500/10 border-red-500/20' : 'bg-amber-500/10 border-amber-500/20'
      }`}>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-mono text-[10px] font-bold bg-white/10 px-1.5 py-0.5 rounded border border-white/10 text-slate-300">
              {control.control_id}
            </span>
            <StatusBadge status={control.status} severity={control.severity} />
          </div>
          <p className="text-sm font-semibold text-white leading-tight">{control.assertion || control.check_id}</p>
          <p className="text-xs text-slate-500 mt-1">{control.provider.toUpperCase()} · {control.region}</p>
        </div>
        <button onClick={onClose} className="p-1.5 hover:bg-white/10 rounded-lg transition-colors flex-shrink-0">
          <X className="w-4 h-4 text-slate-500 hover:text-white" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin">
        {control.findings?.length > 0 && (
          <div>
            <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <ClipboardList className="w-3.5 h-3.5 text-red-400" /> What's Wrong
            </h4>
            <div className={`rounded-xl border p-3 space-y-2 ${isCritical ? 'bg-red-500/10 border-red-500/20' : 'bg-amber-500/10 border-amber-500/20'}`}>
              {control.findings.map((finding, i) => (
                <div key={i} className="flex gap-2">
                  <span className={`text-xs mt-0.5 flex-shrink-0 ${isCritical ? 'text-red-400' : 'text-amber-400'}`}>•</span>
                  <p className="text-xs text-slate-300 leading-relaxed">{finding}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        <div>
          <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <Wrench className="w-3.5 h-3.5 text-blue-400" /> Recommended Remediation
          </h4>
          {remLoading ? (
            <div className="flex items-center gap-2 py-4 text-slate-500">
              <Loader2 className="w-4 h-4 animate-spin" />
              <span className="text-xs">Loading guidance…</span>
            </div>
          ) : remediation ? (
            <div className="space-y-2">
              {remediation.steps.map((step, i) => (
                <div key={i} className="flex gap-3 bg-blue-500/10 border border-blue-500/20 rounded-xl px-3 py-2.5">
                  <span className="w-5 h-5 rounded-full bg-blue-600 text-white text-[10px] font-bold flex items-center justify-center flex-shrink-0 mt-0.5">{i + 1}</span>
                  <p className="text-xs text-slate-300 leading-relaxed">{step}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="bg-white/[0.03] border border-white/8 rounded-xl p-3">
              <p className="text-xs text-slate-400 leading-relaxed">{control.remediation || 'Review the control requirement and develop a remediation plan based on your system architecture.'}</p>
            </div>
          )}
        </div>

        {remediation?.references && remediation.references.length > 0 && (
          <div>
            <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <BookOpen className="w-3.5 h-3.5 text-slate-500" /> References
            </h4>
            <div className="space-y-1">
              {remediation.references.map((ref, i) => (
                <div key={i} className="flex items-center gap-1.5 text-xs text-blue-400">
                  <ExternalLink className="w-3 h-3 flex-shrink-0" /><span>{ref}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="pt-2 border-t border-white/5">
          <p className="text-[10px] text-slate-600">Assessed: {new Date(control.assessed_at).toLocaleString()}</p>
        </div>
      </div>

      <div className="p-3 border-t border-white/8 flex gap-2">
        <button className="flex-1 py-2 text-xs font-bold bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-white rounded-xl transition-all">
          Create POAM Item
        </button>
        <button className="flex-1 py-2 text-xs font-semibold bg-white/5 border border-white/10 hover:bg-white/10 text-slate-300 rounded-xl transition-colors">
          Assign Owner
        </button>
      </div>
    </div>
  );
}

export default function FrameworksPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlFw = searchParams.get('fw');
  const urlFilter = searchParams.get('filter') as 'all' | 'medium' | 'critical' | null;

  const [activeTab, setActiveTab] = useState(urlFw || 'nist_800_53');
  const [expandedFamilies, setExpandedFamilies] = useState<Record<string, boolean>>({});
  const [statusFilter, setStatusFilter] = useState<'all' | 'pass' | 'medium' | 'critical'>(urlFilter || 'all');
  const [selectedControl, setSelectedControl] = useState<AssessmentResult | null>(null);

  useEffect(() => {
    if (urlFw && FRAMEWORKS.find(f => f.id === urlFw)) setActiveTab(urlFw);
    if (urlFilter) setStatusFilter(urlFilter as any);
  }, [urlFw, urlFilter]);

  const { data: runs, isLoading: runsLoading } = useQuery<any[]>({
    queryKey: ['assessments', 'runs', activeTab],
    queryFn: async () => (await api.get(`/assessments/runs?framework=${activeTab}&limit=1`)).data,
  });

  const latestRunId = runs?.[0]?.id;
  const latestRun = runs?.[0];

  const { data: results, isLoading: resultsLoading } = useQuery<AssessmentResult[]>({
    queryKey: ['assessments', 'results', latestRunId],
    queryFn: async () => {
      if (!latestRunId) return [];
      return (await api.get(`/assessments/runs/${latestRunId}/results`)).data;
    },
    enabled: !!latestRunId,
  });

  const { data: remediation, isLoading: remLoading } = useQuery<RemediationGuide>({
    queryKey: ['remediation', selectedControl?.control_id],
    queryFn: async () => (await api.get(`/assessments/remediation/${selectedControl!.control_id}`)).data,
    enabled: !!selectedControl && selectedControl.status !== 'pass',
  });

  const switchTab = (id: string) => {
    setActiveTab(id);
    setSelectedControl(null);
    setSearchParams({ fw: id, ...(statusFilter !== 'all' ? { filter: statusFilter } : {}) });
  };

  const changeFilter = (f: string) => {
    setStatusFilter(f as any);
    setSearchParams({ fw: activeTab, ...(f !== 'all' ? { filter: f } : {}) });
  };

  const familyGroups: Record<string, AssessmentResult[]> = {};
  (results ?? []).forEach(r => {
    const family = r.control_id.split('-')[0].split('.')[0] || 'GEN';
    if (!familyGroups[family]) familyGroups[family] = [];
    familyGroups[family].push(r);
  });
  Object.values(familyGroups).forEach(controls =>
    controls.sort((a, b) => {
      const aO = a.status === 'pass' ? 4 : SEVERITY_ORDER[a.severity] ?? 3;
      const bO = b.status === 'pass' ? 4 : SEVERITY_ORDER[b.severity] ?? 3;
      return aO - bO;
    })
  );

  const filterControl = (c: AssessmentResult) => {
    if (statusFilter === 'all') return true;
    if (statusFilter === 'pass') return c.status === 'pass';
    if (statusFilter === 'critical') return c.status !== 'pass' && (c.severity === 'critical' || c.severity === 'high');
    if (statusFilter === 'medium') return c.status !== 'pass' && c.severity === 'medium';
    return true;
  };

  const isLoading = runsLoading || resultsLoading;
  const activeFw = FRAMEWORKS.find(f => f.id === activeTab);
  const totalCritical = (results ?? []).filter(r => r.status !== 'pass' && (r.severity === 'critical' || r.severity === 'high')).length;
  const totalMedium = (results ?? []).filter(r => r.status !== 'pass' && r.severity === 'medium').length;
  const totalPassing = (results ?? []).filter(r => r.status === 'pass').length;

  return (
    <div className="space-y-4 page-enter text-white">
      {/* Framework tabs */}
      <div className="bg-[#0d1117] border border-white/8 rounded-2xl overflow-x-auto scrollbar-hide">
        <nav className="flex min-w-max border-b border-white/5">
          {FRAMEWORKS.map(fw => (
            <button
              key={fw.id}
              onClick={() => switchTab(fw.id)}
              className={`px-5 py-3.5 text-sm font-semibold border-b-2 transition-colors whitespace-nowrap ${
                activeTab === fw.id
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-slate-500 hover:text-slate-300 hover:border-white/20'
              }`}
            >
              {fw.name}
            </button>
          ))}
        </nav>
      </div>

      {/* Framework info + run status */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <h2 className="font-bold text-white text-base">{activeFw?.name}</h2>
          <p className="text-xs text-slate-500 mt-0.5">{activeFw?.desc}</p>
        </div>
        {latestRun && (
          <div className="flex items-center gap-3 text-xs text-slate-500">
            <span>Last run: {new Date(latestRun.started_at).toLocaleString()}</span>
            {latestRun.pass_rate != null && (
              <span className={`font-bold px-2 py-0.5 rounded-full border text-xs ${
                latestRun.pass_rate >= 80 ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20' :
                latestRun.pass_rate >= 60 ? 'bg-amber-500/15 text-amber-400 border-amber-500/20' :
                'bg-red-500/15 text-red-400 border-red-500/20'
              }`}>{latestRun.pass_rate.toFixed(1)}% pass rate</span>
            )}
          </div>
        )}
      </div>

      {/* Stats row */}
      {results && results.length > 0 && (
        <div className="grid grid-cols-3 gap-3">
          {[
            { filter: 'critical', value: totalCritical, label: 'Critical / High', icon: XCircle, cls: 'text-red-400', border: 'border-red-500/20', activeBorder: 'border-red-500/40 ring-1 ring-red-500/30', bg: 'bg-red-500/10' },
            { filter: 'medium',   value: totalMedium,   label: 'Medium Risk',     icon: AlertTriangle, cls: 'text-amber-400', border: 'border-amber-500/20', activeBorder: 'border-amber-500/40 ring-1 ring-amber-500/30', bg: 'bg-amber-500/10' },
            { filter: 'pass',     value: totalPassing,  label: 'Passing',         icon: CheckCircle, cls: 'text-emerald-400', border: 'border-emerald-500/20', activeBorder: 'border-emerald-500/40 ring-1 ring-emerald-500/30', bg: 'bg-emerald-500/10' },
          ].map(s => {
            const Icon = s.icon;
            const isActive = statusFilter === s.filter;
            return (
              <button
                key={s.filter}
                onClick={() => changeFilter(isActive ? 'all' : s.filter)}
                className={`flex items-center justify-between p-3.5 rounded-2xl border transition-all bg-[#0d1117] ${isActive ? s.activeBorder : s.border} hover:bg-white/[0.04]`}
              >
                <div className="text-left">
                  <div className={`text-2xl font-extrabold ${s.cls}`}>{s.value}</div>
                  <div className="text-xs text-slate-500 mt-0.5">{s.label}</div>
                </div>
                <Icon className={`w-5 h-5 ${s.cls}`} />
              </button>
            );
          })}
        </div>
      )}

      <div className="flex gap-4 min-h-0">
        <div className="flex-1 min-w-0 bg-[#0d1117] border border-white/8 rounded-2xl overflow-hidden">
          {/* Filter bar */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-white/5 bg-white/[0.02]">
            <div className="flex items-center gap-2 text-xs text-slate-500 flex-wrap">
              <Filter className="w-3.5 h-3.5" />
              {(['all', 'critical', 'medium', 'pass'] as const).map(f => (
                <button
                  key={f}
                  onClick={() => changeFilter(f)}
                  className={`px-2.5 py-1 rounded-full font-semibold transition-colors ${
                    statusFilter === f
                      ? f === 'critical' ? 'bg-red-500/15 text-red-400 border border-red-500/20' :
                        f === 'medium'   ? 'bg-amber-500/15 text-amber-400 border border-amber-500/20' :
                        f === 'pass'     ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/20' :
                        'bg-blue-500/15 text-blue-400 border border-blue-500/20'
                      : 'text-slate-500 hover:bg-white/5 hover:text-slate-300'
                  }`}
                >
                  {f === 'all' ? 'All' : f === 'pass' ? 'Passing' : f === 'critical' ? 'Critical/High' : 'Medium'}
                </button>
              ))}
            </div>
            {statusFilter !== 'all' && (
              <button onClick={() => changeFilter('all')} className="text-xs text-slate-500 hover:text-slate-300 flex items-center gap-1 transition-colors">
                <X className="w-3 h-3" /> Clear
              </button>
            )}
          </div>

          {isLoading ? (
            <div className="py-16 text-center text-slate-500">
              <Loader2 className="w-8 h-8 animate-spin mx-auto mb-3" />
              <p className="text-sm">Loading controls…</p>
            </div>
          ) : !latestRunId ? (
            <div className="py-16 text-center">
              <AlertTriangle className="w-10 h-10 text-slate-700 mx-auto mb-3" />
              <h3 className="text-sm font-semibold text-slate-400">No assessment data</h3>
              <p className="text-xs text-slate-600 mt-1">Run an assessment for this framework to see controls.</p>
            </div>
          ) : (
            <div className="divide-y divide-white/5 max-h-[70vh] overflow-auto scrollbar-thin">
              {Object.entries(familyGroups).map(([family, controls]) => {
                const filtered = controls.filter(filterControl);
                if (filtered.length === 0 && statusFilter !== 'all') return null;
                const isExpanded = expandedFamilies[family] !== false;
                const passCount = controls.filter(c => c.status === 'pass').length;
                const critCount = controls.filter(c => c.status !== 'pass' && (c.severity === 'critical' || c.severity === 'high')).length;

                return (
                  <div key={family}>
                    <button
                      onClick={() => setExpandedFamilies(p => ({ ...p, [family]: !isExpanded }))}
                      className="w-full flex items-center justify-between px-4 py-3 hover:bg-white/[0.03] transition-colors text-left"
                    >
                      <div className="flex items-center gap-2">
                        {isExpanded
                          ? <ChevronDown className="w-4 h-4 text-slate-500" />
                          : <ChevronRight className="w-4 h-4 text-slate-500" />}
                        <span className="font-bold text-white text-sm">{family} Family</span>
                        {critCount > 0 && (
                          <span className="text-[10px] px-1.5 py-0.5 bg-red-500/15 text-red-400 rounded-full border border-red-500/20 font-bold">{critCount} critical</span>
                        )}
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-xs text-slate-600">{passCount}/{controls.length} passing</span>
                        <div className="w-16 h-1.5 bg-white/5 rounded-full overflow-hidden">
                          <div className="h-full bg-emerald-500" style={{ width: `${(passCount / controls.length) * 100}%` }} />
                        </div>
                      </div>
                    </button>

                    {isExpanded && (
                      <div className="divide-y divide-white/[0.04] bg-white/[0.01]">
                        {(statusFilter === 'all' ? controls : filtered).map(control => {
                          const isFailing = control.status !== 'pass';
                          const isCritical = isFailing && (control.severity === 'critical' || control.severity === 'high');
                          const isMedium = isFailing && control.severity === 'medium';
                          const isSelected = selectedControl?.id === control.id;

                          return (
                            <div
                              key={control.id}
                              onClick={() => isFailing ? setSelectedControl(isSelected ? null : control) : undefined}
                              className={`flex items-start gap-3 px-4 py-3 transition-all ${
                                isFailing ? 'cursor-pointer hover:bg-white/[0.03]' : 'cursor-default'
                              } ${isSelected ? 'bg-blue-500/10 border-l-2 border-l-blue-500 pl-[14px]' : ''}`}
                            >
                              <div className={`mt-0.5 flex-shrink-0 ${isCritical ? 'text-red-400' : isMedium ? 'text-amber-400' : 'text-emerald-400'}`}>
                                {isCritical ? <XCircle className="w-4 h-4" /> :
                                 isMedium ? <AlertTriangle className="w-4 h-4" /> :
                                 <CheckCircle className="w-4 h-4" />}
                              </div>
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <span className="font-mono text-[10px] font-bold bg-white/5 border border-white/10 text-slate-300 px-1.5 py-0.5 rounded">{control.control_id}</span>
                                  <span className="text-sm text-white font-medium truncate">{control.assertion || control.check_id}</span>
                                </div>
                                <p className="text-xs text-slate-600 mt-0.5">{control.provider.toUpperCase()} · {control.region}</p>
                                {isFailing && control.findings?.length > 0 && (
                                  <p className="text-xs text-slate-500 mt-1 line-clamp-1">{control.findings[0]}</p>
                                )}
                              </div>
                              <div className="flex items-center gap-2 flex-shrink-0">
                                <StatusBadge status={control.status} severity={control.severity} />
                                {isFailing && (
                                  <ChevronRight className={`w-4 h-4 text-slate-600 transition-transform ${isSelected ? 'rotate-90 text-blue-400' : ''}`} />
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {selectedControl && (
          <div className="w-96 flex-shrink-0">
            <ControlDetailPanel
              control={selectedControl}
              remediation={remediation}
              remLoading={remLoading}
              onClose={() => setSelectedControl(null)}
            />
          </div>
        )}
      </div>
    </div>
  );
}
