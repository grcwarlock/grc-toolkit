import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Play, CheckCircle, AlertTriangle, XCircle, Clock,
  ChevronDown, ChevronRight, FileText, Loader2, X,
  Info, BookOpen, ArrowRight
} from 'lucide-react';
import api from '../lib/api';

interface AssessmentRun {
  id: string;
  framework: string;
  started_at: string;
  completed_at: string | null;
  status: string;
  total_checks: number;
  passed: number;
  failed: number;
  errors: number;
  pass_rate: number | null;
}

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

const FRAMEWORK_LABELS: Record<string, string> = {
  nist_800_53: 'NIST 800-53',
  soc2: 'SOC 2',
  iso27001: 'ISO 27001',
  hipaa: 'HIPAA',
  cmmc_l2: 'CMMC L2',
};

const REMEDIATION_STEPS: Record<string, string[]> = {
  'pass': [],
  'default': [
    'Review the failing resource in your cloud console or configuration management system.',
    'Identify the root cause: misconfiguration, missing policy, or inadequate controls.',
    'Apply the recommended configuration change and document the change in your change management system.',
    'Re-run the compliance check to verify remediation.',
    'Update your risk register and notify the control owner of the resolution.',
  ],
};

function getRemediationSteps(controlId: string, assertion: string): string[] {
  const family = controlId.split('-')[0].split('.')[0];
  const steps: Record<string, string[]> = {
    AC: [
      `Review all user accounts with access to the system covered by ${controlId}.`,
      'Identify accounts that have not been used in 90+ days and disable or remove them.',
      'Ensure all privileged accounts have MFA enforced (TOTP, FIDO2, or hardware token).',
      'Configure automated access review reminders on a 90-day cycle.',
      'Document the access review completion in your GRC ticketing system.',
    ],
    AU: [
      `Enable or verify audit logging is active for all resources in scope for ${controlId}.`,
      'Ship logs to a centralized, tamper-resistant SIEM (Splunk, Datadog, etc.).',
      'Set log retention to minimum 365 days per policy requirements.',
      'Create alert rules for authentication failures, privilege escalations, and API key usage.',
      'Run quarterly log integrity verification and document results.',
    ],
    CM: [
      `Create a documented baseline configuration for the affected resource (CIS Benchmark Level 2 recommended).`,
      'Enable configuration drift detection using AWS Config, Azure Policy, or similar.',
      'Remediate all deviations from the approved baseline immediately.',
      'Establish a change control process requiring security review for config changes.',
      'Schedule quarterly CIS Benchmark compliance scans and track results.',
    ],
    IA: [
      `Enroll all accounts covered by ${controlId} in MFA using TOTP or hardware security keys.`,
      'Update password policy: minimum 16 characters, complexity requirements, 90-day rotation.',
      'Audit and rotate all API keys older than 90 days.',
      'Remove or disable shared/service accounts without documented business justification.',
      'Enable just-in-time (JIT) access for privileged administrative actions.',
    ],
    SC: [
      `Review and update network security group rules for resources covered by ${controlId}.`,
      'Ensure TLS 1.2+ is enforced on all endpoints; disable TLS 1.0 and 1.1.',
      'Enable encryption at rest for all data stores using AES-256 or equivalent.',
      'Deploy WAF in front of all public-facing web applications.',
      'Review and tighten firewall rules — remove any rules allowing 0.0.0.0/0 ingress.',
    ],
    SI: [
      `Scan all systems covered by ${controlId} with your vulnerability scanner immediately.`,
      'Prioritize and remediate all CVSS ≥ 9.0 vulnerabilities within 24 hours.',
      'Ensure EDR/AV agents are deployed and up to date on all endpoints.',
      'Integrate vulnerability scanning into your CI/CD pipeline as a blocking gate.',
      'Track remediation progress in your POAM and report weekly to security leadership.',
    ],
    RA: [
      `Conduct or update the risk assessment for systems in scope for ${controlId}.`,
      'Run a full vulnerability scan and record all findings with CVSS scores.',
      'Prioritize remediation by risk level: critical ≤ 24h, high ≤ 7d, medium ≤ 30d.',
      'Document accepted risks with business justification and CISO sign-off.',
      'Schedule next assessment within 12 months (or after significant changes).',
    ],
  };

  return steps[family] || steps['AC'].map(s => s.replace('access', 'configuration')).slice(0, 5);
}

export default function AssessmentsPage() {
  const queryClient = useQueryClient();
  const [selectedFramework, setSelectedFramework] = useState('nist_800_53');
  const [selectedRun, setSelectedRun] = useState<AssessmentRun | null>(null);
  const [selectedResult, setSelectedResult] = useState<AssessmentResult | null>(null);
  const [statusFilter, setStatusFilter] = useState<'all' | 'pass' | 'fail'>('all');

  const { data: runs, isLoading } = useQuery<AssessmentRun[]>({
    queryKey: ['assessments', 'runs'],
    queryFn: async () => (await api.get('/assessments/runs')).data,
    refetchInterval: 10000,
  });

  const triggerMutation = useMutation({
    mutationFn: async () => (await api.post('/assessments/run', {
      framework: selectedFramework,
      providers: ['aws', 'azure', 'gcp'],
    })).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['assessments', 'runs'] }),
  });

  const { data: runResults } = useQuery<{ results: AssessmentResult[] }>({
    queryKey: ['assessments', 'results', selectedRun?.id],
    queryFn: async () => (await api.get(`/assessments/runs/${selectedRun!.id}/results`)).data,
    enabled: !!selectedRun,
  });

  const results = runResults?.results ?? [];
  const filteredResults = results.filter(r =>
    statusFilter === 'all' ? true : r.status === statusFilter
  );

  const passCount = results.filter(r => r.status === 'pass').length;
  const failCount = results.filter(r => r.status === 'fail').length;

  const fw = Object.entries(FRAMEWORK_LABELS);

  const formatDate = (d: string | null) => d ? new Date(d).toLocaleString() : 'In progress…';

  const statusIcon = (status: string) => {
    if (status === 'completed') return <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />;
    if (status === 'failed') return <XCircle className="w-3.5 h-3.5 text-red-400" />;
    return <Loader2 className="w-3.5 h-3.5 text-blue-400 animate-spin" />;
  };

  const severityBadge = (sev: string) => {
    const map: Record<string, string> = {
      critical: 'bg-red-500/15 text-red-400 border-red-500/20',
      high:     'bg-orange-500/15 text-orange-400 border-orange-500/20',
      medium:   'bg-amber-500/15 text-amber-400 border-amber-500/20',
      low:      'bg-blue-500/15 text-blue-400 border-blue-500/20',
    };
    return `${map[sev] || 'bg-slate-500/15 text-slate-400 border-slate-500/20'} text-[10px] font-bold px-1.5 py-0.5 rounded border`;
  };

  return (
    <div className="space-y-5 page-enter text-white">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-[#0d1117] border border-white/8 rounded-2xl p-5">
        <div>
          <h2 className="text-lg font-bold text-white">Assessments</h2>
          <p className="text-slate-400 text-sm mt-0.5">Run and view compliance checks across your infrastructure</p>
        </div>
        <div className="flex items-center gap-3 w-full sm:w-auto">
          <select
            value={selectedFramework}
            onChange={e => setSelectedFramework(e.target.value)}
            className="flex-1 sm:flex-none bg-white/5 border border-white/10 text-white text-sm rounded-xl px-3 py-2.5 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20"
          >
            {fw.map(([id, label]) => <option key={id} value={id} className="bg-[#0d1117]">{label}</option>)}
          </select>
          <button
            onClick={() => triggerMutation.mutate()}
            disabled={triggerMutation.isPending}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-semibold text-white transition-all shadow-lg shadow-blue-500/20 disabled:opacity-50 whitespace-nowrap"
          >
            {triggerMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            Trigger Run
          </button>
        </div>
      </div>

      <div className={`grid gap-5 ${selectedRun ? 'grid-cols-1 lg:grid-cols-2' : 'grid-cols-1'}`}>
        {/* Run list */}
        <div className="bg-[#0d1117] border border-white/8 rounded-2xl overflow-hidden">
          <div className="px-5 py-3 border-b border-white/8 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Assessment Runs</h3>
            {isLoading && <Loader2 className="w-4 h-4 animate-spin text-slate-500" />}
          </div>

          <div className="overflow-auto max-h-[600px] scrollbar-thin">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-[#0d1117] border-b border-white/8">
                <tr>
                  {['Framework', 'Date', 'Status', 'Checks', 'Pass Rate'].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 text-slate-500 font-semibold uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {runs?.map(run => (
                  <tr
                    key={run.id}
                    onClick={() => { setSelectedRun(run); setSelectedResult(null); setStatusFilter('all'); }}
                    className={`cursor-pointer transition-colors ${selectedRun?.id === run.id ? 'bg-blue-500/10 border-l-2 border-l-blue-500' : 'hover:bg-white/[0.03]'}`}
                  >
                    <td className="px-4 py-3 font-semibold text-white">{FRAMEWORK_LABELS[run.framework] || run.framework}</td>
                    <td className="px-4 py-3 text-slate-400">{formatDate(run.started_at)}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        {statusIcon(run.status)}
                        <span className={`capitalize font-medium ${run.status === 'completed' ? 'text-emerald-400' : run.status === 'failed' ? 'text-red-400' : 'text-blue-400'}`}>
                          {run.status}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-slate-400">{run.total_checks || '—'}</td>
                    <td className="px-4 py-3">
                      {run.pass_rate != null ? (
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 bg-white/10 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${run.pass_rate >= 80 ? 'bg-emerald-500' : run.pass_rate >= 60 ? 'bg-amber-500' : 'bg-red-500'}`}
                              style={{ width: `${run.pass_rate}%` }}
                            />
                          </div>
                          <span className={`font-bold ${run.pass_rate >= 80 ? 'text-emerald-400' : run.pass_rate >= 60 ? 'text-amber-400' : 'text-red-400'}`}>
                            {run.pass_rate.toFixed(1)}%
                          </span>
                        </div>
                      ) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Results panel */}
        {selectedRun && (
          <div className="bg-[#0d1117] border border-white/8 rounded-2xl overflow-hidden flex flex-col">
            <div className="px-5 py-3 border-b border-white/8 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <FileText className="w-4 h-4 text-blue-400" />
                  {FRAMEWORK_LABELS[selectedRun.framework]} Results
                </h3>
                <p className="text-[11px] text-slate-500 mt-0.5">
                  {passCount} passed · {failCount} failed · {formatDate(selectedRun.started_at)}
                </p>
              </div>
              <button onClick={() => { setSelectedRun(null); setSelectedResult(null); }} className="p-1.5 hover:bg-white/5 rounded-lg text-slate-500 hover:text-white transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Filter tabs */}
            <div className="flex gap-1 px-4 py-2 border-b border-white/5">
              {(['all', 'fail', 'pass'] as const).map(f => (
                <button
                  key={f}
                  onClick={() => { setStatusFilter(f); setSelectedResult(null); }}
                  className={`px-3 py-1 rounded-lg text-xs font-semibold transition-colors ${
                    statusFilter === f ? 'bg-blue-500/20 text-blue-400 border border-blue-500/20' : 'text-slate-500 hover:text-slate-300'
                  }`}
                >
                  {f === 'all' ? `All (${results.length})` : f === 'fail' ? `Failing (${failCount})` : `Passing (${passCount})`}
                </button>
              ))}
            </div>

            <div className="flex-1 overflow-auto max-h-[520px] scrollbar-thin divide-y divide-white/5">
              {filteredResults.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-slate-500">
                  <CheckCircle className="w-8 h-8 mb-2 text-emerald-500/40" />
                  <p className="text-sm">No results in this category</p>
                </div>
              ) : filteredResults.map(result => (
                <div key={result.id} className="group">
                  <button
                    onClick={() => setSelectedResult(selectedResult?.id === result.id ? null : result)}
                    className={`w-full text-left px-4 py-3 hover:bg-white/[0.03] transition-colors flex items-start gap-3 ${selectedResult?.id === result.id ? 'bg-white/[0.04]' : ''}`}
                  >
                    <div className="flex-shrink-0 mt-0.5">
                      {result.status === 'pass'
                        ? <CheckCircle className="w-4 h-4 text-emerald-400" />
                        : result.severity === 'critical' || result.severity === 'high'
                          ? <XCircle className="w-4 h-4 text-red-400" />
                          : <AlertTriangle className="w-4 h-4 text-amber-400" />
                      }
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="font-bold text-xs text-blue-400">{result.control_id}</span>
                        <span className="text-slate-600 text-[10px]">{result.check_id?.split('.').pop()}</span>
                        {result.status === 'fail' && <span className={severityBadge(result.severity)}>{result.severity}</span>}
                      </div>
                      <p className="text-xs text-slate-400 leading-tight line-clamp-2">{result.assertion}</p>
                      <div className="flex items-center gap-2 mt-1 text-[10px] text-slate-600">
                        <span className="uppercase font-semibold">{result.provider}</span>
                        <span>·</span>
                        <span>{result.region}</span>
                      </div>
                    </div>
                    <ChevronRight className={`w-3.5 h-3.5 text-slate-600 flex-shrink-0 transition-transform ${selectedResult?.id === result.id ? 'rotate-90' : ''}`} />
                  </button>

                  {/* Expanded remediation */}
                  {selectedResult?.id === result.id && result.status === 'fail' && (
                    <div className="px-4 pb-4 space-y-3 bg-white/[0.02]">
                      {result.findings.length > 0 && (
                        <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-3">
                          <p className="text-xs font-bold text-red-400 mb-2 flex items-center gap-1.5">
                            <AlertTriangle className="w-3.5 h-3.5" /> Findings
                          </p>
                          {result.findings.map((f, i) => (
                            <p key={i} className="text-xs text-red-300 leading-relaxed">• {f}</p>
                          ))}
                        </div>
                      )}
                      <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-3">
                        <p className="text-xs font-bold text-blue-400 mb-3 flex items-center gap-1.5">
                          <BookOpen className="w-3.5 h-3.5" /> Step-by-Step Remediation
                        </p>
                        <ol className="space-y-2">
                          {getRemediationSteps(result.control_id, result.assertion).map((step, i) => (
                            <li key={i} className="flex gap-2.5 text-xs text-slate-300 leading-relaxed">
                              <span className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-500/20 border border-blue-500/30 flex items-center justify-center font-bold text-blue-400 text-[10px]">{i + 1}</span>
                              <span>{step}</span>
                            </li>
                          ))}
                        </ol>
                        <div className="mt-3 pt-3 border-t border-blue-500/10 flex items-center gap-1.5 text-[10px] text-blue-400">
                          <Info className="w-3 h-3" />
                          Control: {result.control_id} · Check: {result.check_id}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
