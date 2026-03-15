import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Zap, CheckCircle, AlertTriangle, X, Key, Eye, EyeOff,
  RefreshCw, Trash2, ChevronRight, Loader2, Wifi, WifiOff
} from 'lucide-react';
import api from '../lib/api';

interface ToolDef {
  id: string;
  name: string;
  category: string;
  icon: string;
  fields: string[];
  layer?: number;
  optional?: boolean;
}

interface Connection {
  id: string;
  name: string;
  provider: string;
  is_active: boolean;
  last_sync_at: string | null;
  last_sync_status: string;
  configured_fields: string[];
  has_credentials: boolean;
  layer?: number;
}

const CATEGORY_ORDER = [
  'Cloud Security', 'Endpoint Security', 'Identity', 'SIEM',
  'Vulnerability', 'DevSecOps', 'Ticketing', 'Monitoring',
  'Alerting', 'GRC Platform', 'Evidence Management', 'Dashboard',
  'AI Reasoning', 'SIEM / APM',
];

const CATEGORY_COLORS: Record<string, string> = {
  'Cloud Security':      'from-blue-500/20 to-cyan-500/10 border-blue-500/20',
  'Endpoint Security':   'from-red-500/20 to-orange-500/10 border-red-500/20',
  'Identity':            'from-violet-500/20 to-purple-500/10 border-violet-500/20',
  'SIEM':                'from-amber-500/20 to-yellow-500/10 border-amber-500/20',
  'SIEM / APM':          'from-amber-500/20 to-yellow-500/10 border-amber-500/20',
  'Vulnerability':       'from-orange-500/20 to-red-500/10 border-orange-500/20',
  'DevSecOps':           'from-slate-500/20 to-slate-500/10 border-slate-500/20',
  'Ticketing':           'from-blue-500/20 to-indigo-500/10 border-blue-500/20',
  'Alerting':            'from-red-500/20 to-pink-500/10 border-red-500/20',
  'GRC Platform':        'from-emerald-500/20 to-teal-500/10 border-emerald-500/20',
  'Evidence Management': 'from-sky-500/20 to-blue-500/10 border-sky-500/20',
  'Dashboard':           'from-violet-500/20 to-indigo-500/10 border-violet-500/20',
  'AI Reasoning':        'from-amber-500/20 to-orange-500/10 border-amber-500/20',
};

function fieldLabel(field: string): string {
  return field.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function isSecret(field: string): boolean {
  return ['secret', 'token', 'password', 'key', 'json'].some(s => field.toLowerCase().includes(s));
}

export default function ToolConfigPage() {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<ToolDef | null>(null);
  const [formValues, setFormValues] = useState<Record<string, string>>({});
  const [showSecrets, setShowSecrets] = useState<Record<string, boolean>>({});
  const [testResult, setTestResult] = useState<{ status: string; message: string; latency_ms?: number } | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeCategory, setActiveCategory] = useState<string | null>(null);

  const { data: catalog } = useQuery<{ tools: ToolDef[] }>({
    queryKey: ['tool-catalog'],
    queryFn: async () => (await api.get('/tool-config/catalog')).data,
  });

  const { data: connections } = useQuery<Record<string, Connection>>({
    queryKey: ['tool-connections'],
    queryFn: async () => (await api.get('/tool-config/connections')).data,
  });

  const saveMutation = useMutation({
    mutationFn: async ({ provider, config }: { provider: string; config: Record<string, string> }) =>
      (await api.put(`/tool-config/connections/${provider}`, { config, is_active: true })).data,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tool-connections'] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (provider: string) =>
      (await api.delete(`/tool-config/connections/${provider}`)).data,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tool-connections'] });
      setSelected(null);
    },
  });

  const testMutation = useMutation({
    mutationFn: async (provider: string) =>
      (await api.post(`/tool-config/connections/${provider}/test`)).data,
    onSuccess: (data) => setTestResult(data),
  });

  const tools = catalog?.tools ?? [];
  const categories = CATEGORY_ORDER.filter(c => tools.some(t => t.category === c));

  const filtered = tools.filter(t =>
    (!activeCategory || t.category === activeCategory) &&
    (!searchTerm || t.name.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  const openConfig = (tool: ToolDef) => {
    setSelected(tool);
    setFormValues({});
    setTestResult(null);
    setShowSecrets({});
  };

  const handleSave = async () => {
    if (!selected) return;
    await saveMutation.mutateAsync({ provider: selected.id, config: formValues });
    setSelected(null);
  };

  return (
    <div className="space-y-6 text-white">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white">Tool Integrations</h2>
          <p className="text-sm text-slate-400 mt-0.5">
            Connect your security tools via API to enable automated evidence collection and compliance monitoring.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-medium">
            {Object.values(connections ?? {}).filter(c => c.has_credentials).length} connected
          </span>
          <span className="px-2.5 py-1 rounded-full bg-white/5 border border-white/10 text-slate-400 font-medium">
            {tools.length} available
          </span>
        </div>
      </div>

      {/* Search + Category filter */}
      <div className="flex flex-col sm:flex-row gap-3">
        <input
          type="text"
          placeholder="Search integrations…"
          value={searchTerm}
          onChange={e => setSearchTerm(e.target.value)}
          className="flex-1 bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/30"
        />
        <div className="flex gap-2 flex-wrap">
          <button
            onClick={() => setActiveCategory(null)}
            className={`px-3 py-2 rounded-lg text-xs font-medium transition-all ${
              !activeCategory ? 'bg-blue-600/20 border border-blue-500/30 text-blue-400' : 'bg-white/5 border border-white/10 text-slate-400 hover:bg-white/10'
            }`}
          >
            All
          </button>
          {categories.slice(0, 6).map(c => (
            <button
              key={c}
              onClick={() => setActiveCategory(activeCategory === c ? null : c)}
              className={`px-3 py-2 rounded-lg text-xs font-medium transition-all whitespace-nowrap ${
                activeCategory === c ? 'bg-blue-600/20 border border-blue-500/30 text-blue-400' : 'bg-white/5 border border-white/10 text-slate-400 hover:bg-white/10'
              }`}
            >
              {c}
            </button>
          ))}
        </div>
      </div>

      {/* Tool grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {filtered.map(tool => {
          const conn = connections?.[tool.id];
          const isConnected = conn?.has_credentials;
          const syncStatus = conn?.last_sync_status;
          const catColors = CATEGORY_COLORS[tool.category] ?? 'from-slate-500/20 to-slate-500/10 border-slate-500/20';

          return (
            <button
              key={tool.id}
              onClick={() => openConfig(tool)}
              className={`relative text-left bg-gradient-to-br ${catColors} border rounded-xl p-4 hover:scale-[1.02] transition-all group`}
            >
              {isConnected && (
                <div className="absolute top-3 right-3">
                  <span className="flex items-center gap-1 text-[10px] font-semibold text-emerald-400">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                    Connected
                  </span>
                </div>
              )}

              <div className="flex items-center gap-2 mb-2">
                <span className="text-2xl">{tool.icon ?? '🔌'}</span>
                {tool.optional && (
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/10 border border-amber-500/20 text-amber-400 font-bold">
                    OPTIONAL
                  </span>
                )}
              </div>
              <h3 className="font-semibold text-white text-sm leading-tight mb-1">{tool.name}</h3>
              <p className="text-[10px] text-slate-500 mb-3">
                {tool.category}{tool.layer ? ` · Layer ${tool.layer}` : ''}
              </p>

              <div className="flex items-center justify-between">
                <div className="flex gap-1 flex-wrap">
                  {tool.fields.slice(0, 2).map(f => (
                    <span key={f} className="text-[9px] px-1.5 py-0.5 bg-white/5 rounded text-slate-500">
                      {fieldLabel(f).split(' ')[0]}
                    </span>
                  ))}
                  {tool.fields.length > 2 && (
                    <span className="text-[9px] px-1.5 py-0.5 bg-white/5 rounded text-slate-500">+{tool.fields.length - 2}</span>
                  )}
                </div>
                <ChevronRight className="w-3.5 h-3.5 text-slate-600 group-hover:text-slate-400 transition-colors" />
              </div>

              {isConnected && syncStatus === 'error' && (
                <div className="mt-2 flex items-center gap-1 text-[10px] text-amber-400">
                  <AlertTriangle className="w-3 h-3" /> Sync error
                </div>
              )}
            </button>
          );
        })}
      </div>

      {/* Configuration slide-over */}
      {selected && (
        <div className="fixed inset-0 z-50 flex">
          <div className="fixed inset-0 bg-black/70 backdrop-blur-sm" onClick={() => setSelected(null)} />
          <div className="relative ml-auto w-full max-w-md bg-[#0d1117] border-l border-white/8 flex flex-col h-full overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-white/8 bg-gradient-to-r from-blue-500/5 to-violet-500/5">
              <div className="flex items-center gap-3">
                <div className="text-2xl">{selected.icon}</div>
                <div>
                  <h3 className="font-bold text-white">{selected.name}</h3>
                  <p className="text-xs text-slate-400">{selected.category}</p>
                </div>
              </div>
              <button onClick={() => setSelected(null)} className="p-2 hover:bg-white/5 rounded-lg text-slate-400 hover:text-white transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-5">
              {/* Existing connection status */}
              {connections?.[selected.id]?.has_credentials && (
                <div className="flex items-center justify-between bg-emerald-500/10 border border-emerald-500/20 rounded-xl px-4 py-3">
                  <div className="flex items-center gap-2 text-emerald-400 text-sm font-medium">
                    <Wifi className="w-4 h-4" />
                    Connected
                  </div>
                  <button
                    onClick={() => deleteMutation.mutate(selected.id)}
                    className="text-xs text-red-400 hover:text-red-300 flex items-center gap-1 transition-colors"
                  >
                    <Trash2 className="w-3.5 h-3.5" /> Disconnect
                  </button>
                </div>
              )}

              {/* Credential fields */}
              <div className="space-y-4">
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                  <Key className="w-3.5 h-3.5" /> API Credentials
                </h4>
                {selected.fields.map(field => {
                  const secret = isSecret(field);
                  const shown = showSecrets[field];
                  return (
                    <div key={field}>
                      <label className="block text-xs font-medium text-slate-300 mb-1.5">
                        {fieldLabel(field)}
                        {secret && <span className="ml-1.5 text-[10px] text-slate-600">(encrypted at rest)</span>}
                      </label>
                      <div className="relative">
                        <input
                          type={secret && !shown ? 'password' : 'text'}
                          value={formValues[field] ?? ''}
                          onChange={e => setFormValues(p => ({ ...p, [field]: e.target.value }))}
                          placeholder={secret ? '••••••••••••••••' : `Enter ${fieldLabel(field).toLowerCase()}`}
                          className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/30 pr-10"
                        />
                        {secret && (
                          <button
                            type="button"
                            onClick={() => setShowSecrets(p => ({ ...p, [field]: !shown }))}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                          >
                            {shown ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Test result */}
              {testResult && (
                <div className={`flex items-start gap-3 p-4 rounded-xl border ${
                  testResult.status === 'success'
                    ? 'bg-emerald-500/10 border-emerald-500/20'
                    : 'bg-red-500/10 border-red-500/20'
                }`}>
                  {testResult.status === 'success'
                    ? <CheckCircle className="w-5 h-5 text-emerald-400 flex-shrink-0 mt-0.5" />
                    : <WifiOff className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                  }
                  <div>
                    <p className={`text-sm font-medium ${testResult.status === 'success' ? 'text-emerald-300' : 'text-red-300'}`}>
                      {testResult.status === 'success' ? 'Connection successful' : 'Connection failed'}
                    </p>
                    <p className="text-xs text-slate-400 mt-0.5">{testResult.message}</p>
                    {testResult.latency_ms && (
                      <p className="text-xs text-emerald-500 mt-1">Response time: {testResult.latency_ms}ms</p>
                    )}
                  </div>
                </div>
              )}

              {/* Help text */}
              <div className="bg-white/3 border border-white/5 rounded-xl p-4">
                <p className="text-xs text-slate-500 leading-relaxed">
                  Credentials are stored encrypted and used only for automated evidence collection during compliance assessments.
                  In demo mode, connections are simulated — no real API calls are made.
                </p>
              </div>
            </div>

            {/* Footer */}
            <div className="p-4 border-t border-white/8 flex gap-3">
              <button
                onClick={() => testMutation.mutate(selected.id)}
                disabled={testMutation.isPending}
                className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl bg-white/5 border border-white/10 text-sm font-medium text-slate-300 hover:bg-white/10 transition-colors disabled:opacity-50"
              >
                {testMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                Test
              </button>
              <button
                onClick={handleSave}
                disabled={saveMutation.isPending || Object.keys(formValues).length === 0}
                className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-semibold text-white transition-all disabled:opacity-40 shadow-lg shadow-blue-500/20"
              >
                {saveMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle className="w-4 h-4" />}
                Save & Connect
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
