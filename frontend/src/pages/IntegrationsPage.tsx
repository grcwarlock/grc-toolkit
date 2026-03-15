import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Plug, RefreshCw, Plus, Trash2, CheckCircle, AlertTriangle,
  Loader2, ZapIcon, Cloud, Code, Shield, Database, Globe,
  Activity, Layers, Server, Lock, Bell, FileText, Brain,
  ChevronRight, ExternalLink, X
} from 'lucide-react';
import api from '../lib/api';

interface IntegrationCatalogItem {
  id: string;
  name: string;
  type: string;
  category: string;
  description: string;
  icon: string;
  frameworks: string[];
  control_families: Record<string, string[]>;
  layer: number;
  optional?: boolean;
  doc_url: string;
  auth_fields: string[];
}

interface IntegrationResponse {
  id: string;
  name: string;
  provider: string;
  source_type: string;
  is_active: boolean;
  last_sync_at: string | null;
  last_sync_status: string;
  sync_interval_minutes: number;
}

interface SyncResult {
  provider: string;
  findings_synced: number;
  control_families_covered: Record<string, string[]>;
  findings: Array<{
    description: string;
    severity: string;
    control_family: string;
    control_mappings: Record<string, string>;
    asset: string;
  }>;
  synced_at: string;
}

const LAYER_META: Record<number, { label: string; color: string; border: string; desc: string }> = {
  1: { label: "LAYER 1", color: "text-[#00D4FF]", border: "border-[#00D4FF]/25", desc: "Data Collection" },
  3: { label: "LAYER 3", color: "text-[#F59E0B]", border: "border-[#F59E0B]/25", desc: "AI Reasoning (Optional)" },
  4: { label: "LAYER 4", color: "text-[#10B981]", border: "border-[#10B981]/25", desc: "Output & Action" },
};

const CATEGORY_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  CLOUD:      Cloud,
  EDR:        Shield,
  IDENTITY:   Lock,
  SCANNER:    Layers,
  SIEM:       Activity,
  DEVSECOPS:  Code,
  GRC:        Globe,
  ALERTING:   Bell,
  TICKETING:  Database,
  EVIDENCE:   FileText,
  DASHBOARD:  Server,
  AI:         Brain,
};

const FRAMEWORK_COLORS: Record<string, string> = {
  nist_800_53: "bg-blue-500/15 text-blue-400 border-blue-500/20",
  soc2:        "bg-emerald-500/15 text-emerald-400 border-emerald-500/20",
  iso27001:    "bg-violet-500/15 text-violet-400 border-violet-500/20",
  hipaa:       "bg-amber-500/15 text-amber-400 border-amber-500/20",
  cmmc_l2:     "bg-red-500/15 text-red-400 border-red-500/20",
};

const FRAMEWORK_LABELS: Record<string, string> = {
  nist_800_53: "NIST 800-53",
  soc2:        "SOC 2",
  iso27001:    "ISO 27001",
  hipaa:       "HIPAA",
  cmmc_l2:     "CMMC L2",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border border-red-500/25",
  high:     "bg-orange-500/15 text-orange-400 border border-orange-500/25",
  medium:   "bg-amber-500/15 text-amber-400 border border-amber-500/25",
  low:      "bg-blue-500/15 text-blue-400 border border-blue-500/25",
};

const PROVIDER_GRADIENT: Record<string, string> = {
  aws:          "from-amber-500 to-orange-500",
  azure:        "from-blue-500 to-cyan-500",
  gcp:          "from-red-500 to-orange-400",
  prisma_cloud: "from-orange-500 to-red-500",
  crowdstrike:  "from-red-600 to-rose-500",
  ms_defender:  "from-blue-600 to-blue-400",
  sentinelone:  "from-violet-600 to-purple-500",
  okta:         "from-blue-500 to-indigo-500",
  entra_id:     "from-blue-600 to-cyan-400",
  cyberark:     "from-red-700 to-red-500",
  sailpoint:    "from-teal-600 to-emerald-500",
  google_workspace: "from-blue-400 to-green-400",
  tenable:      "from-emerald-600 to-teal-500",
  qualys:       "from-red-500 to-orange-500",
  rapid7:       "from-orange-600 to-amber-500",
  wiz:          "from-violet-500 to-fuchsia-500",
  orca:         "from-teal-500 to-cyan-400",
  ms_sentinel:  "from-blue-600 to-indigo-500",
  splunk:       "from-green-600 to-emerald-500",
  elastic:      "from-amber-500 to-yellow-400",
  datadog:      "from-violet-500 to-purple-400",
  github:       "from-slate-600 to-slate-400",
  gitlab:       "from-orange-500 to-amber-400",
  snyk:         "from-violet-600 to-purple-500",
  servicenow:   "from-green-600 to-teal-500",
  drata:        "from-blue-600 to-violet-500",
  vanta:        "from-indigo-600 to-blue-500",
  pagerduty:    "from-green-600 to-emerald-500",
  slack:        "from-violet-500 to-fuchsia-400",
  jira:         "from-blue-600 to-blue-400",
  confluence:   "from-blue-700 to-blue-500",
  sharepoint:   "from-teal-600 to-cyan-500",
  aws_s3:       "from-amber-600 to-orange-500",
  grafana:      "from-orange-500 to-amber-400",
  openai:       "from-emerald-500 to-teal-400",
  anthropic:    "from-amber-500 to-orange-400",
  gemini:       "from-blue-500 to-violet-500",
  ollama:       "from-slate-600 to-slate-400",
};

function providerGradient(id: string) {
  return PROVIDER_GRADIENT[id] ?? "from-violet-500 to-purple-400";
}

export default function IntegrationsPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'connected' | 'catalog'>('connected');
  const [syncResult, setSyncResult] = useState<SyncResult | null>(null);
  const [connectingId, setConnectingId] = useState<string | null>(null);
  const [filterLayer, setFilterLayer] = useState<number | null>(null);

  const { data: catalog } = useQuery<{ integrations: IntegrationCatalogItem[] }>({
    queryKey: ['integrations', 'catalog'],
    queryFn: async () => (await api.get('/integrations/catalog')).data,
  });

  const { data: connected, isLoading } = useQuery<IntegrationResponse[]>({
    queryKey: ['integrations', 'connected'],
    queryFn: async () => (await api.get('/integrations/')).data,
    refetchInterval: 15000,
  });

  const syncMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await api.post(`/integrations/${id}/sync`);
      return res.data as SyncResult;
    },
    onSuccess: (data) => {
      setSyncResult(data);
      queryClient.invalidateQueries({ queryKey: ['integrations', 'connected'] });
    },
  });

  const connectMutation = useMutation({
    mutationFn: async (providerId: string) =>
      api.post('/integrations/', { integration_id: providerId, config: {} }),
    onSuccess: () => {
      setConnectingId(null);
      setActiveTab('connected');
      queryClient.invalidateQueries({ queryKey: ['integrations', 'connected'] });
    },
  });

  const removeMutation = useMutation({
    mutationFn: async (id: string) => api.delete(`/integrations/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['integrations', 'connected'] }),
  });

  const connectedProviders = new Set(connected?.map(c => c.provider) ?? []);
  const allItems = catalog?.integrations ?? [];

  const layerGroups: Record<number, IntegrationCatalogItem[]> = {};
  allItems.forEach(item => {
    const l = item.layer ?? 1;
    if (!layerGroups[l]) layerGroups[l] = [];
    layerGroups[l].push(item);
  });

  const catalogByCategory: Record<string, IntegrationCatalogItem[]> = {};
  const itemsToShow = filterLayer ? (layerGroups[filterLayer] ?? []) : allItems;
  itemsToShow.forEach(item => {
    if (!catalogByCategory[item.category]) catalogByCategory[item.category] = [];
    catalogByCategory[item.category].push(item);
  });

  return (
    <div className="space-y-5 page-enter text-white">
      {/* Header */}
      <div className="bg-[#0d1117] border border-white/8 rounded-2xl p-5">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Plug className="w-5 h-5 text-violet-400" />
              Integrations
            </h2>
            <p className="text-slate-400 text-sm mt-0.5">
              {connected?.length ?? 0} connected · {allItems.length} available ·
              Findings automatically mapped to NIST 800-53, SOC 2, ISO 27001, HIPAA, and CMMC L2 controls
            </p>
          </div>
          <div className="flex gap-2 flex-wrap">
            {Object.entries(FRAMEWORK_LABELS).map(([k, label]) => (
              <span key={k} className={`px-2.5 py-1 rounded-lg text-[10px] font-bold border ${FRAMEWORK_COLORS[k]}`}>
                {label}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Architecture layer summary */}
      <div className="grid grid-cols-3 gap-3">
        {[1, 3, 4].map(layer => {
          const meta = LAYER_META[layer];
          const count = (layerGroups[layer] ?? []).length;
          const connCount = (layerGroups[layer] ?? []).filter(i => connectedProviders.has(i.id)).length;
          return (
            <button
              key={layer}
              onClick={() => setFilterLayer(filterLayer === layer ? null : layer)}
              className={`bg-[#0d1117] border ${filterLayer === layer ? meta.border + ' ring-1 ring-inset ' + meta.border : 'border-white/8'} rounded-2xl p-4 text-left hover:border-white/15 transition-all`}
            >
              <div className={`text-[10px] font-bold font-mono tracking-wider mb-1 ${meta.color}`}>{meta.label}</div>
              <div className="font-bold text-white text-sm">{meta.desc}</div>
              <div className="text-xs text-slate-500 mt-1">{count} tools · {connCount} connected</div>
            </button>
          );
        })}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-[#0d1117] border border-white/8 p-1 rounded-xl w-fit">
        {([['connected', 'Connected Tools'], ['catalog', 'Integration Catalog']] as const).map(([id, label]) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`px-4 py-2 rounded-lg text-sm font-semibold transition-all ${
              activeTab === id ? 'bg-white/10 text-white shadow-sm' : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            {label}
            {id === 'connected' && (connected?.length ?? 0) > 0 && (
              <span className="ml-1.5 px-1.5 py-0.5 rounded-full bg-blue-500/20 text-blue-400 text-[10px] font-bold">
                {connected!.length}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ── Connected Tools ── */}
      {activeTab === 'connected' && (
        <div className="space-y-4">
          {/* Sync result panel */}
          {syncResult && (
            <div className="bg-[#0d1117] border border-emerald-500/20 rounded-2xl p-5">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="font-bold text-white flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-emerald-400" />
                    Sync Complete — {syncResult.provider}
                  </h3>
                  <p className="text-slate-400 text-xs mt-0.5">
                    {syncResult.findings_synced} findings mapped to controls ·{' '}
                    {new Date(syncResult.synced_at).toLocaleString()}
                  </p>
                </div>
                <button onClick={() => setSyncResult(null)} className="text-slate-500 hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Framework coverage */}
              <div className="flex gap-2 flex-wrap mb-4">
                {Object.entries(syncResult.control_families_covered).map(([fw, fams]) => (
                  <div key={fw} className={`px-2.5 py-1 rounded-lg text-[10px] font-bold border ${FRAMEWORK_COLORS[fw] ?? ''}`}>
                    {FRAMEWORK_LABELS[fw] ?? fw}: {fams.join(', ')}
                  </div>
                ))}
              </div>

              {/* Findings list */}
              {syncResult.findings.length > 0 && (
                <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                  {syncResult.findings.map((f, i) => (
                    <div key={i} className="flex items-start gap-3 bg-white/3 rounded-xl p-3">
                      <span className={`px-2 py-0.5 rounded-md text-[10px] font-bold flex-shrink-0 ${SEVERITY_COLORS[f.severity] ?? ''}`}>
                        {f.severity.toUpperCase()}
                      </span>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs text-slate-200 font-medium">{f.description}</p>
                        <div className="flex gap-1 mt-1 flex-wrap">
                          {Object.entries(f.control_mappings).slice(0, 3).map(([fw, ctrl]) => (
                            <span key={fw} className="text-[9px] text-slate-500 bg-white/5 px-1.5 py-0.5 rounded font-mono">
                              {ctrl}
                            </span>
                          ))}
                          <span className="text-[9px] text-slate-500">· {f.asset}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Connected grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {isLoading
              ? Array.from({ length: 6 }).map((_, i) => (
                  <div key={i} className="bg-[#0d1117] border border-white/8 rounded-2xl p-5 animate-pulse">
                    <div className="h-4 bg-white/5 rounded w-2/3 mb-2" />
                    <div className="h-3 bg-white/5 rounded w-1/3 mb-4" />
                    <div className="h-8 bg-white/5 rounded" />
                  </div>
                ))
              : (connected?.length ?? 0) === 0
              ? (
                <div className="col-span-3 py-16 text-center text-slate-500">
                  <Plug className="w-10 h-10 mx-auto mb-3 opacity-30" />
                  <p className="text-sm font-semibold mb-1">No integrations connected</p>
                  <button
                    onClick={() => setActiveTab('catalog')}
                    className="text-sm text-blue-400 hover:text-blue-300 transition-colors"
                  >
                    Browse the catalog →
                  </button>
                </div>
              )
              : connected!.map(integration => {
                  const isSyncing =
                    syncMutation.isPending && syncMutation.variables === integration.id;
                  const catalogEntry = allItems.find(i => i.id === integration.provider);
                  const layerMeta = LAYER_META[catalogEntry?.layer ?? 1];
                  return (
                    <div
                      key={integration.id}
                      className="bg-[#0d1117] border border-white/8 hover:border-white/15 rounded-2xl p-5 transition-all"
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center gap-3">
                          <div
                            className={`w-10 h-10 rounded-xl bg-gradient-to-br ${providerGradient(integration.provider)} flex items-center justify-center flex-shrink-0 shadow-lg`}
                          >
                            <Plug className="w-4 h-4 text-white" />
                          </div>
                          <div>
                            <h3 className="font-bold text-white text-sm">{integration.name}</h3>
                            <span className={`text-[10px] font-bold font-mono ${layerMeta?.color ?? 'text-slate-500'}`}>
                              {layerMeta?.label} · {layerMeta?.desc}
                            </span>
                          </div>
                        </div>
                        <div className="flex items-center gap-1.5">
                          {isSyncing ? (
                            <Loader2 className="w-3.5 h-3.5 text-blue-400 animate-spin" />
                          ) : integration.is_active ? (
                            <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                          )}
                          <span
                            className={`text-[10px] font-semibold ${
                              isSyncing
                                ? 'text-blue-400'
                                : integration.is_active
                                ? 'text-emerald-400'
                                : 'text-amber-400'
                            }`}
                          >
                            {isSyncing ? 'Syncing' : integration.is_active ? 'Active' : 'Inactive'}
                          </span>
                        </div>
                      </div>

                      {/* Framework badges */}
                      {catalogEntry?.frameworks && (
                        <div className="flex gap-1 flex-wrap mb-3">
                          {catalogEntry.frameworks.slice(0, 4).map(fw => (
                            <span
                              key={fw}
                              className={`px-1.5 py-0.5 rounded text-[9px] font-bold border ${FRAMEWORK_COLORS[fw] ?? ''}`}
                            >
                              {FRAMEWORK_LABELS[fw] ?? fw}
                            </span>
                          ))}
                          {(catalogEntry.frameworks.length ?? 0) > 4 && (
                            <span className="text-[9px] text-slate-500 self-center">
                              +{catalogEntry.frameworks.length - 4}
                            </span>
                          )}
                        </div>
                      )}

                      {integration.last_sync_at && (
                        <p className="text-xs text-slate-500 mb-3">
                          Synced {new Date(integration.last_sync_at).toLocaleString()}
                        </p>
                      )}

                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => syncMutation.mutate(integration.id)}
                          disabled={isSyncing}
                          className="flex-1 flex items-center justify-center gap-2 py-2 rounded-xl bg-white/5 border border-white/10 hover:bg-blue-500/10 hover:border-blue-500/20 hover:text-blue-400 text-xs font-semibold text-slate-300 transition-colors disabled:opacity-50"
                        >
                          <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
                          Sync Now
                        </button>
                        <button
                          onClick={() => {
                            if (confirm(`Remove ${integration.name}?`))
                              removeMutation.mutate(integration.id);
                          }}
                          className="p-2 rounded-xl bg-white/5 border border-white/10 hover:bg-red-500/10 hover:border-red-500/20 text-slate-500 hover:text-red-400 transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  );
                })}
          </div>
        </div>
      )}

      {/* ── Catalog ── */}
      {activeTab === 'catalog' && (
        <div className="space-y-8">
          {filterLayer && (
            <div className="flex items-center gap-2">
              <span className={`text-xs font-bold font-mono ${LAYER_META[filterLayer]?.color}`}>
                {LAYER_META[filterLayer]?.label}: {LAYER_META[filterLayer]?.desc}
              </span>
              <button
                onClick={() => setFilterLayer(null)}
                className="text-slate-500 hover:text-white text-xs"
              >
                (clear filter ×)
              </button>
            </div>
          )}

          {Object.entries(catalogByCategory).map(([category, items]) => {
            const CatIcon = CATEGORY_ICONS[category] ?? ZapIcon;
            return (
              <div key={category}>
                <div className="flex items-center gap-2.5 mb-3">
                  <CatIcon className="w-4 h-4 text-slate-400" />
                  <h3 className="text-sm font-bold text-white capitalize">
                    {category.charAt(0) + category.slice(1).toLowerCase().replace('devsecops', 'DevSecOps')}
                  </h3>
                  <span className="text-xs text-slate-600">
                    {items.length} tool{items.length !== 1 ? 's' : ''}
                  </span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                  {items.map(item => {
                    const isConn = connectedProviders.has(item.id);
                    const isConnecting = connectingId === item.id && connectMutation.isPending;
                    const layerMeta = LAYER_META[item.layer ?? 1];
                    return (
                      <div
                        key={item.id}
                        className={`bg-[#0d1117] border ${
                          isConn ? 'border-emerald-500/20' : 'border-white/8'
                        } hover:border-white/15 rounded-2xl p-4 transition-all flex flex-col`}
                      >
                        {/* Card header */}
                        <div className="flex items-start gap-3 mb-2">
                          <div
                            className={`w-9 h-9 rounded-xl bg-gradient-to-br ${providerGradient(item.id)} flex items-center justify-center flex-shrink-0`}
                          >
                            <Plug className="w-4 h-4 text-white" />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <h4 className="font-bold text-white text-sm">{item.name}</h4>
                              {item.optional && (
                                <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/10 border border-amber-500/20 text-amber-400 font-bold">
                                  OPTIONAL
                                </span>
                              )}
                            </div>
                            <span className={`text-[10px] font-bold font-mono ${layerMeta?.color ?? 'text-slate-500'}`}>
                              {layerMeta?.label} · {item.type.toUpperCase()}
                            </span>
                          </div>
                        </div>

                        {/* Description */}
                        <p className="text-xs text-slate-400 leading-relaxed mb-3 flex-1 line-clamp-2">
                          {item.description}
                        </p>

                        {/* Framework coverage */}
                        <div className="flex gap-1 flex-wrap mb-3">
                          {item.frameworks.map(fw => (
                            <span
                              key={fw}
                              className={`px-1.5 py-0.5 rounded text-[9px] font-bold border ${FRAMEWORK_COLORS[fw] ?? ''}`}
                            >
                              {FRAMEWORK_LABELS[fw] ?? fw}
                            </span>
                          ))}
                        </div>

                        {/* Control families preview */}
                        {item.control_families?.nist_800_53 && (
                          <div className="mb-3">
                            <p className="text-[9px] text-slate-600 font-mono mb-1">
                              NIST 800-53 FAMILIES:
                            </p>
                            <p className="text-[10px] text-slate-400 font-mono">
                              {item.control_families.nist_800_53.join(' · ')}
                            </p>
                          </div>
                        )}

                        {/* Actions */}
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => {
                              if (!isConn) {
                                setConnectingId(item.id);
                                connectMutation.mutate(item.id);
                              }
                            }}
                            disabled={isConnecting}
                            className={`flex-1 flex items-center justify-center gap-1.5 py-2 rounded-xl text-xs font-bold transition-all ${
                              isConn
                                ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 cursor-default'
                                : 'bg-white/5 border border-white/10 hover:bg-blue-500/10 hover:border-blue-500/20 hover:text-blue-400 text-slate-300'
                            }`}
                          >
                            {isConnecting ? (
                              <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            ) : isConn ? (
                              <><CheckCircle className="w-3.5 h-3.5" /> Connected</>
                            ) : (
                              <><Plus className="w-3.5 h-3.5" /> Connect</>
                            )}
                          </button>
                          {item.doc_url && (
                            <a
                              href={item.doc_url}
                              target="_blank"
                              rel="noreferrer"
                              className="p-2 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 text-slate-500 hover:text-slate-300 transition-colors"
                              title="API Docs"
                            >
                              <ExternalLink className="w-3.5 h-3.5" />
                            </a>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
