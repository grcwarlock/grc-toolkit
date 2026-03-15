import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Network, Loader2, Shield, AlertTriangle, Server, Users, ArrowRight } from 'lucide-react';
import api from '../lib/api';

const NODE_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  threat: { bg: 'bg-red-500/15', border: 'border-red-500/30', text: 'text-red-400' },
  control: { bg: 'bg-blue-500/15', border: 'border-blue-500/30', text: 'text-blue-400' },
  asset: { bg: 'bg-emerald-500/15', border: 'border-emerald-500/30', text: 'text-emerald-400' },
  vendor: { bg: 'bg-violet-500/15', border: 'border-violet-500/30', text: 'text-violet-400' },
};

const NODE_ICONS: Record<string, any> = {
  threat: AlertTriangle,
  control: Shield,
  asset: Server,
  vendor: Users,
};

const REL_COLORS: Record<string, string> = {
  mitigates: 'text-blue-500',
  targets: 'text-red-500',
  provides: 'text-violet-500',
  supports: 'text-emerald-500',
};

export default function RiskGraphPage() {
  const { data: graph, isLoading } = useQuery({
    queryKey: ['risk', 'graph'],
    queryFn: async () => (await api.get('/risk/graph')).data,
  });

  const edgesBySource = useMemo(() => {
    if (!graph) return {};
    const map: Record<string, any[]> = {};
    for (const edge of graph.edges) {
      if (!map[edge.source]) map[edge.source] = [];
      map[edge.source].push(edge);
    }
    return map;
  }, [graph]);

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-32 text-slate-500">
        <Loader2 className="w-8 h-8 animate-spin mb-3" />
        <p className="text-sm">Loading risk graph…</p>
      </div>
    );
  }

  if (!graph) return null;

  return (
    <div className="space-y-5 page-enter text-white">
      {/* Header */}
      <div className="bg-[#0d1117] border border-white/8 rounded-2xl p-5">
        <h2 className="text-lg font-bold text-white flex items-center gap-2">
          <Network className="w-5 h-5 text-blue-400" /> Risk Relationship Graph
        </h2>
        <p className="text-slate-400 text-sm mt-0.5">Visualize how threats, controls, assets, and vendors are interconnected</p>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Threats', value: graph.summary.threat_count, cls: 'text-red-400 border-red-500/20', icon: AlertTriangle },
          { label: 'Controls', value: graph.summary.control_count, cls: 'text-blue-400 border-blue-500/20', icon: Shield },
          { label: 'Assets', value: graph.summary.asset_count, cls: 'text-emerald-400 border-emerald-500/20', icon: Server },
          { label: 'Vendors', value: graph.summary.vendor_count, cls: 'text-violet-400 border-violet-500/20', icon: Users },
        ].map(c => {
          const Icon = c.icon;
          return (
            <div key={c.label} className={`bg-[#0d1117] border ${c.cls} rounded-2xl p-4`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-slate-400">{c.label}</span>
                <Icon className={`w-4 h-4 ${c.cls.split(' ')[0]}`} />
              </div>
              <p className={`text-3xl font-extrabold ${c.cls.split(' ')[0]}`}>{c.value}</p>
            </div>
          );
        })}
      </div>

      {/* Graph visualization — cluster-based layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {graph.clusters.map((cluster: any) => {
          const clusterNodes = graph.nodes.filter((n: any) => cluster.node_ids.includes(n.id));
          return (
            <div key={cluster.id} className="bg-[#0d1117] border border-white/8 rounded-2xl p-5">
              <h3 className="text-sm font-bold text-white mb-4">{cluster.label}</h3>
              <div className="space-y-2">
                {clusterNodes.map((node: any) => {
                  const colors = NODE_COLORS[node.type] || NODE_COLORS.asset;
                  const Icon = NODE_ICONS[node.type] || Server;
                  const nodeEdges = edgesBySource[node.id] || [];
                  return (
                    <div key={node.id} className={`${colors.bg} border ${colors.border} rounded-xl p-3`}>
                      <div className="flex items-center gap-2 mb-1">
                        <Icon className={`w-4 h-4 ${colors.text}`} />
                        <span className={`text-sm font-semibold ${colors.text}`}>{node.label}</span>
                        {node.risk_level && (
                          <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded capitalize ${
                            node.risk_level === 'high' ? 'bg-red-500/15 text-red-400' :
                            node.risk_level === 'medium' ? 'bg-amber-500/15 text-amber-400' : 'bg-blue-500/15 text-blue-400'
                          }`}>{node.risk_level}</span>
                        )}
                        {node.criticality && (
                          <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-400">{node.criticality}</span>
                        )}
                      </div>
                      {node.category && <p className="text-[10px] text-slate-500 ml-6 capitalize">{node.category}</p>}
                      {node.impact_mode && <p className="text-[10px] text-slate-500 ml-6">Impact: ${(node.impact_mode / 1000).toFixed(0)}K • Freq: {node.frequency_mode}/yr</p>}
                      {nodeEdges.length > 0 && (
                        <div className="mt-2 ml-6 space-y-0.5">
                          {nodeEdges.map((edge: any, i: number) => {
                            const targetNode = graph.nodes.find((n: any) => n.id === edge.target);
                            return (
                              <div key={i} className="flex items-center gap-1.5 text-[10px]">
                                <ArrowRight className={`w-3 h-3 ${REL_COLORS[edge.relationship] || 'text-slate-500'}`} />
                                <span className={`${REL_COLORS[edge.relationship] || 'text-slate-500'} font-semibold capitalize`}>{edge.relationship}</span>
                                <span className="text-slate-400">{targetNode?.label || edge.target}</span>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      {/* Connection matrix */}
      <div className="bg-[#0d1117] border border-white/8 rounded-2xl p-5">
        <h3 className="text-sm font-bold text-white mb-4">Relationship Matrix ({graph.edges.length} connections)</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {graph.edges.map((edge: any, i: number) => {
            const sourceNode = graph.nodes.find((n: any) => n.id === edge.source);
            const targetNode = graph.nodes.find((n: any) => n.id === edge.target);
            return (
              <div key={i} className="flex items-center gap-2 bg-white/[0.02] border border-white/5 rounded-lg px-3 py-2">
                <span className={`text-[10px] font-semibold ${NODE_COLORS[sourceNode?.type]?.text || 'text-slate-400'}`}>{sourceNode?.label}</span>
                <ArrowRight className={`w-3 h-3 ${REL_COLORS[edge.relationship] || 'text-slate-500'} flex-shrink-0`} />
                <span className={`text-[10px] font-semibold ${NODE_COLORS[targetNode?.type]?.text || 'text-slate-400'}`}>{targetNode?.label}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
