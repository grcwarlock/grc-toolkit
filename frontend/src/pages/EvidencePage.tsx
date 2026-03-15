import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Download, Search, Database, CheckCircle, XCircle, Filter, RefreshCw } from 'lucide-react';
import api from '../lib/api';

interface EvidenceItem {
  id: string;
  control_id: string;
  check_id: string;
  provider: string;
  service: string;
  resource_type: string;
  region: string;
  account_id: string;
  collected_at: string;
  status: string;
  sha256_hash: string;
}

interface EvidenceListResponse {
  items: EvidenceItem[];
  total: number;
  page: number;
  page_size: number;
}

const PROVIDER_COLORS: Record<string, string> = {
  aws:     'bg-amber-500/15 text-amber-400 border-amber-500/20',
  azure:   'bg-blue-500/15 text-blue-400 border-blue-500/20',
  gcp:     'bg-emerald-500/15 text-emerald-400 border-emerald-500/20',
  okta:    'bg-violet-500/15 text-violet-400 border-violet-500/20',
  manual:  'bg-slate-500/15 text-slate-400 border-slate-500/20',
  qualys:  'bg-red-500/15 text-red-400 border-red-500/20',
  splunk:  'bg-orange-500/15 text-orange-400 border-orange-500/20',
};

function providerBadge(provider: string) {
  const cls = PROVIDER_COLORS[provider.toLowerCase()] ?? 'bg-slate-500/15 text-slate-400 border-slate-500/20';
  return `${cls} text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase`;
}

export default function EvidencePage() {
  const [page, setPage] = useState(1);
  const [providerFilter, setProviderFilter] = useState('');
  const [searchControl, setSearchControl] = useState('');

  const { data, isLoading, refetch } = useQuery<EvidenceListResponse>({
    queryKey: ['evidence', page, providerFilter, searchControl],
    queryFn: async () => {
      let url = `/evidence/?page=${page}&page_size=25`;
      if (providerFilter) url += `&provider=${providerFilter}`;
      if (searchControl) url += `&control_id=${searchControl}`;
      return (await api.get(url)).data;
    },
  });

  const handleExport = async () => {
    try {
      const res = await api.get('/export/evidence?format=csv', { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement('a');
      a.href = url;
      a.setAttribute('download', `evidence_export_${new Date().toISOString().split('T')[0]}.csv`);
      document.body.appendChild(a);
      a.click();
      a.parentNode?.removeChild(a);
    } catch (e) { console.error(e); }
  };

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / 25);

  return (
    <div className="space-y-5 page-enter text-white">
      {/* Header */}
      <div className="bg-[#0d1117] border border-white/8 rounded-2xl p-5 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Database className="w-5 h-5 text-blue-400" /> Evidence Repository
          </h2>
          <p className="text-slate-400 text-sm mt-0.5">
            {total.toLocaleString()} immutable records · raw configuration states and logs
          </p>
        </div>
        <div className="flex items-center gap-2 w-full md:w-auto">
          <button onClick={() => refetch()} className="p-2.5 bg-white/5 border border-white/10 rounded-xl text-slate-400 hover:text-white hover:bg-white/10 transition-colors">
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={handleExport}
            className="flex items-center gap-2 bg-white/5 border border-white/10 hover:bg-white/10 text-slate-300 px-4 py-2.5 rounded-xl text-sm font-medium transition-colors"
          >
            <Download className="w-4 h-4" /> Export CSV
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={searchControl}
            onChange={e => { setSearchControl(e.target.value); setPage(1); }}
            placeholder="Search by control ID (e.g. AC-2, A.5.1)"
            className="w-full bg-[#0d1117] border border-white/8 rounded-xl pl-9 pr-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20"
          />
        </div>
        <div className="relative">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <select
            value={providerFilter}
            onChange={e => { setProviderFilter(e.target.value); setPage(1); }}
            className="bg-[#0d1117] border border-white/8 rounded-xl pl-9 pr-8 py-2.5 text-sm text-white focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 appearance-none"
          >
            <option value="" className="bg-[#0d1117]">All Providers</option>
            {['aws', 'azure', 'gcp', 'okta', 'manual', 'qualys', 'splunk'].map(p => (
              <option key={p} value={p} className="bg-[#0d1117] capitalize">{p.toUpperCase()}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="bg-[#0d1117] border border-white/8 rounded-2xl overflow-hidden">
        <div className="overflow-auto">
          <table className="w-full text-xs">
            <thead className="border-b border-white/8">
              <tr>
                {['Control / Check', 'Provider & Resource', 'Status', 'Collected At', 'Integrity Hash'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-slate-500 font-semibold uppercase tracking-wider whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {isLoading ? (
                Array.from({ length: 8 }).map((_, i) => (
                  <tr key={i}>
                    {[...Array(5)].map((_, j) => (
                      <td key={j} className="px-4 py-3">
                        <div className="h-3 bg-white/5 rounded animate-pulse" style={{ width: `${60 + Math.random() * 30}%` }} />
                      </td>
                    ))}
                  </tr>
                ))
              ) : items.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-slate-500">
                    <Database className="w-8 h-8 mx-auto mb-2 opacity-30" />
                    No evidence records found
                  </td>
                </tr>
              ) : items.map(item => (
                <tr key={item.id} className="hover:bg-white/[0.02] transition-colors">
                  <td className="px-4 py-3">
                    <div className="font-bold text-blue-400">{item.control_id}</div>
                    <div className="text-slate-600 mt-0.5">{item.check_id}</div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5 mb-0.5">
                      <span className={providerBadge(item.provider)}>{item.provider}</span>
                      <span className="text-slate-300 font-medium">{item.service}</span>
                    </div>
                    <div className="text-slate-600">{item.region} · {item.resource_type}</div>
                  </td>
                  <td className="px-4 py-3">
                    {item.status === 'collected' ? (
                      <span className="flex items-center gap-1 text-emerald-400 font-semibold">
                        <CheckCircle className="w-3.5 h-3.5" /> Collected
                      </span>
                    ) : item.status === 'failed' ? (
                      <span className="flex items-center gap-1 text-red-400 font-semibold">
                        <XCircle className="w-3.5 h-3.5" /> Failed
                      </span>
                    ) : (
                      <span className="text-slate-500 capitalize">{item.status}</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-slate-400 whitespace-nowrap">
                    {new Date(item.collected_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-slate-600 font-mono text-[10px]">
                      {item.sha256_hash ? `${item.sha256_hash.slice(0, 16)}…` : 'aaaaaaaaaaaa…'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="border-t border-white/8 px-4 py-3 flex items-center justify-between">
            <p className="text-xs text-slate-500">{total.toLocaleString()} records</p>
            <div className="flex items-center gap-2">
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                className="px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-xs text-slate-400 hover:bg-white/10 disabled:opacity-30 transition-colors">
                Previous
              </button>
              <span className="text-xs text-slate-400">Page {page} of {totalPages}</span>
              <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                className="px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-xs text-slate-400 hover:bg-white/10 disabled:opacity-30 transition-colors">
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
