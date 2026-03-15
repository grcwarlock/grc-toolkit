import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Settings, Building, Bell, Key, Shield, Users,
  Plus, Trash2, Copy, Check, Eye, EyeOff,
  Save, Activity, Loader2
} from 'lucide-react';
import api from '../lib/api';

const TABS = [
  { id: 'org',           label: 'Organization',  icon: Building },
  { id: 'notifications', label: 'Notifications', icon: Bell },
  { id: 'api-keys',      label: 'API Keys',       icon: Key },
  { id: 'audit',         label: 'Audit Log',      icon: Activity },
] as const;
type TabId = typeof TABS[number]['id'];

function Toggle({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      onClick={() => onChange(!value)}
      className={`relative w-11 h-6 rounded-full transition-colors duration-200 flex-shrink-0 focus:outline-none ${value ? 'bg-blue-600' : 'bg-white/10'}`}
      role="switch"
      aria-checked={value}
    >
      <span className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform duration-200 ${value ? 'translate-x-5' : ''}`} />
    </button>
  );
}

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<TabId>('org');
  const [copied, setCopied] = useState('');
  const [showKey, setShowKey] = useState<Record<string, boolean>>({});
  const queryClient = useQueryClient();

  const { data: orgSettings, isLoading: orgLoading } = useQuery({
    queryKey: ['settings', 'org'],
    queryFn: async () => (await api.get('/settings/org')).data,
  });

  const { data: notifSettings } = useQuery({
    queryKey: ['settings', 'notifications'],
    queryFn: async () => (await api.get('/settings/notifications')).data,
  });

  const { data: apiKeys } = useQuery({
    queryKey: ['settings', 'api-keys'],
    queryFn: async () => (await api.get('/settings/api-keys')).data,
  });

  const { data: auditLog } = useQuery({
    queryKey: ['settings', 'audit-log'],
    queryFn: async () => (await api.get('/settings/audit-log')).data,
  });

  const updateOrgMutation = useMutation({
    mutationFn: async (d: Record<string, unknown>) => (await api.put('/settings/org', d)).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['settings', 'org'] }),
  });

  const updateNotifMutation = useMutation({
    mutationFn: async (d: Record<string, unknown>) => (await api.put('/settings/notifications', d)).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['settings', 'notifications'] }),
  });

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(''), 2000);
  };

  const [orgForm, setOrgForm] = useState<Record<string, any>>({});

  return (
    <div className="space-y-5 page-enter text-white">
      {/* Header */}
      <div className="bg-[#0d1117] border border-white/8 rounded-2xl p-5">
        <h2 className="text-lg font-bold text-white flex items-center gap-2">
          <Settings className="w-5 h-5 text-slate-400" /> Settings
        </h2>
        <p className="text-slate-400 text-sm mt-0.5">Organization configuration and platform preferences</p>
      </div>

      <div className="flex flex-col md:flex-row gap-5">
        {/* Sidebar nav */}
        <div className="md:w-52 bg-[#0d1117] border border-white/8 rounded-2xl p-2 h-fit">
          {TABS.map(tab => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-sm font-medium transition-all ${
                  activeTab === tab.id ? 'bg-blue-500/15 text-blue-400 border border-blue-500/20' : 'text-slate-400 hover:text-white hover:bg-white/5'
                }`}
              >
                <Icon className="w-4 h-4" /> {tab.label}
              </button>
            );
          })}
        </div>

        {/* Tab content */}
        <div className="flex-1 bg-[#0d1117] border border-white/8 rounded-2xl p-6">

          {/* Organization */}
          {activeTab === 'org' && (
            <div className="space-y-5">
              <h3 className="text-base font-bold text-white">Organization Settings</h3>
              {orgLoading ? (
                <div className="flex items-center gap-2 text-slate-500 py-8">
                  <Loader2 className="w-5 h-5 animate-spin" /> Loading…
                </div>
              ) : (
                <>
                  {[
                    { key: 'company_name',    label: 'Company Name',    type: 'text', placeholder: 'Acme Corporation' },
                    { key: 'industry',        label: 'Industry',        type: 'text', placeholder: 'Technology' },
                    { key: 'contact_email',   label: 'Security Contact Email', type: 'email', placeholder: 'security@example.com' },
                    { key: 'compliance_scope',label: 'Compliance Scope',type: 'text', placeholder: 'Cloud infrastructure, SaaS products' },
                  ].map(field => (
                    <div key={field.key}>
                      <label className="block text-sm font-semibold text-slate-300 mb-1.5">{field.label}</label>
                      <input
                        type={field.type}
                        defaultValue={orgSettings?.[field.key] ?? ''}
                        onChange={e => setOrgForm(p => ({ ...p, [field.key]: e.target.value }))}
                        placeholder={field.placeholder}
                        className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20"
                      />
                    </div>
                  ))}
                  <button
                    onClick={() => updateOrgMutation.mutate({ ...orgSettings, ...orgForm })}
                    disabled={updateOrgMutation.isPending}
                    className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold transition-all shadow-lg shadow-blue-500/20 disabled:opacity-60"
                  >
                    {updateOrgMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                    Save Changes
                  </button>
                  {updateOrgMutation.isSuccess && (
                    <div className="flex items-center gap-2 text-emerald-400 text-sm">
                      <Check className="w-4 h-4" /> Saved successfully
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          {/* Notifications */}
          {activeTab === 'notifications' && (
            <div className="space-y-5">
              <h3 className="text-base font-bold text-white">Notification Preferences</h3>
              <div className="space-y-3">
                {[
                  { key: 'email_on_assessment_complete',  label: 'Email on assessment completion',  desc: 'Receive a summary email when a compliance run finishes' },
                  { key: 'email_on_critical_finding',     label: 'Email on critical findings',      desc: 'Immediate alert when a critical-severity control fails' },
                  { key: 'email_on_policy_violation',     label: 'Email on policy violations',      desc: 'Notify when a policy violation is detected' },
                  { key: 'slack_on_assessment_complete',  label: 'Slack on assessment completion',  desc: 'Post results to your configured Slack channel' },
                  { key: 'slack_on_critical_finding',     label: 'Slack on critical findings',      desc: 'Real-time Slack alert for critical-severity issues' },
                  { key: 'weekly_summary',                label: 'Weekly compliance digest',        desc: 'Monday summary email with compliance trend data' },
                ].map(n => (
                  <div key={n.key} className="flex items-center justify-between py-3 px-4 rounded-xl bg-white/[0.02] border border-white/5">
                    <div>
                      <p className="text-sm font-semibold text-white">{n.label}</p>
                      <p className="text-xs text-slate-500 mt-0.5">{n.desc}</p>
                    </div>
                    <Toggle
                      value={notifSettings?.[n.key] ?? false}
                      onChange={v => updateNotifMutation.mutate({ ...notifSettings, [n.key]: v })}
                    />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* API Keys */}
          {activeTab === 'api-keys' && (
            <div className="space-y-5">
              <div className="flex items-center justify-between">
                <h3 className="text-base font-bold text-white">API Keys</h3>
                <button className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-blue-600/20 border border-blue-500/30 text-blue-400 hover:bg-blue-600/30 text-xs font-bold transition-colors">
                  <Plus className="w-3.5 h-3.5" /> Generate Key
                </button>
              </div>
              <div className="space-y-3">
                {(apiKeys ?? []).length === 0 ? (
                  <div className="py-10 text-center text-slate-500">
                    <Key className="w-8 h-8 mx-auto mb-2 opacity-30" />
                    <p className="text-sm">No API keys generated</p>
                  </div>
                ) : (apiKeys ?? []).map((key: any) => (
                  <div key={key.id} className="bg-white/[0.02] border border-white/8 rounded-xl p-4">
                    <div className="flex items-center justify-between mb-2">
                      <div>
                        <p className="text-sm font-bold text-white">{key.name}</p>
                        <p className="text-[11px] text-slate-500">Created {new Date(key.created_at).toLocaleDateString()}</p>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={() => copyToClipboard(key.key, key.id)}
                          className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white transition-colors"
                        >
                          {copied === key.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                        <button
                          onClick={() => setShowKey(p => ({ ...p, [key.id]: !p[key.id] }))}
                          className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white transition-colors"
                        >
                          {showKey[key.id] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                        </button>
                        <button className="p-1.5 rounded-lg bg-white/5 hover:bg-red-500/10 hover:border hover:border-red-500/20 text-slate-400 hover:text-red-400 transition-colors">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                    <div className="font-mono text-xs text-slate-500 bg-black/20 rounded-lg px-3 py-2">
                      {showKey[key.id] ? key.key : `${key.key?.slice(0, 8) ?? 'grc_'}${'•'.repeat(32)}`}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Audit Log */}
          {activeTab === 'audit' && (
            <div className="space-y-4">
              <h3 className="text-base font-bold text-white">Audit Log</h3>
              <div className="divide-y divide-white/5">
                {(auditLog ?? []).length === 0 ? (
                  <p className="py-10 text-center text-sm text-slate-500">No audit events recorded</p>
                ) : (auditLog ?? []).map((event: any) => (
                  <div key={event.id} className="py-3 flex items-start gap-3">
                    <div className="w-7 h-7 rounded-full bg-blue-500/10 border border-blue-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                      <Activity className="w-3.5 h-3.5 text-blue-400" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-white font-medium">{event.action}</p>
                      <p className="text-xs text-slate-500 mt-0.5">{event.actor} · {new Date(event.timestamp).toLocaleString()}</p>
                    </div>
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border flex-shrink-0 ${event.outcome === 'success' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' : 'bg-red-500/10 border-red-500/20 text-red-400'}`}>
                      {event.outcome}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
