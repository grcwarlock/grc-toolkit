import { useState } from 'react';
import { NavLink, Outlet, useLocation, Link } from 'react-router-dom';
import {
  Shield, LayoutDashboard, Layers, CheckSquare,
  Database, AlertTriangle, Users, Plug, FileText,
  LogOut, Menu, X, User, Settings, HardDrive,
  Globe, Bell, ChevronDown, ChevronRight, Zap
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

const NAV_SECTIONS = [
  {
    label: 'Compliance',
    items: [
      { name: 'Dashboard',    path: '/dashboard',   icon: LayoutDashboard },
      { name: 'Frameworks',   path: '/frameworks',  icon: Layers },
      { name: 'Assessments',  path: '/assessments', icon: CheckSquare },
    ],
  },
  {
    label: 'Security',
    items: [
      { name: 'Risk Analysis', path: '/risk',        icon: AlertTriangle },
      { name: 'Evidence',      path: '/evidence',    icon: Database },
      { name: 'Data Silos',    path: '/data-silos',  icon: HardDrive },
    ],
  },
  {
    label: 'Third Parties',
    items: [
      { name: 'Vendors',       path: '/vendors',      icon: Users },
      { name: 'Integrations',  path: '/integrations', icon: Plug },
      { name: 'Tool Config',   path: '/tool-config',  icon: Zap },
    ],
  },
  {
    label: 'Reporting',
    items: [
      { name: 'POAM & Reports', path: '/poam',      icon: FileText },
      { name: 'Trust Hub',      path: '/trust-hub', icon: Globe },
    ],
  },
];

export default function Layout() {
  const { user, logout } = useAuth();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [collapsedSections, setCollapsedSections] = useState<Set<string>>(new Set());
  const location = useLocation();

  const allItems = NAV_SECTIONS.flatMap(s => s.items);
  const pageTitle = allItems.find(item => item.path === location.pathname)?.name
    || (location.pathname === '/settings' ? 'Settings' : 'GRC Warlock');

  const toggleSection = (label: string) => {
    setCollapsedSections(prev => {
      const next = new Set(prev);
      if (next.has(label)) next.delete(label); else next.add(label);
      return next;
    });
  };

  const SidebarContent = () => (
    <>
      <div className="flex items-center gap-3 px-5 py-4 border-b border-white/8">
        <Link to="/" className="flex items-center gap-3 group">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-violet-600 flex items-center justify-center flex-shrink-0 shadow-lg shadow-blue-500/30">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <div>
            <div className="font-bold text-sm text-white leading-tight">
              GRC <span className="bg-gradient-to-r from-blue-400 to-violet-400 bg-clip-text text-transparent">Warlock</span>
            </div>
            <div className="text-[10px] text-slate-500 uppercase tracking-widest">Enterprise</div>
          </div>
        </Link>
      </div>

      <nav className="flex-1 py-3 overflow-y-auto scrollbar-thin">
        {NAV_SECTIONS.map((section) => {
          const isCollapsed = collapsedSections.has(section.label);
          return (
            <div key={section.label} className="mb-1">
              <button
                onClick={() => toggleSection(section.label)}
                className="w-full flex items-center justify-between px-4 py-1.5 text-[10px] font-semibold uppercase tracking-widest text-slate-600 hover:text-slate-400 transition-colors"
              >
                {section.label}
                {isCollapsed ? <ChevronRight className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              </button>
              {!isCollapsed && (
                <ul>
                  {section.items.map((item) => {
                    const Icon = item.icon;
                    return (
                      <li key={item.path}>
                        <NavLink
                          to={item.path}
                          onClick={() => setIsMobileMenuOpen(false)}
                          className={({ isActive }) => `
                            flex items-center gap-2.5 px-4 py-2 text-sm transition-all mx-2 rounded-lg
                            ${isActive
                              ? 'bg-gradient-to-r from-blue-600/20 to-violet-600/10 text-blue-400 border border-blue-500/20 font-medium'
                              : 'text-slate-400 hover:bg-white/5 hover:text-slate-200'
                            }
                          `}
                        >
                          <Icon className="w-4 h-4 flex-shrink-0" />
                          <span>{item.name}</span>
                        </NavLink>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          );
        })}
      </nav>

      <div className="border-t border-white/8 p-3 space-y-0.5">
        <NavLink
          to="/settings"
          onClick={() => setIsMobileMenuOpen(false)}
          className={({ isActive }) => `
            flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-all
            ${isActive
              ? 'bg-gradient-to-r from-blue-600/20 to-violet-600/10 text-blue-400 border border-blue-500/20 font-medium'
              : 'text-slate-400 hover:bg-white/5 hover:text-slate-200'
            }
          `}
        >
          <Settings className="w-4 h-4" />
          <span>Settings</span>
        </NavLink>

        <div className="flex items-center gap-2.5 px-3 py-2 rounded-lg mt-1">
          <div className="w-7 h-7 rounded-full bg-gradient-to-br from-blue-600/30 to-violet-600/20 border border-blue-500/30 flex items-center justify-center flex-shrink-0">
            <User className="w-3.5 h-3.5 text-blue-400" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-xs font-medium text-slate-200 truncate">{user?.full_name}</div>
            <div className="text-[10px] text-slate-500 truncate capitalize">{user?.role}</div>
          </div>
          <button
            onClick={logout}
            title="Sign out"
            className="p-1.5 text-slate-600 hover:text-red-400 hover:bg-red-400/10 rounded transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </>
  );

  return (
    <div className="min-h-screen bg-[#070d19] flex flex-col md:flex-row font-sans">
      {/* Mobile top bar */}
      <div className="md:hidden bg-[#0d1117] text-white flex items-center justify-between px-4 py-3 sticky top-0 z-50 border-b border-white/8">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-md bg-gradient-to-br from-blue-500 to-violet-600 flex items-center justify-center">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <span className="font-bold text-sm">
            GRC <span className="bg-gradient-to-r from-blue-400 to-violet-400 bg-clip-text text-transparent">Warlock</span>
          </span>
        </div>
        <div className="flex items-center gap-1">
          <button className="p-2 text-slate-400 hover:text-white">
            <Bell className="w-5 h-5" />
          </button>
          <button onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)} className="p-2 text-slate-400 hover:text-white">
            {isMobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {/* Sidebar */}
      <div className={`
        fixed inset-y-0 left-0 z-40 w-56 bg-[#0d1117] flex flex-col transform transition-transform duration-200 ease-in-out border-r border-white/5
        md:translate-x-0 md:static md:flex
        ${isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full'}
      `}>
        <SidebarContent />
      </div>

      {isMobileMenuOpen && (
        <div className="fixed inset-0 bg-black/60 z-30 md:hidden" onClick={() => setIsMobileMenuOpen(false)} />
      )}

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Header */}
        <header className="hidden md:flex items-center justify-between px-6 py-3 bg-[#0d1117]/80 backdrop-blur-sm border-b border-white/8 sticky top-0 z-20">
          <h1 className="text-base font-semibold text-white">{pageTitle}</h1>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 text-xs text-emerald-400 font-medium bg-emerald-500/10 px-2.5 py-1 rounded-full border border-emerald-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
              Operational
            </div>
            <button className="relative p-2 text-slate-400 hover:text-white hover:bg-white/5 rounded-lg transition-colors">
              <Bell className="w-4 h-4" />
              <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 bg-red-500 rounded-full"></span>
            </button>
            <div className="flex items-center gap-2 pl-3 border-l border-white/8">
              <div className="w-7 h-7 rounded-full bg-gradient-to-br from-blue-600/30 to-violet-600/20 border border-blue-500/30 flex items-center justify-center">
                <User className="w-3.5 h-3.5 text-blue-400" />
              </div>
              <div className="text-xs">
                <div className="font-medium text-slate-200 leading-tight">{user?.full_name}</div>
                <div className="text-slate-500 capitalize">{user?.role}</div>
              </div>
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
