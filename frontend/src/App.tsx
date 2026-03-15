import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './contexts/AuthContext';
import Layout from './components/Layout';
import LandingPage from './pages/LandingPage';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import DashboardPage from './pages/DashboardPage';
import FrameworksPage from './pages/FrameworksPage';
import AssessmentsPage from './pages/AssessmentsPage';
import EvidencePage from './pages/EvidencePage';
import RiskPage from './pages/RiskPage';
import VendorsPage from './pages/VendorsPage';
import IntegrationsPage from './pages/IntegrationsPage';
import POAMPage from './pages/POAMPage';
import DataSilosPage from './pages/DataSilosPage';
import TrustHubPage from './pages/TrustHubPage';
import TrustPortalPage from './pages/TrustPortalPage';
import SettingsPage from './pages/SettingsPage';
import ToolConfigPage from './pages/ToolConfigPage';
import MonitoringPage from './pages/MonitoringPage';
import QuestionnairesPage from './pages/QuestionnairesPage';
import TasksPage from './pages/TasksPage';
import PersonnelPage from './pages/PersonnelPage';
import AuditPortalPage from './pages/AuditPortalPage';
import SSPPage from './pages/SSPPage';
import RiskGraphPage from './pages/RiskGraphPage';
import AIReasoningPage from './pages/AIReasoningPage';
import FeaturePage from './pages/FeaturePage';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading, login } = useAuth();
  const [autoLogging, setAutoLogging] = React.useState(false);
  const [autoFailed, setAutoFailed] = React.useState(false);

  React.useEffect(() => {
    if (!isLoading && !isAuthenticated && !autoLogging && !autoFailed) {
      setAutoLogging(true);
      login('admin@grc-demo.com', 'demo1234')
        .catch(() => setAutoFailed(true))
        .finally(() => setAutoLogging(false));
    }
  }, [isLoading, isAuthenticated, autoLogging, autoFailed, login]);

  if (isLoading || autoLogging) {
    return (
      <div className="min-h-screen bg-[#030711] flex flex-col items-center justify-center gap-4">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-violet-600 flex items-center justify-center shadow-lg shadow-blue-500/30 animate-pulse">
          <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
        </div>
        <p className="text-slate-400 text-sm">Loading demo…</p>
      </div>
    );
  }

  if (autoFailed && !isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (!isAuthenticated) return null;

  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/trust" element={<TrustPortalPage />} />
      <Route path="/features/:slug" element={<FeaturePage />} />
      
      <Route element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/frameworks" element={<FrameworksPage />} />
        <Route path="/assessments" element={<AssessmentsPage />} />
        <Route path="/evidence" element={<EvidencePage />} />
        <Route path="/risk" element={<RiskPage />} />
        <Route path="/vendors" element={<VendorsPage />} />
        <Route path="/integrations" element={<IntegrationsPage />} />
        <Route path="/poam" element={<POAMPage />} />
        <Route path="/data-silos" element={<DataSilosPage />} />
        <Route path="/trust-hub" element={<TrustHubPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/tool-config" element={<ToolConfigPage />} />
        <Route path="/monitoring" element={<MonitoringPage />} />
        <Route path="/questionnaires" element={<QuestionnairesPage />} />
        <Route path="/tasks" element={<TasksPage />} />
        <Route path="/personnel" element={<PersonnelPage />} />
        <Route path="/audit-portal" element={<AuditPortalPage />} />
        <Route path="/ssp" element={<SSPPage />} />
        <Route path="/risk-graph" element={<RiskGraphPage />} />
        <Route path="/ai-reasoning" element={<AIReasoningPage />} />
      </Route>
    </Routes>
  );
}
