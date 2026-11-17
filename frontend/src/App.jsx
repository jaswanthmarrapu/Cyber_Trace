import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import AuthPage from './pages/AuthPage';
import { useCases } from './hooks/useCases';
import MainLayout from './layouts/MainLayout';
import Dashboard from './pages/Dashboard';
import AISummary from './pages/AISummary';
import EvidenceVault from './pages/EvidenceVault';
import IntegrityVerification from './pages/IntegrityVerification';
import LogAnalysis from './pages/LogAnalysis';
import IPInvestigation from './pages/IPInvestigation';
import FileForensics from './pages/FileForensics';
import ThreatDetection from './pages/ThreatDetection';
import AttackTimeline from './pages/AttackTimeline';
import Cases from './pages/Cases';
import Reports from './pages/Reports';
import Settings from './pages/Settings';

function AppContent() {
  const { isAuthenticated, isLoading } = useAuth();
  const [currentTab, setCurrentTab] = useState('dashboard');
  const { cases, activeCase, setActiveCase, refreshCases } = useCases();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#060a14] flex flex-col items-center justify-center text-cyan-400 font-mono">
        <div className="w-10 h-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mb-4" />
        <p className="text-xs tracking-widest uppercase">Validating Cryptographic Session...</p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <AuthPage onLoginSuccess={() => setCurrentTab('dashboard')} />;
  }

  const renderContent = () => {
    switch (currentTab) {
      case 'dashboard':
        return <Dashboard activeCase={activeCase} onNavigate={setCurrentTab} />;
      case 'ai':
        return <AISummary activeCase={activeCase} />;
      case 'evidence':
        return <EvidenceVault activeCase={activeCase} onNavigate={setCurrentTab} />;
      case 'integrity':
        return <IntegrityVerification />;
      case 'logs':
        return <LogAnalysis activeCase={activeCase} />;
      case 'ip':
        return <IPInvestigation activeCase={activeCase} />;
      case 'forensics':
        return <FileForensics activeCase={activeCase} />;
      case 'threats':
        return <ThreatDetection activeCase={activeCase} />;
      case 'timeline':
        return <AttackTimeline activeCase={activeCase} />;
      case 'cases':
        return <Cases activeCase={activeCase} onSelectCase={setActiveCase} onNavigate={setCurrentTab} />;
      case 'reports':
        return <Reports activeCase={activeCase} />;
      case 'settings':
        return <Settings />;
      default:
        return <Dashboard activeCase={activeCase} onNavigate={setCurrentTab} />;
    }
  };

  return (
    <MainLayout
      currentTab={currentTab}
      onSelectTab={setCurrentTab}
      activeCase={activeCase}
      cases={cases}
      onSelectCase={setActiveCase}
    >
      {renderContent()}
    </MainLayout>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
