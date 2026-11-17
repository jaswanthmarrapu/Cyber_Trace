import React, { useState } from 'react';
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

export default function App() {
  const [currentTab, setCurrentTab] = useState('dashboard');
  const { cases, activeCase, setActiveCase, refreshCases } = useCases();

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
