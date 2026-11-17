import React from 'react';
import Navbar from '../components/Navbar';
import Sidebar from '../components/Sidebar';

export default function MainLayout({ currentTab, onSelectTab, activeCase, cases, onSelectCase, children }) {
  return (
    <div className="min-h-screen bg-[#080c14] text-slate-100 flex flex-col font-sans">
      <Navbar activeCase={activeCase} cases={cases} onSelectCase={onSelectCase} />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar currentTab={currentTab} onSelectTab={onSelectTab} />
        <main className="flex-1 overflow-y-auto p-6 bg-[#080c14]">
          {children}
        </main>
      </div>
    </div>
  );
}

