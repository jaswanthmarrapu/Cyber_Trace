import React from 'react';
import {
  LayoutDashboard,
  FolderGit2,
  HardDrive,
  FileCode,
  Globe,
  Binary,
  AlertTriangle,
  Clock,
  FileText,
  Settings as SettingsIcon,
  ShieldCheck,
  ShieldAlert,
  ChevronRight,
  Sparkles,
  Lock
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function Sidebar({ currentTab, onSelectTab }) {
  const { role, isViewer } = useAuth();
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'ai', label: 'AI Assistant', icon: Sparkles, badge: 'AI' },
    { id: 'evidence', label: 'Evidence Collection', icon: HardDrive, badge: 'Vault' },
    { id: 'logs', label: 'Log Analysis', icon: FileCode },
    { id: 'ip', label: 'IP Investigation', icon: Globe },
    { id: 'forensics', label: 'File Forensics', icon: Binary },
    { id: 'threats', label: 'Threat Detection', icon: AlertTriangle, badge: 'MITRE' },
    { id: 'timeline', label: 'Attack Timeline', icon: Clock },
    { id: 'cases', label: 'Investigation Cases', icon: FolderGit2 },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'settings', label: 'Settings', icon: SettingsIcon },
  ];

  return (
    <aside className="w-64 bg-[#070b14] border-r border-slate-800/80 flex flex-col justify-between py-4 select-none shrink-0 shadow-lg">
      <div className="space-y-1.5 px-3">
        <div className="px-3 pb-2 text-[10px] font-mono uppercase tracking-widest text-slate-500 font-bold flex items-center justify-between">
          <span>Forensic Navigation</span>
          <span className="text-cyan-500 font-bold text-[9px] px-1.5 py-0.2 rounded bg-cyan-950 border border-cyan-800">
            SEC-T3
          </span>
        </div>

        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs font-medium transition-all duration-200 group ${
                isActive
                  ? 'bg-gradient-to-r from-cyan-500/15 to-blue-500/10 text-cyan-300 border border-cyan-500/40 shadow-cyan-glow font-semibold'
                  : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50 border border-transparent'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 transition-colors ${isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-cyan-400'}`} />
                <span>{item.label}</span>
              </div>
              <div className="flex items-center gap-1.5">
                {item.badge && (
                  <span className={`text-[9px] px-1.5 py-0.5 rounded font-mono font-bold ${
                    item.badge === 'MITRE'
                      ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                      : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                  }`}>
                    {item.badge}
                  </span>
                )}
                {isActive && <ChevronRight className="w-3.5 h-3.5 text-cyan-400" />}
              </div>
            </button>
          );
        })}
      </div>

      {/* ISO & RBAC Session Block */}
      <div className="px-4 pt-4 border-t border-slate-800/80 space-y-2">
        {/* Role Access Indicator */}
        <div className={`p-2.5 rounded-xl border text-[11px] font-mono ${
          role === 'Admin'
            ? 'bg-purple-950/40 border-purple-500/40 text-purple-300'
            : isViewer
            ? 'bg-amber-950/40 border-amber-500/40 text-amber-300'
            : 'bg-cyan-950/40 border-cyan-500/40 text-cyan-300'
        }`}>
          <div className="flex items-center justify-between font-bold">
            <span>ROLE: {role.toUpperCase()}</span>
            {isViewer ? <Lock className="w-3 h-3 text-amber-400" /> : <ShieldCheck className="w-3 h-3 text-cyan-400" />}
          </div>
          <p className="text-[10px] text-slate-400 mt-1 leading-tight">
            {isViewer
              ? 'Read-Only: Evidence upload & case mutations disabled'
              : role === 'Admin'
              ? 'Full Administrator Clearance'
              : 'DFIR Examiner Clearance'}
          </p>
        </div>

        <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-[11px] font-mono text-slate-400 space-y-1">
          <div className="flex items-center gap-1.5 text-cyan-400 font-semibold">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>ISO/IEC 27037 Standard</span>
          </div>
          <p className="text-[10px] text-slate-500 leading-snug">
            Bit-level SHA-256 integrity baseline with immutable chain of custody.
          </p>
        </div>
      </div>
    </aside>
  );
}
