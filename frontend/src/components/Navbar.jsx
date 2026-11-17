import React, { useState, useEffect } from 'react';
import {
  Shield,
  Activity,
  User,
  Bell,
  Radio,
  Clock,
  ChevronDown,
  AlertOctagon,
  CheckCircle2,
  X,
  LogOut,
  Key,
  ShieldCheck,
  Eye
} from 'lucide-react';
import StatusBadge from './StatusBadge';
import { useAuth } from '../context/AuthContext';

export default function Navbar({ activeCase, cases, onSelectCase }) {
  const { user, role, logout } = useAuth();
  const [currentTime, setCurrentTime] = useState('');
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(now.toUTCString().slice(17, 25) + ' UTC');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const notifications = [
    { id: 1, title: 'Critical Alert: Web Shell Identified', desc: 'High-entropy script /uploads/cache.php flagged on staging', time: '12m ago', severity: 'Critical' },
    { id: 2, title: 'SQL Injection Detected', desc: 'Blind SQLmap attempt against /products.php (203.0.113.45)', time: '28m ago', severity: 'High' },
    { id: 3, title: 'Integrity Check Passed', desc: 'SHA-256 for access_staging_combined.log verified against baseline', time: '1h ago', severity: 'Low' }
  ];

  return (
    <header className="h-16 bg-[#070b14] border-b border-slate-800/80 px-6 flex items-center justify-between sticky top-0 z-40 backdrop-blur-md">
      {/* Logo & Platform Title */}
      <div className="flex items-center gap-6">
        <div className="flex items-center gap-2.5 text-cyan-400 font-mono font-bold text-lg tracking-wider">
          <div className="p-1.5 rounded-lg bg-cyan-950/80 border border-cyan-500/40 shadow-cyan-glow">
            <Shield className="w-5 h-5 text-cyan-400" />
          </div>
          <span>CYBER<span className="text-blue-500">TRACE</span></span>
          <span className="hidden sm:inline-block text-[9px] uppercase tracking-widest px-1.5 py-0.5 rounded bg-cyan-950/90 text-cyan-300 border border-cyan-700/60 ml-1">
            DFIR Platform
          </span>
        </div>

        {/* Active Case Selector */}
        <div className="hidden md:flex items-center gap-2 pl-5 border-l border-slate-800">
          <span className="text-[11px] text-slate-500 font-mono uppercase tracking-wider">Active Case:</span>
          <select
            value={activeCase?.id || ''}
            onChange={(e) => {
              const selected = cases.find((c) => c.id === e.target.value);
              if (selected) onSelectCase(selected);
            }}
            className="bg-slate-900 border border-slate-700/80 rounded-lg text-xs text-cyan-300 px-3 py-1.5 font-mono focus:outline-none focus:border-cyan-500 max-w-xs truncate cursor-pointer"
          >
            {cases.map((c) => (
              <option key={c.id} value={c.id}>
                [{c.case_number}] {c.title}
              </option>
            ))}
          </select>
          {activeCase && <StatusBadge status={activeCase.severity} />}
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-4">
        {/* UTC Clock */}
        <div className="hidden lg:flex items-center gap-1.5 px-3 py-1 rounded-lg bg-slate-900/80 border border-slate-800 text-xs font-mono text-slate-400">
          <Clock className="w-3.5 h-3.5 text-cyan-400" />
          <span>{currentTime || '00:00:00 UTC'}</span>
        </div>

        {/* Live Integrity Pulse */}
        <div className="hidden sm:flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/30 border border-emerald-500/30 text-emerald-400 text-xs font-mono">
          <Radio className="w-3 h-3 text-emerald-400 animate-pulse" />
          <span>SHA-256 Validated</span>
        </div>

        {/* Notification Bell with Dropdown */}
        <div className="relative">
          <button
            onClick={() => setNotificationsOpen(!notificationsOpen)}
            className="relative p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white transition-colors"
          >
            <Bell className="w-4 h-4" />
            <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-red-500 animate-ping"></span>
            <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-red-500"></span>
          </button>

          {notificationsOpen && (
            <div className="absolute right-0 mt-2 w-80 sm:w-96 bg-[#0b1329] border border-slate-800 rounded-xl shadow-2xl p-4 text-xs z-50 animate-fadeIn">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="font-semibold text-white font-mono flex items-center gap-1.5">
                  <AlertOctagon className="w-3.5 h-3.5 text-cyan-400" />
                  Live Security Alerts
                </span>
                <button onClick={() => setNotificationsOpen(false)} className="text-slate-500 hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div className="divide-y divide-slate-800/80 mt-2 space-y-2">
                {notifications.map((n) => (
                  <div key={n.id} className="pt-2">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-slate-200">{n.title}</span>
                      <StatusBadge status={n.severity} />
                    </div>
                    <p className="text-slate-400 mt-1 leading-snug">{n.desc}</p>
                    <span className="text-[10px] text-slate-500 font-mono mt-1 block">{n.time}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* User Identity Profile Badge & Dropdown */}
        <div className="relative">
          <button
            type="button"
            onClick={() => setProfileOpen(!profileOpen)}
            className="flex items-center gap-2.5 pl-2 py-1 border-l border-slate-800 hover:opacity-90 transition-opacity text-left cursor-pointer"
          >
            <div className={`w-8 h-8 rounded-xl p-[1px] ${
              role === 'Admin'
                ? 'bg-gradient-to-tr from-purple-500 to-indigo-600'
                : role === 'Viewer'
                ? 'bg-gradient-to-tr from-amber-500 to-yellow-600'
                : 'bg-gradient-to-tr from-cyan-500 to-blue-600'
            }`}>
              <div className="w-full h-full bg-slate-950 rounded-xl flex items-center justify-center text-xs font-bold font-mono text-cyan-300 uppercase">
                {user?.username ? user.username.slice(0, 2) : 'FE'}
              </div>
            </div>
            <div className="hidden xl:block text-left text-xs">
              <p className="font-semibold text-slate-200 truncate max-w-[120px]">
                {user?.full_name || user?.username || 'Forensic Examiner'}
              </p>
              <div className="flex items-center gap-1.5 mt-0.5">
                <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded border ${
                  role === 'Admin'
                    ? 'border-purple-500/40 text-purple-300 bg-purple-950/60'
                    : role === 'Viewer'
                    ? 'border-amber-500/40 text-amber-300 bg-amber-950/60'
                    : 'border-cyan-500/40 text-cyan-300 bg-cyan-950/60'
                }`}>
                  {role || 'Investigator'}
                </span>
              </div>
            </div>
            <ChevronDown className="w-3.5 h-3.5 text-slate-500 hidden xl:block" />
          </button>

          {/* User Profile Menu Dropdown */}
          {profileOpen && (
            <div className="absolute right-0 mt-2 w-72 bg-[#0b1329] border border-slate-800 rounded-xl shadow-2xl p-4 text-xs z-50 animate-fadeIn">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-500/40 flex items-center justify-center font-mono text-cyan-300 font-bold uppercase">
                    {user?.username ? user.username.slice(0, 2) : 'FE'}
                  </div>
                  <div>
                    <p className="font-semibold text-white truncate max-w-[170px]">
                      {user?.full_name || 'Forensic Examiner'}
                    </p>
                    <p className="text-[11px] text-slate-400 font-mono truncate max-w-[170px]">
                      @{user?.username || 'examiner'}
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setProfileOpen(false)}
                  className="text-slate-500 hover:text-white"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="py-2.5 space-y-1.5 text-slate-300 font-mono text-[11px]">
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">Official Email:</span>
                  <span className="text-slate-300 truncate max-w-[140px]">{user?.email || 'examiner@cybertrace.local'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-500">Security Clearance:</span>
                  <span className="text-cyan-400 font-semibold">{role || 'Investigator'}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-500">Authentication Mode:</span>
                  <span className="text-emerald-400">JWT Token Active</span>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800 mt-2">
                <button
                  type="button"
                  onClick={() => {
                    setProfileOpen(false);
                    logout();
                  }}
                  className="w-full py-2 px-3 rounded-lg bg-red-950/40 hover:bg-red-900/60 border border-red-500/40 text-red-300 font-mono text-xs flex items-center justify-center gap-2 transition-colors cursor-pointer"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  Terminate Session (Sign Out)
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
