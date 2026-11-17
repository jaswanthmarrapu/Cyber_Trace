import React from 'react';

export default function StatusBadge({ status, type = 'status' }) {
  const getColors = () => {
    const val = (status || '').toLowerCase();
    if (val === 'critical' || val === 'compromised') {
      return 'bg-red-500/10 text-red-400 border-red-500/30';
    }
    if (val === 'high' || val === 'investigating') {
      return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    }
    if (val === 'medium' || val === 'open') {
      return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
    }
    if (val === 'low' || val === 'verified' || val === 'closed') {
      return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    }
    return 'bg-slate-500/10 text-slate-300 border-slate-700';
  };

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getColors()}`}>
      <span className="w-1.5 h-1.5 mr-1.5 rounded-full bg-current opacity-75"></span>
      {status || 'Unknown'}
    </span>
  );
}

