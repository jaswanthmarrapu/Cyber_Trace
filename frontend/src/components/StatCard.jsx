import React from 'react';

export default function StatCard({ title, value, subtitle, icon: Icon, color = 'cyan', change }) {
  const colorThemes = {
    cyan: {
      border: 'hover:border-cyan-500/50',
      iconBg: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
      text: 'text-cyan-400',
    },
    blue: {
      border: 'hover:border-blue-500/50',
      iconBg: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
      text: 'text-blue-400',
    },
    red: {
      border: 'hover:border-red-500/50',
      iconBg: 'bg-red-500/10 text-red-400 border-red-500/30',
      text: 'text-red-400',
    },
    emerald: {
      border: 'hover:border-emerald-500/50',
      iconBg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      text: 'text-emerald-400',
    },
  };

  const currentTheme = colorThemes[color] || colorThemes.cyan;

  return (
    <div className={`cyber-card p-5 rounded-xl border transition-all duration-300 ${currentTheme.border}`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">{title}</p>
          <h3 className="text-2xl font-bold font-mono text-slate-100 mt-1">{value}</h3>
          {subtitle && <p className="text-xs text-slate-500 mt-1">{subtitle}</p>}
        </div>
        {Icon && (
          <div className={`p-3 rounded-lg border ${currentTheme.iconBg}`}>
            <Icon className="w-6 h-6" />
          </div>
        )}
      </div>
      {change && (
        <div className="mt-3 text-xs text-slate-400 flex items-center gap-1">
          <span className={currentTheme.text}>{change}</span>
        </div>
      )}
    </div>
  );
}

