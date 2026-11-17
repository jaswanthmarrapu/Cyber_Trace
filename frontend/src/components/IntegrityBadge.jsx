import React from 'react';
import { ShieldCheck, ShieldAlert, Shield } from 'lucide-react';

export default function IntegrityBadge({ status }) {
  const val = (status || '').toLowerCase();

  if (val === 'verified') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-950/40 text-emerald-400 border border-emerald-500/30 text-xs font-mono">
        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
        SHA-256 Verified
      </span>
    );
  }

  if (val === 'compromised') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-red-950/40 text-red-400 border border-red-500/40 text-xs font-mono animate-pulse">
        <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
        Tamper Detected!
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 text-slate-400 border border-slate-700 text-xs font-mono">
      <Shield className="w-3.5 h-3.5 text-slate-400" />
      Unverified
    </span>
  );
}

