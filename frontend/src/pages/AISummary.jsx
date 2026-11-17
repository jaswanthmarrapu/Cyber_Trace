import React, { useState, useEffect } from 'react';
import { aiService } from '../services/aiService';
import { Sparkles, Shield, AlertTriangle, CheckSquare, RefreshCw, Cpu } from 'lucide-react';

export default function AISummary({ activeCase }) {
  const [summaryData, setSummaryData] = useState(null);
  const [loading, setLoading] = useState(false);

  const loadSummary = async () => {
    if (!activeCase) return;
    try {
      setLoading(true);
      const res = await aiService.getSummary(activeCase.id);
      setSummaryData(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSummary();
  }, [activeCase]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <span>AI-Assisted Investigation Summary & Briefing</span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
              Copilot Engine
            </span>
          </h2>
          <p className="text-sm text-slate-400">
            Synthesized executive narrative, root cause analysis, and prioritized remediation actions.
          </p>
        </div>
        <button
          onClick={loadSummary}
          disabled={loading || !activeCase}
          className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-cyan-500/30 rounded-lg text-sm flex items-center gap-2"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          <span>Regenerate Summary</span>
        </button>
      </div>

      {loading ? (
        <div className="p-16 text-center text-slate-400 space-y-3 cyber-card rounded-xl">
          <Cpu className="w-8 h-8 text-cyan-400 mx-auto animate-spin" />
          <p className="text-sm font-mono">Synthesizing telemetry and forensic evidence...</p>
        </div>
      ) : summaryData ? (
        <div className="space-y-6 animate-fadeIn">
          {/* Executive Narrative */}
          <div className="cyber-card p-6 rounded-xl border border-slate-800 space-y-3">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="font-semibold text-slate-100 flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-cyan-400" />
                <span>Executive Incident Narrative</span>
              </h3>
              <span className="text-xs font-mono text-cyan-300">
                Case {summaryData.case_number}
              </span>
            </div>
            <p className="text-sm text-slate-200 leading-relaxed font-sans">
              {summaryData.executive_summary}
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Attack Chain */}
            <div className="cyber-card p-6 rounded-xl border border-slate-800 space-y-3">
              <h3 className="font-semibold text-slate-100 flex items-center gap-2 pb-2 border-b border-slate-800">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span>Reconstructed Attack Vector Chain</span>
              </h3>
              <div className="space-y-2 text-xs font-sans text-slate-300">
                {summaryData.attack_narrative.map((item, i) => (
                  <div key={i} className="p-2.5 rounded bg-slate-900/80 border border-slate-800">
                    {item}
                  </div>
                ))}
              </div>
            </div>

            {/* Strategic Remediation Checklist */}
            <div className="cyber-card p-6 rounded-xl border border-slate-800 space-y-3">
              <h3 className="font-semibold text-slate-100 flex items-center gap-2 pb-2 border-b border-slate-800">
                <CheckSquare className="w-4 h-4 text-emerald-400" />
                <span>Containment & Remediation Checklist</span>
              </h3>
              <div className="space-y-2 text-xs font-sans text-slate-300">
                {summaryData.remediation_plan.map((item, i) => (
                  <div key={i} className="flex items-start gap-2 p-2 rounded bg-slate-900/60 border border-slate-800/80">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0"></span>
                    <span>{item}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="p-12 text-center text-slate-500 cyber-card rounded-xl">
          <Sparkles className="w-10 h-10 mx-auto text-slate-600 mb-2" />
          <p className="text-sm">Select an active case to generate an AI forensic summary.</p>
        </div>
      )}
    </div>
  );
}

