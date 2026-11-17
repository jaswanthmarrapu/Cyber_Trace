import React, { useState, useEffect } from 'react';
import { evidenceService } from '../services/evidenceService';
import { forensicService } from '../services/forensicService';
import { mockEvidence, mockForensicAnalysis } from '../data/mockForensicData';
import {
  Binary,
  ShieldCheck,
  AlertTriangle,
  Terminal,
  Code,
  Cpu,
  Search,
  Eye,
  FileCode,
  Gauge
} from 'lucide-react';

export default function FileForensics({ activeCase }) {
  const [evidenceList, setEvidenceList] = useState(mockEvidence);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState('evd-002');
  const [analysisResult, setAnalysisResult] = useState(mockForensicAnalysis);
  const [stringSearch, setStringSearch] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const res = await evidenceService.getAll(activeCase?.id);
        if (res.data && res.data.length > 0) {
          setEvidenceList(res.data);
          setSelectedEvidenceId(res.data[0].id);
        }
      } catch (err) {
        setEvidenceList(mockEvidence);
      }
    }
    load();
  }, [activeCase]);

  const runAnalysis = async () => {
    if (!selectedEvidenceId) return alert('Select evidence item first');
    try {
      setLoading(true);
      const res = await forensicService.analyze(selectedEvidenceId);
      setAnalysisResult(res.data);
    } catch (err) {
      // Offline fallback
      setAnalysisResult(mockForensicAnalysis);
    } finally {
      setLoading(false);
    }
  };

  const filteredStrings = (analysisResult?.sample_strings || []).filter(s =>
    s.toLowerCase().includes(stringSearch.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <span>Passive File Forensics & Static Disassembly</span>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
            Zero-Execution Guard
          </span>
        </h2>
        <p className="text-sm text-slate-400">
          In-memory binary analysis: Magic byte inspection, Shannon entropy scoring, string extraction, and YARA signature matching.
        </p>
      </div>

      {/* Select Evidence Bar */}
      <div className="cyber-card p-5 rounded-2xl border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex-1 w-full sm:w-auto">
          <label className="block text-xs font-mono text-slate-400 mb-1">Target Vault Artifact for Disassembly</label>
          <select
            value={selectedEvidenceId}
            onChange={(e) => {
              setSelectedEvidenceId(e.target.value);
            }}
            className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3.5 py-2.5 text-sm text-cyan-300 font-mono focus:border-cyan-500"
          >
            {evidenceList.map((e) => (
              <option key={e.id} value={e.id}>
                [{e.evidence_number}] {e.original_filename} ({(e.file_size_bytes / 1024).toFixed(1)} KB) • {e.mime_type}
              </option>
            ))}
          </select>
        </div>
        <button
          onClick={runAnalysis}
          disabled={loading || !selectedEvidenceId}
          className="w-full sm:w-auto px-6 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold rounded-xl text-sm flex items-center justify-center gap-2 shadow-cyan-glow self-end"
        >
          <Binary className="w-4 h-4" />
          <span>{loading ? 'Dissecting Artifact...' : 'Dissect & Scan Signatures'}</span>
        </button>
      </div>

      {analysisResult && (
        <div className="space-y-6 animate-fadeIn">
          {/* Header Metric Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Magic Bytes Card */}
            <div className="cyber-card p-5 rounded-xl border border-slate-800 space-y-1">
              <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">Magic Byte Signature</span>
              <p className="font-mono text-lg font-bold text-slate-100 mt-1 select-all">
                {analysisResult.magic_bytes.magic_hex || '3C 3F 70 68 70'}
              </p>
              <p className="text-xs text-slate-400 font-mono">{analysisResult.magic_bytes.detected_type}</p>
            </div>

            {/* Shannon Entropy Card */}
            <div className="cyber-card p-5 rounded-xl border border-slate-800 space-y-1">
              <span className="text-xs font-mono text-blue-400 uppercase tracking-wider">Shannon Entropy Meter</span>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="font-mono text-2xl font-bold text-white">
                  {analysisResult.entropy.entropy}
                </span>
                <span className="text-xs text-slate-500 font-mono">/ 8.00 Max</span>
              </div>
              {/* Visual Entropy Bar */}
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden mt-1">
                <div
                  className={`h-full rounded-full ${
                    analysisResult.entropy.entropy > 7.2 ? 'bg-red-500' : 'bg-cyan-400'
                  }`}
                  style={{ width: `${(analysisResult.entropy.entropy / 8) * 100}%` }}
                />
              </div>
              <p className={`text-xs mt-1 font-medium ${
                analysisResult.entropy.is_packed_or_encrypted ? 'text-amber-400' : 'text-emerald-400'
              }`}>
                {analysisResult.entropy.classification}
              </p>
            </div>

            {/* Signature Hits Card */}
            <div className="cyber-card p-5 rounded-xl border border-slate-800 space-y-1">
              <span className="text-xs font-mono text-red-400 uppercase tracking-wider">Threat Signature Hits</span>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="font-mono text-2xl font-bold text-red-400">
                  {analysisResult.signature_matches.length}
                </span>
                <span className="text-xs text-slate-500 font-mono">YARA / Heuristic rules</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                {analysisResult.signature_matches.length > 0
                  ? 'Known web shell / C2 malware markers flagged'
                  : 'Clean / No known signature matches'}
              </p>
            </div>
          </div>

          {/* Signature Rules Hit Card */}
          {analysisResult.signature_matches.length > 0 && (
            <div className="cyber-card p-5 rounded-2xl border border-red-500/40 bg-red-950/10 space-y-3">
              <h3 className="font-semibold text-red-400 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400 animate-pulse" />
                <span>Identified Malware / Threat Signatures</span>
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {analysisResult.signature_matches.map((rule, idx) => (
                  <div key={idx} className="p-3.5 bg-slate-900/80 rounded-xl border border-red-500/20 text-xs space-y-1">
                    <div className="flex justify-between font-mono">
                      <span className="text-red-400 font-bold">{rule.rule_name}</span>
                      <span className="text-cyan-400 font-semibold">{rule.mitre_id}</span>
                    </div>
                    <p className="text-slate-300">Category: {rule.category} | Severity: {rule.severity}</p>
                    <div className="mt-2 text-[11px] font-mono text-slate-400 bg-slate-950 p-2 rounded border border-slate-900">
                      Matched: {rule.matched_signatures?.join(', ') || 'Known pattern matched'}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Extracted IOCs & Strings */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Extracted IOC Indicators */}
            <div className="cyber-card p-5 rounded-2xl border border-slate-800 space-y-3">
              <h3 className="font-semibold text-slate-100 flex items-center gap-2 text-sm">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>Extracted Network & Command IOCs</span>
              </h3>
              <div className="space-y-3 text-xs font-mono">
                <div>
                  <span className="text-slate-500 block mb-1">Embedded IP Addresses:</span>
                  <div className="flex flex-wrap gap-1.5">
                    {analysisResult.iocs?.ips?.length > 0 ? (
                      analysisResult.iocs.ips.map((ip, i) => (
                        <span key={i} className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                          {ip}
                        </span>
                      ))
                    ) : (
                      <span className="text-slate-500">None detected</span>
                    )}
                  </div>
                </div>

                <div>
                  <span className="text-slate-500 block mb-1">Embedded C2 URLs / Gateways:</span>
                  <div className="flex flex-wrap gap-1.5">
                    {analysisResult.iocs?.urls?.length > 0 ? (
                      analysisResult.iocs.urls.map((u, i) => (
                        <span key={i} className="px-2 py-0.5 rounded bg-slate-800 text-blue-300 border border-slate-700 truncate max-w-full">
                          {u}
                        </span>
                      ))
                    ) : (
                      <span className="text-slate-500">None detected</span>
                    )}
                  </div>
                </div>

                <div>
                  <span className="text-slate-500 block mb-1">Identified Shell Commands:</span>
                  <div className="flex flex-wrap gap-1.5">
                    {analysisResult.iocs?.commands?.map((cmd, i) => (
                      <span key={i} className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30">
                        {cmd}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Printable String Inspector */}
            <div className="cyber-card p-5 rounded-2xl border border-slate-800 space-y-3">
              <div className="flex items-center justify-between pb-1 border-b border-slate-800">
                <h3 className="font-semibold text-slate-100 flex items-center gap-2 text-sm">
                  <Code className="w-4 h-4 text-blue-400" />
                  <span>ASCII & Unicode Printable Strings</span>
                </h3>
                <div className="relative">
                  <Search className="w-3.5 h-3.5 absolute left-2 top-2 text-slate-500" />
                  <input
                    type="text"
                    placeholder="Search strings..."
                    value={stringSearch}
                    onChange={(e) => setStringSearch(e.target.value)}
                    className="pl-7 pr-3 py-1 bg-slate-900 border border-slate-700 rounded text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div className="max-h-56 overflow-y-auto bg-slate-950 p-3 rounded-xl border border-slate-900 font-mono text-xs text-slate-300 space-y-1.5">
                {filteredStrings.length > 0 ? (
                  filteredStrings.map((str, idx) => (
                    <div key={idx} className="truncate hover:text-cyan-300 transition-colors select-all">
                      <span className="text-slate-600 mr-2">{String(idx + 1).padStart(2, '0')}:</span>
                      {str}
                    </div>
                  ))
                ) : (
                  <div className="text-slate-500 text-center py-4">No matching strings found</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
