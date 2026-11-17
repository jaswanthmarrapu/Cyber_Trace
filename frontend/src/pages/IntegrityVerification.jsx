import React, { useState } from 'react';
import { evidenceService } from '../services/evidenceService';
import { ShieldCheck, ShieldAlert, FileCheck, Hash, Copy, Check } from 'lucide-react';

export default function IntegrityVerification() {
  const [file, setFile] = useState(null);
  const [expectedHash, setExpectedHash] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleVerify = async (e) => {
    e.preventDefault();
    if (!file) return alert('Select file to verify');

    const form = new FormData();
    form.append('file', file);
    form.append('expected_sha256', expectedHash);

    try {
      setLoading(true);
      const res = await evidenceService.quickVerifyFile(form);
      setResult(res.data);
    } catch (err) {
      alert('Verification error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white">Evidence Integrity & Cryptographic Checksum Engine</h2>
        <p className="text-sm text-slate-400">
          Compute bit-level hashes (SHA-256, SHA-1, MD5) and detect digital tampering against baseline checksums.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Panel */}
        <div className="cyber-card p-6 rounded-xl border border-slate-800 space-y-4">
          <h3 className="font-semibold text-slate-100 flex items-center gap-2">
            <FileCheck className="w-5 h-5 text-cyan-400" />
            <span>Select Digital Artifact</span>
          </h3>

          <form onSubmit={handleVerify} className="space-y-4">
            <div className="p-6 border-2 border-dashed border-slate-700 rounded-xl bg-slate-900/50 text-center">
              <Hash className="w-8 h-8 text-cyan-400 mx-auto mb-2" />
              <input
                type="file"
                required
                onChange={(e) => setFile(e.target.files[0])}
                className="block w-full text-xs text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-cyan-500 file:text-slate-950 hover:file:bg-cyan-400 cursor-pointer"
              />
              {file && (
                <p className="text-xs text-cyan-300 mt-2 font-mono">
                  Selected: {file.name} ({(file.size / 1024).toFixed(1)} KB)
                </p>
              )}
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">
                Expected SHA-256 Checksum (Optional for comparison)
              </label>
              <input
                type="text"
                placeholder="Paste reference SHA-256 hash to verify against baseline..."
                value={expectedHash}
                onChange={(e) => setExpectedHash(e.target.value)}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <button
              type="submit"
              disabled={loading || !file}
              className="w-full py-2.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold rounded-lg text-sm flex items-center justify-center gap-2 shadow-cyan-glow"
            >
              <ShieldCheck className="w-4 h-4" />
              <span>{loading ? 'Computing Cryptographic Hashes...' : 'Calculate & Verify Hashes'}</span>
            </button>
          </form>
        </div>

        {/* Verification Output Panel */}
        <div className="cyber-card p-6 rounded-xl border border-slate-800 space-y-4">
          <h3 className="font-semibold text-slate-100 flex items-center gap-2">
            <Hash className="w-5 h-5 text-blue-400" />
            <span>Cryptographic Verification Output</span>
          </h3>

          {result ? (
            <div className="space-y-4 animate-fadeIn">
              {/* Integrity Status Pill */}
              <div className={`p-4 rounded-xl border flex items-center gap-3 ${
                result.matches_expected === true
                  ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-400'
                  : result.matches_expected === false
                  ? 'bg-red-950/30 border-red-500/40 text-red-400'
                  : 'bg-cyan-950/30 border-cyan-500/30 text-cyan-300'
              }`}>
                {result.matches_expected === true ? (
                  <ShieldCheck className="w-6 h-6 shrink-0" />
                ) : result.matches_expected === false ? (
                  <ShieldAlert className="w-6 h-6 shrink-0" />
                ) : (
                  <Hash className="w-6 h-6 shrink-0" />
                )}
                <div>
                  <h4 className="font-bold text-sm">{result.integrity_status}</h4>
                  <p className="text-xs text-slate-300 font-sans mt-0.5">
                    {result.matches_expected === true
                      ? 'Integrity Verified: Computed checksum perfectly matches the recorded baseline.'
                      : result.matches_expected === false
                      ? 'ALERT: Checksum mismatch! The file content has been altered or corrupted.'
                      : 'Hashes successfully calculated across all standard forensic algorithms.'}
                  </p>
                </div>
              </div>

              {/* Hash Outputs */}
              <div className="space-y-3 font-mono text-xs">
                <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                  <div className="flex justify-between items-center text-slate-400 mb-1">
                    <span className="text-cyan-400 font-bold">SHA-256 (NIST Standard)</span>
                    <button
                      onClick={() => copyToClipboard(result.sha256)}
                      className="text-slate-500 hover:text-cyan-400 flex items-center gap-1"
                    >
                      {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                  <p className="text-slate-200 select-all break-all">{result.sha256}</p>
                </div>

                <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                  <span className="text-slate-400 font-bold block mb-1">SHA-1</span>
                  <p className="text-slate-300 select-all break-all">{result.sha1}</p>
                </div>

                <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                  <span className="text-slate-400 font-bold block mb-1">MD5 (Legacy Compatibility)</span>
                  <p className="text-slate-300 select-all break-all">{result.md5}</p>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-12 text-center text-slate-500 space-y-2">
              <ShieldCheck className="w-10 h-10 mx-auto text-slate-600" />
              <p className="text-sm">No verification run yet.</p>
              <p className="text-xs text-slate-600 font-mono">
                Upload a file on the left to compute instant hashes and check against reference values.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

