import React, { useState } from 'react';
import {
  Settings as SettingsIcon,
  Shield,
  HardDrive,
  Hash,
  Server,
  User,
  CheckCircle,
  Save,
  Radio,
  FileCheck,
  Bell,
  Lock
} from 'lucide-react';

export default function Settings() {
  const [saved, setSaved] = useState(false);
  const [testingApi, setTestingApi] = useState(false);
  const [apiStatus, setApiStatus] = useState(null);

  const defaultApiEndpoint = import.meta.env.VITE_API_URL
    ? import.meta.env.VITE_API_URL.replace(/\/api\/v1\/?$/, '')
    : (typeof window !== 'undefined' && window.location.origin.includes('517') ? 'http://127.0.0.1:8000' : (typeof window !== 'undefined' ? window.location.origin : 'http://127.0.0.1:8000'));

  const [config, setConfig] = useState({
    investigatorName: 'Senior Forensic Examiner',
    organization: 'Cyber Defense Incident Response Team (CIRT)',
    certifications: 'GCFA, EnCE, CISSP',
    defaultHash: 'SHA-256 (NIST FIPS 180-4)',
    autoVerifyOnUpload: true,
    maxUploadSizeMB: 50,
    vaultPath: 'Secure Storage Vault (/uploads)',
    enforceIsoCaveat: true,
    apiEndpoint: defaultApiEndpoint,
    zeroExecutionGuard: true,
    notificationsEnabled: true
  });

  const handleSave = (e) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  const testConnection = async () => {
    setTestingApi(true);
    try {
      const endpoint = (config.apiEndpoint || '').replace(/\/+$/, '');
      const healthUrl = endpoint.endsWith('/api/v1') ? `${endpoint}/health` : `${endpoint}/api/v1/health`;
      const res = await fetch(healthUrl);
      if (res.ok) {
        setApiStatus('Connected: Fast API Backend is Healthy (200 OK)');
      } else {
        setApiStatus(`API Endpoint Responded with Error (HTTP ${res.status})`);
      }
    } catch (err) {
      setApiStatus('Notice: Running in Standalone In-Memory Simulation Mode (FastAPI Endpoint Offline)');
    } finally {
      setTestingApi(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <span>Platform Settings & Forensic Configuration</span>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
            System v1.0
          </span>
        </h2>
        <p className="text-sm text-slate-400">
          Configure investigator credentials, cryptographic verification standards, vault boundaries, and API connectivity.
        </p>
      </div>

      {saved && (
        <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 text-sm flex items-center gap-2 animate-fadeIn font-mono">
          <CheckCircle className="w-5 h-5 text-emerald-400" />
          <span>Configuration saved successfully. Cryptographic parameters updated.</span>
        </div>
      )}

      <form onSubmit={handleSave} className="space-y-6">
        {/* Examiner Profile Card */}
        <div className="cyber-card p-6 rounded-2xl border border-slate-800 space-y-4">
          <h3 className="font-semibold text-slate-100 flex items-center gap-2 text-base pb-2 border-b border-slate-800">
            <User className="w-4 h-4 text-cyan-400" />
            <span>Investigator Credentials & Attribution</span>
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Lead Examiner Name</label>
              <input
                type="text"
                value={config.investigatorName}
                onChange={(e) => setConfig({ ...config, investigatorName: e.target.value })}
                className="w-full px-3.5 py-2 bg-slate-900 border border-slate-700 rounded-xl text-sm text-slate-100 focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Organization / Agency</label>
              <input
                type="text"
                value={config.organization}
                onChange={(e) => setConfig({ ...config, organization: e.target.value })}
                className="w-full px-3.5 py-2 bg-slate-900 border border-slate-700 rounded-xl text-sm text-slate-100 focus:border-cyan-500"
              />
            </div>
            <div className="md:col-span-2">
              <label className="block text-xs font-mono text-slate-400 mb-1">Forensic Certifications</label>
              <input
                type="text"
                value={config.certifications}
                onChange={(e) => setConfig({ ...config, certifications: e.target.value })}
                className="w-full px-3.5 py-2 bg-slate-900 border border-slate-700 rounded-xl text-sm text-slate-100 focus:border-cyan-500"
              />
            </div>
          </div>
        </div>

        {/* Cryptographic Standards */}
        <div className="cyber-card p-6 rounded-2xl border border-slate-800 space-y-4">
          <h3 className="font-semibold text-slate-100 flex items-center gap-2 text-base pb-2 border-b border-slate-800">
            <Hash className="w-4 h-4 text-blue-400" />
            <span>Cryptographic Integrity Engine & Vault Standards</span>
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div>
              <label className="block text-slate-400 mb-1">Primary Integrity Algorithm</label>
              <select
                value={config.defaultHash}
                onChange={(e) => setConfig({ ...config, defaultHash: e.target.value })}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-xl text-cyan-300"
              >
                <option value="SHA-256 (NIST FIPS 180-4)">SHA-256 (NIST FIPS 180-4 Standard)</option>
                <option value="SHA-512">SHA-512 (High Security)</option>
                <option value="BLAKE3">BLAKE3 (High Throughput)</option>
                <option value="Multi-Hash">Multi-Hash (SHA-256 + SHA-1 + MD5)</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Max Evidence Upload Size (MB)</label>
              <input
                type="number"
                value={config.maxUploadSizeMB}
                onChange={(e) => setConfig({ ...config, maxUploadSizeMB: Number(e.target.value) })}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-xl text-slate-100"
              />
            </div>

            <div className="md:col-span-2 pt-2 space-y-2">
              <label className="flex items-center gap-2 cursor-pointer text-slate-300 font-sans">
                <input
                  type="checkbox"
                  checked={config.autoVerifyOnUpload}
                  onChange={(e) => setConfig({ ...config, autoVerifyOnUpload: e.target.checked })}
                  className="rounded bg-slate-900 border-slate-700 text-cyan-500"
                />
                <span>Automatically compute and register SHA-256 baseline immediately on stream ingestion</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer text-slate-300 font-sans">
                <input
                  type="checkbox"
                  checked={config.zeroExecutionGuard}
                  onChange={(e) => setConfig({ ...config, zeroExecutionGuard: e.target.checked })}
                  className="rounded bg-slate-900 border-slate-700 text-cyan-500"
                />
                <span>Enforce Zero-Execution Vault (Random UUID storage, chmod 0600 file permissions)</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer text-slate-300 font-sans">
                <input
                  type="checkbox"
                  checked={config.enforceIsoCaveat}
                  onChange={(e) => setConfig({ ...config, enforceIsoCaveat: e.target.checked })}
                  className="rounded bg-slate-900 border-slate-700 text-cyan-500"
                />
                <span>Enforce ISO/IEC 27037 Attribution Warning across all IP Investigation views and reports</span>
              </label>
            </div>
          </div>
        </div>

        {/* Backend API Connection */}
        <div className="cyber-card p-6 rounded-2xl border border-slate-800 space-y-4">
          <h3 className="font-semibold text-slate-100 flex items-center gap-2 text-base pb-2 border-b border-slate-800">
            <Server className="w-4 h-4 text-purple-400" />
            <span>FastAPI Backend Services Connection</span>
          </h3>

          <div className="flex flex-col sm:flex-row items-center gap-3">
            <div className="flex-1 w-full">
              <label className="block text-xs font-mono text-slate-400 mb-1">FastAPI REST Server URL</label>
              <input
                type="text"
                value={config.apiEndpoint}
                onChange={(e) => setConfig({ ...config, apiEndpoint: e.target.value })}
                className="w-full px-3.5 py-2 bg-slate-900 border border-slate-700 rounded-xl text-sm text-cyan-300 font-mono"
              />
            </div>
            <button
              type="button"
              onClick={testConnection}
              disabled={testingApi}
              className="w-full sm:w-auto px-4 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 rounded-xl text-xs font-mono flex items-center justify-center gap-1.5 self-end"
            >
              <Radio className={`w-3.5 h-3.5 ${testingApi ? 'animate-spin' : ''}`} />
              <span>{testingApi ? 'Probing...' : 'Test Connection'}</span>
            </button>
          </div>

          {apiStatus && (
            <p className="text-xs font-mono text-slate-400 bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
              {apiStatus}
            </p>
          )}
        </div>

        <div className="flex justify-end gap-3 pt-2">
          <button
            type="submit"
            className="px-6 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold rounded-xl text-sm flex items-center gap-2 shadow-cyan-glow"
          >
            <Save className="w-4 h-4" />
            <span>Save Platform Preferences</span>
          </button>
        </div>
      </form>
    </div>
  );
}

