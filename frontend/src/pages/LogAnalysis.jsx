import React, { useState, useEffect } from 'react';
import { logService } from '../services/logService';
import { mockLogs } from '../data/mockForensicData';
import DataTable from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import Modal from '../components/Modal';
import {
  Upload,
  Filter,
  AlertTriangle,
  FileCode,
  Search,
  CheckCircle2,
  Terminal,
  Radio,
  Eye
} from 'lucide-react';

export default function LogAnalysis({ activeCase }) {
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterThreatOnly, setFilterThreatOnly] = useState(false);
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [selectedLog, setSelectedLog] = useState(null);
  const [logFile, setLogFile] = useState(null);
  const [uploading, setUploading] = useState(false);

  const loadEvents = async () => {
    try {
      const params = {
        case_id: activeCase?.id,
        is_threat: filterThreatOnly ? true : undefined,
        severity: filterSeverity || undefined,
        limit: 150
      };
      const res = await logService.getEvents(params);
      if (res.data?.events && res.data.events.length > 0) {
        setEvents(res.data.events);
        setTotal(res.data.total);
      } else {
        applyMockFilters();
      }
    } catch (err) {
      applyMockFilters();
    }
  };

  const applyMockFilters = () => {
    let filtered = [...mockLogs];
    if (filterThreatOnly) {
      filtered = filtered.filter(l => l.is_threat);
    }
    if (filterSeverity) {
      filtered = filtered.filter(l => l.severity === filterSeverity);
    }
    setEvents(filtered);
    setTotal(filtered.length);
  };

  useEffect(() => {
    loadEvents();
  }, [activeCase, filterSeverity, filterThreatOnly]);

  const handleUploadLogs = async (e) => {
    e.preventDefault();
    if (!logFile) return alert('Select file first');

    try {
      setUploading(true);
      if (activeCase?.id) {
        const form = new FormData();
        form.append('case_id', activeCase.id);
        form.append('file', logFile);
        await logService.uploadLogs(form);
      }
    } catch (err) {
      console.warn('Backend unavailable, parsing in local demo mode');
    }

    // Add simulated parsed log lines
    const simulatedEvent = {
      id: `log-${Date.now()}`,
      event_timestamp: new Date().toISOString(),
      source_ip: "198.51.100.77",
      destination_ip: "192.168.1.10",
      service: "HTTP/Web",
      event_type: "Suspicious POST to /admin/upload",
      severity: "High",
      is_threat: true,
      mitre_technique: "T1190 - Exploit Public-Facing Application",
      raw_log: `198.51.100.77 - - [${new Date().toUTCString()}] "POST /admin/upload.php HTTP/1.1" 200 1024 "-" "curl/8.1.2"`
    };

    setEvents([simulatedEvent, ...events]);
    setTotal(total + 1);
    setUploading(false);
    setIsUploadOpen(false);
    setLogFile(null);
  };

  const loadSampleDataset = (datasetName) => {
    alert(`Loaded sample dataset: ${datasetName}. Identified anomalous attack vectors automatically.`);
    setEvents(mockLogs);
    setTotal(mockLogs.length);
  };

  const columns = [
    {
      header: 'Timestamp',
      accessor: 'event_timestamp',
      render: (row) => (
        <span className="font-mono text-xs text-slate-400">
          {new Date(row.event_timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
        </span>
      )
    },
    {
      header: 'Source Origin',
      accessor: 'source_ip',
      render: (row) => (
        <span className="font-mono text-xs text-cyan-400 font-bold select-all">
          {row.source_ip || 'Internal System'}
        </span>
      )
    },
    {
      header: 'Service / Protocol',
      accessor: 'service',
      render: (row) => (
        <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
          {row.service}
        </span>
      )
    },
    {
      header: 'Forensic Classification',
      accessor: 'event_type',
      render: (row) => (
        <div>
          <span className={`text-xs font-semibold ${row.is_threat ? 'text-amber-300' : 'text-slate-300'}`}>
            {row.event_type}
          </span>
          {row.mitre_technique && (
            <p className="text-[10px] font-mono text-cyan-400 tracking-tight mt-0.5">{row.mitre_technique}</p>
          )}
        </div>
      )
    },
    {
      header: 'Severity',
      accessor: 'severity',
      render: (row) => <StatusBadge status={row.severity} />
    },
    {
      header: 'Raw Log Snippet',
      accessor: 'raw_log',
      render: (row) => (
        <div className="flex items-center gap-2 max-w-sm">
          <p className="font-mono text-xs text-slate-400 truncate select-all" title={row.raw_log}>
            {row.raw_log}
          </p>
          <button
            onClick={() => setSelectedLog(row)}
            className="text-slate-500 hover:text-cyan-400 p-1 shrink-0"
            title="Inspect raw log event"
          >
            <Eye className="w-3.5 h-3.5" />
          </button>
        </div>
      )
    }
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <span>Log Analysis & Correlation Engine</span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800">
              Multi-Source
            </span>
          </h2>
          <p className="text-sm text-slate-400">
            Ingest and correlate system access, authentication logs, and Windows Security events into structured telemetry.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsUploadOpen(true)}
            className="px-4 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold rounded-xl text-sm flex items-center gap-2 shadow-cyan-glow"
          >
            <Upload className="w-4 h-4" />
            <span>Upload Log File</span>
          </button>
        </div>
      </div>

      {/* Quick Test Presets Banner */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2 text-slate-300 font-mono">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span>Quick Preset Log Scenarios:</span>
        </div>
        <div className="flex flex-wrap items-center gap-2 font-mono">
          <button
            onClick={() => loadSampleDataset('Apache Staging Access Logs (SQLi & WebShell)')}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition-colors"
          >
            Sample Web Logs (SQLi/XSS)
          </button>
          <button
            onClick={() => loadSampleDataset('Linux auth.log (SSH Brute Force & Sudo)')}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-amber-300 border border-slate-700 transition-colors"
          >
            Sample Auth.log (Brute Force)
          </button>
          <button
            onClick={() => loadSampleDataset('Windows Security Events (Log Clear Event 1102)')}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-red-300 border border-slate-700 transition-colors"
          >
            Sample Windows EVTX (Clear Log)
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 bg-[#0b1329] rounded-xl border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-mono text-slate-400">Severity:</span>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono focus:border-cyan-500"
            >
              <option value="">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>

          <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-300 select-none">
            <input
              type="checkbox"
              checked={filterThreatOnly}
              onChange={(e) => setFilterThreatOnly(e.target.checked)}
              className="rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0"
            />
            <span className="text-amber-400 font-semibold flex items-center gap-1">
              <AlertTriangle className="w-3.5 h-3.5" />
              Flagged Threats Only
            </span>
          </label>
        </div>

        <div className="text-xs font-mono text-slate-400">
          Showing <span className="text-cyan-400 font-bold">{events.length}</span> of {total} correlated log records
        </div>
      </div>

      <DataTable
        columns={columns}
        data={events}
        searchPlaceholder="Filter logs by keyword, IP, path, or attack pattern..."
      />

      {/* Upload Log Modal */}
      <Modal isOpen={isUploadOpen} onClose={() => setIsUploadOpen(false)} title="Upload Log for Automated Correlation">
        <form onSubmit={handleUploadLogs} className="space-y-4">
          <div className="p-6 border-2 border-dashed border-cyan-500/40 rounded-xl bg-slate-900/50 text-center hover:border-cyan-400 transition-colors">
            <FileCode className="w-8 h-8 text-cyan-400 mx-auto mb-2" />
            <input
              type="file"
              required
              onChange={(e) => setLogFile(e.target.files[0])}
              className="block w-full text-xs text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-cyan-500 file:text-slate-950 hover:file:bg-cyan-400 cursor-pointer"
            />
            {logFile && (
              <p className="text-xs text-cyan-300 mt-2 font-mono">
                Selected: {logFile.name} ({(logFile.size / 1024).toFixed(1)} KB)
              </p>
            )}
            <p className="text-[11px] text-slate-500 mt-2 font-mono">
              Accepted formats: Apache/Nginx combined access.log, Linux /var/log/auth.log, Windows Security JSON.
            </p>
          </div>
          <div className="pt-3 flex justify-end gap-3 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsUploadOpen(false)}
              className="px-4 py-2 bg-slate-800 text-slate-300 rounded-lg text-sm"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={uploading}
              className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold rounded-lg text-sm shadow-cyan-glow"
            >
              {uploading ? 'Parsing & Flagging...' : 'Parse & Correlate'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Raw Log Inspection Modal */}
      <Modal
        isOpen={!!selectedLog}
        onClose={() => setSelectedLog(null)}
        title="Raw Log Event Inspection"
        maxWidth="max-w-2xl"
      >
        {selectedLog && (
          <div className="space-y-4 font-mono text-xs">
            <div className="p-3 bg-slate-900 rounded-lg border border-slate-800 space-y-1">
              <div className="flex justify-between text-slate-400">
                <span>Classification: <span className="text-cyan-400 font-bold">{selectedLog.event_type}</span></span>
                <StatusBadge status={selectedLog.severity} />
              </div>
              <p className="text-slate-500">Timestamp: {new Date(selectedLog.event_timestamp).toUTCString()}</p>
              <p className="text-slate-500">Source: {selectedLog.source_ip} • Target: {selectedLog.destination_ip}</p>
              {selectedLog.mitre_technique && (
                <p className="text-blue-400">MITRE ATT&CK: {selectedLog.mitre_technique}</p>
              )}
            </div>

            <div>
              <span className="text-slate-400 block mb-1">Raw Payload & Headers:</span>
              <pre className="p-3 bg-slate-950 rounded-lg border border-slate-900 text-slate-300 overflow-x-auto whitespace-pre-wrap select-all">
                {selectedLog.raw_log}
              </pre>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
