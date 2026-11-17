import React, { useState, useEffect } from 'react';
import { threatService } from '../services/threatService';
import { mockLogs } from '../data/mockForensicData';
import DataTable from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import {
  AlertOctagon,
  ShieldAlert,
  Cpu,
  Crosshair,
  Filter,
  Eye,
  CheckCircle,
  ExternalLink
} from 'lucide-react';

export default function ThreatDetection({ activeCase }) {
  const [threatData, setThreatData] = useState({ total_threats: 0, mitre_matrix: {}, threats: [] });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadThreats() {
      try {
        setLoading(true);
        const res = await threatService.getDetections(activeCase?.id);
        if (res.data?.threats && res.data.threats.length > 0) {
          setThreatData(res.data);
        } else {
          loadMockThreats();
        }
      } catch (err) {
        loadMockThreats();
      } finally {
        setLoading(false);
      }
    }
    loadThreats();
  }, [activeCase]);

  const loadMockThreats = () => {
    const threats = mockLogs.filter(l => l.is_threat);
    const matrix = {};
    threats.forEach(t => {
      const tech = t.mitre_technique || "Uncategorized";
      matrix[tech] = (matrix[tech] || 0) + 1;
    });
    setThreatData({
      total_threats: threats.length,
      mitre_matrix: matrix,
      threats: threats
    });
  };

  const columns = [
    {
      header: 'Detected Attack Type',
      accessor: 'event_type',
      render: (row) => (
        <div>
          <span className="font-semibold text-slate-100 block">{row.event_type}</span>
          <p className="text-xs text-slate-500 font-mono">{row.service} Service Target</p>
        </div>
      )
    },
    {
      header: 'Attacker Endpoint (Source)',
      accessor: 'source_ip',
      render: (row) => (
        <span className="font-mono text-xs text-cyan-400 font-bold select-all">
          {row.source_ip || 'Internal System'}
        </span>
      )
    },
    {
      header: 'MITRE ATT&CK Mapping',
      accessor: 'mitre_technique',
      render: (row) => (
        <span className="font-mono text-xs px-2.5 py-1 rounded bg-blue-950/80 text-blue-300 border border-blue-800/60 inline-flex items-center gap-1.5">
          <Crosshair className="w-3.5 h-3.5 text-cyan-400" />
          {row.mitre_technique || 'T1190 - Exploit Public-Facing App'}
        </span>
      )
    },
    {
      header: 'Severity',
      accessor: 'severity',
      render: (row) => <StatusBadge status={row.severity} />
    },
    {
      header: 'Observed Indicator Payload',
      accessor: 'raw_log',
      render: (row) => (
        <p className="font-mono text-xs text-slate-400 truncate max-w-sm select-all" title={row.raw_log}>
          {row.raw_log}
        </p>
      )
    }
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <span>Automated Threat Detection & MITRE ATT&CK Mapping</span>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800">
            Real-Time Detections
          </span>
        </h2>
        <p className="text-sm text-slate-400">
          Heuristic and signature-based detection engine mapping anomalous security events to MITRE ATT&CK tactics.
        </p>
      </div>

      {/* MITRE ATT&CK Technique Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {Object.entries(threatData.mitre_matrix).map(([technique, count], i) => (
          <div key={i} className="cyber-card p-4 rounded-xl border border-slate-800 hover:border-cyan-500/30 transition-colors">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider">MITRE Technique</span>
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                {count} {count === 1 ? 'Hit' : 'Hits'}
              </span>
            </div>
            <h4 className="text-xs font-semibold text-slate-100 mt-2 font-mono truncate" title={technique}>
              {technique}
            </h4>
          </div>
        ))}
      </div>

      {/* Threat Detections Table */}
      <DataTable
        columns={columns}
        data={threatData.threats}
        searchPlaceholder="Filter threat detections by signature, IP, or payload..."
      />
    </div>
  );
}
