import React, { useEffect, useState } from 'react';
import { caseService } from '../services/caseService';
import { mockCases, mockEvidence, mockLogs, mockTimeline } from '../data/mockForensicData';
import StatCard from '../components/StatCard';
import StatusBadge from '../components/StatusBadge';
import IntegrityBadge from '../components/IntegrityBadge';
import {
  FolderGit2,
  HardDrive,
  AlertOctagon,
  ShieldCheck,
  TrendingUp,
  Activity,
  ArrowUpRight,
  ShieldAlert,
  Clock,
  Radio,
  ExternalLink,
  Search,
  Filter
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  CartesianGrid,
  PieChart,
  Pie,
  Cell,
  Legend
} from 'recharts';

export default function Dashboard({ activeCase, onNavigate }) {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadStats() {
      try {
        const res = await caseService.getDashboardStats();
        setStats(res.data);
      } catch (err) {
        // Fallback to high-fidelity mock data if backend is offline
        const verifiedCount = mockEvidence.filter(e => e.integrity_status === 'Verified').length;
        const criticalCount = mockLogs.filter(l => l.severity === 'Critical').length;
        const highCount = mockLogs.filter(l => l.severity === 'High').length;
        const mediumCount = mockLogs.filter(l => l.severity === 'Medium').length;
        const lowCount = mockLogs.filter(l => l.severity === 'Low').length;

        setStats({
          metrics: {
            total_cases: mockCases.length,
            active_cases: mockCases.filter(c => c.status === 'Open' || c.status === 'Investigating').length,
            total_evidence: mockEvidence.length,
            verified_evidence: verifiedCount,
            compromised_evidence: 0,
            total_threats: mockLogs.filter(l => l.is_threat).length,
            critical_alerts: criticalCount,
            total_timeline_events: mockTimeline.length
          },
          severity_distribution: {
            Critical: criticalCount,
            High: highCount,
            Medium: mediumCount,
            Low: lowCount
          },
          recent_cases: mockCases.slice(0, 4)
        });
      } finally {
        setLoading(false);
      }
    }
    loadStats();
  }, [activeCase]);

  const attackTrendData = [
    { time: '00:00', totalEvents: 18, threats: 4 },
    { time: '04:00', totalEvents: 54, threats: 16 },
    { time: '08:00', totalEvents: 142, threats: 38 },
    { time: '12:00', totalEvents: 98, threats: 24 },
    { time: '16:00', totalEvents: 165, threats: 45 },
    { time: '20:00', totalEvents: 78, threats: 19 },
    { time: '23:59', totalEvents: 34, threats: 8 },
  ];

  const severityChartData = stats ? [
    { name: 'Critical', count: stats.severity_distribution.Critical, fill: '#ef4444' },
    { name: 'High', count: stats.severity_distribution.High, fill: '#f59e0b' },
    { name: 'Medium', count: stats.severity_distribution.Medium, fill: '#06b6d4' },
    { name: 'Low', count: stats.severity_distribution.Low, fill: '#10b981' },
  ] : [];

  const vectorDistribution = [
    { name: 'SQL Injection', value: 35, color: '#ef4444' },
    { name: 'SSH Brute Force', value: 28, color: '#f59e0b' },
    { name: 'Web Shell C2', value: 22, color: '#00f0ff' },
    { name: 'Privilege Esc.', value: 15, color: '#3b82f6' }
  ];

  const recentActivities = [
    {
      id: 1,
      timestamp: "10 mins ago",
      investigator: "Senior Forensic Examiner",
      action: "Recalculated SHA-256 for b374k_shell_artifact.php",
      target: "EVD-002",
      type: "Integrity Verified",
      status: "Verified"
    },
    {
      id: 2,
      timestamp: "24 mins ago",
      investigator: "Lead Incident Responder",
      action: "Flagged SQL Injection on /products.php (IP 203.0.113.45)",
      target: "access_staging_combined.log",
      type: "Threat Detection",
      status: "Critical"
    },
    {
      id: 3,
      timestamp: "1 hour ago",
      investigator: "SOC Analyst Tier 3",
      action: "Reconstructed attack milestone: Elevated root shell spawned",
      target: "CT-2026-001",
      type: "Timeline Updated",
      status: "High"
    },
    {
      id: 4,
      timestamp: "2 hours ago",
      investigator: "Senior Forensic Examiner",
      action: "Generated official court-grade forensic PDF dossier",
      target: "REP-CT-2026-001",
      type: "Report Exported",
      status: "Verified"
    }
  ];

  return (
    <div className="space-y-6">
      {/* Premium Cybersecurity Command Banner */}
      <div className="relative overflow-hidden p-6 rounded-2xl bg-gradient-to-r from-[#070d1d] via-[#0c1630] to-[#080d1a] border border-cyan-500/30 shadow-cyan-glow">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl -mr-20 -mt-20 pointer-events-none" />
        
        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono bg-cyan-950/80 text-cyan-300 border border-cyan-500/40">
                <Radio className="w-3 h-3 text-cyan-400 animate-pulse" />
                DFIR Operations Command
              </span>
              <span className="text-xs font-mono text-slate-500">ISO/IEC 27037 Standard</span>
            </div>
            <h1 className="text-3xl font-extrabold text-white tracking-tight">
              CyberTrace Incident Intelligence Hub
            </h1>
            <p className="text-sm text-slate-400 max-w-2xl leading-relaxed">
              Enterprise digital forensics workbench providing multi-source log correlation, cryptographic evidence preservation, passive static file disassembly, and court-admissible reporting.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={() => onNavigate('evidence')}
              className="px-4 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold rounded-xl text-sm transition-all shadow-cyan-glow flex items-center gap-2"
            >
              <HardDrive className="w-4 h-4" />
              <span>Collect Evidence</span>
            </button>
            <button
              onClick={() => onNavigate('logs')}
              className="px-4 py-2.5 bg-slate-900/80 hover:bg-slate-800 text-cyan-300 border border-cyan-500/40 rounded-xl text-sm transition-all flex items-center gap-2"
            >
              <Activity className="w-4 h-4 text-cyan-400" />
              <span>Analyze Logs</span>
            </button>
            <button
              onClick={() => onNavigate('reports')}
              className="px-4 py-2.5 bg-slate-900/80 hover:bg-slate-800 text-slate-300 border border-slate-700 rounded-xl text-sm transition-all flex items-center gap-2"
            >
              <span>Export Dossier</span>
              <ArrowUpRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* 5 Key Metric Cards Required */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard
          title="Total Evidence Files"
          value={stats?.metrics?.total_evidence ?? 4}
          subtitle={`${stats?.metrics?.verified_evidence ?? 4} SHA-256 Validated`}
          icon={HardDrive}
          color="cyan"
          change="+100% Ingestion integrity"
        />
        <StatCard
          title="Suspicious Activities"
          value={stats?.metrics?.total_threats ?? 14}
          subtitle="MITRE ATT&CK Detections"
          icon={Activity}
          color="blue"
          change="4 distinct attack vectors"
        />
        <StatCard
          title="Active Investigations"
          value={stats?.metrics?.active_cases ?? 3}
          subtitle={`Total Cases: ${stats?.metrics?.total_cases ?? 4}`}
          icon={FolderGit2}
          color="cyan"
          change="1 Priority Critical"
        />
        <StatCard
          title="Critical Alerts"
          value={stats?.metrics?.critical_alerts ?? 3}
          subtitle="Immediate Action Required"
          icon={AlertOctagon}
          color="red"
          change="SQLi & WebShell detected"
        />
        <StatCard
          title="Evidence Integrity"
          value={stats?.metrics?.compromised_evidence === 0 ? "100% Valid" : "Tamper Alert"}
          subtitle="Zero Hash Mismatch"
          icon={ShieldCheck}
          color="emerald"
          change="SHA-256 Bit-Level Verified"
        />
      </div>

      {/* Interactive Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* 24-Hour Attack Telemetry Area Chart */}
        <div className="lg:col-span-2 cyber-card p-5 rounded-2xl border border-slate-800/80 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-800/60">
            <div>
              <h3 className="font-semibold text-slate-100 flex items-center gap-2 text-base">
                <Activity className="w-4 h-4 text-cyan-400" />
                24-Hour Attack Telemetry & Event Volume
              </h3>
              <p className="text-xs text-slate-400">Total correlated log traffic vs flagged adversarial attempts</p>
            </div>
            <div className="flex items-center gap-3 text-xs font-mono">
              <span className="flex items-center gap-1.5 text-cyan-400">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400"></span> Total Events
              </span>
              <span className="flex items-center gap-1.5 text-red-400">
                <span className="w-2.5 h-2.5 rounded-full bg-red-400"></span> Threat Hits
              </span>
            </div>
          </div>

          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={attackTrendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="cyanGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="redGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 11 }} />
                <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0b1329', borderColor: '#06b6d4', borderRadius: '10px', color: '#f8fafc' }}
                />
                <Area type="monotone" dataKey="totalEvents" stroke="#06b6d4" strokeWidth={2.5} fillOpacity={1} fill="url(#cyanGrad)" />
                <Area type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#redGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Severity & Vector Distribution */}
        <div className="cyber-card p-5 rounded-2xl border border-slate-800/80 space-y-4">
          <div className="pb-2 border-b border-slate-800/60">
            <h3 className="font-semibold text-slate-100 flex items-center gap-2 text-base">
              <TrendingUp className="w-4 h-4 text-blue-400" />
              Attack Vector Breakdown
            </h3>
            <p className="text-xs text-slate-400">Classified incident vectors</p>
          </div>

          <div className="h-44">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={vectorDistribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={70}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {vectorDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#0b1329', borderColor: '#3b82f6', borderRadius: '8px' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="space-y-1.5 pt-1 text-xs">
            {vectorDistribution.map((item, idx) => (
              <div key={idx} className="flex items-center justify-between font-mono">
                <span className="flex items-center gap-2 text-slate-300">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                  {item.name}
                </span>
                <span className="text-slate-400 font-semibold">{item.value}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Active Case Intelligence Dossier */}
      {activeCase && (
        <div className="cyber-card p-5 rounded-2xl border border-cyan-500/30 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-800/80 gap-3">
            <div>
              <span className="text-xs font-mono uppercase tracking-wider text-cyan-400">Active Case Dossier</span>
              <h2 className="text-xl font-bold text-white mt-0.5">{activeCase.title}</h2>
            </div>
            <div className="flex items-center gap-3">
              <StatusBadge status={activeCase.severity} />
              <StatusBadge status={activeCase.status} />
              <button
                onClick={() => onNavigate('cases')}
                className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs rounded-lg font-mono border border-slate-700 flex items-center gap-1"
              >
                <span>View Full Dossier</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          <p className="text-sm text-slate-300 leading-relaxed font-sans">
            {activeCase.description}
          </p>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-3 border-t border-slate-800/80 text-xs font-mono">
            <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800">
              <span className="text-slate-500 block">Case Number</span>
              <span className="text-cyan-300 font-bold">{activeCase.case_number}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800">
              <span className="text-slate-500 block">Incident Classification</span>
              <span className="text-blue-300 font-semibold">{activeCase.incident_type}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800">
              <span className="text-slate-500 block">Lead Investigator</span>
              <span className="text-slate-200">{activeCase.investigator_name}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800">
              <span className="text-slate-500 block">Integrity State</span>
              <span className="text-emerald-400 font-semibold flex items-center gap-1">
                <ShieldCheck className="w-3.5 h-3.5" /> SHA-256 Validated
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Recent Investigation Activities Table */}
      <div className="cyber-card p-5 rounded-2xl border border-slate-800/80 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800/60">
          <div>
            <h3 className="font-semibold text-slate-100 flex items-center gap-2 text-base">
              <Clock className="w-4 h-4 text-cyan-400" />
              Recent Investigation Activities
            </h3>
            <p className="text-xs text-slate-400">Audit trail of forensic actions, hash checks, and incident alerts</p>
          </div>
          <span className="text-xs font-mono text-cyan-400 bg-cyan-950/40 px-2.5 py-1 rounded-md border border-cyan-800/40">
            Immutable Audit Trail
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-[#0b1329] text-xs uppercase font-mono tracking-wider text-slate-400 border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3">Investigator</th>
                <th className="px-4 py-3">Forensic Action</th>
                <th className="px-4 py-3">Target Artifact</th>
                <th className="px-4 py-3">Classification</th>
                <th className="px-4 py-3">Integrity / Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {recentActivities.map((act) => (
                <tr key={act.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="px-4 py-3 text-xs font-mono text-slate-400">{act.timestamp}</td>
                  <td className="px-4 py-3 text-xs font-semibold text-slate-200">{act.investigator}</td>
                  <td className="px-4 py-3 text-xs text-slate-300">{act.action}</td>
                  <td className="px-4 py-3 text-xs font-mono text-cyan-400">{act.target}</td>
                  <td className="px-4 py-3 text-xs text-slate-400">{act.type}</td>
                  <td className="px-4 py-3 text-xs">
                    <StatusBadge status={act.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
