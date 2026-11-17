import React, { useState, useEffect } from 'react';
import { caseService } from '../services/caseService';
import { mockCases } from '../data/mockForensicData';
import DataTable from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import Modal from '../components/Modal';
import {
  FolderPlus,
  FolderGit2,
  CheckCircle,
  Eye,
  AlertCircle,
  User,
  Calendar,
  Layers,
  ArrowRight
} from 'lucide-react';

export default function Cases({ activeCase, onSelectCase, onNavigate }) {
  const [cases, setCases] = useState(mockCases);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [selectedCaseDetail, setSelectedCaseDetail] = useState(null);
  const [formData, setFormData] = useState({
    case_number: `CT-2026-00${mockCases.length + 1}`,
    title: '',
    description: '',
    investigator_name: 'Senior Forensic Examiner',
    severity: 'High',
    incident_type: 'Data Breach'
  });

  const loadCases = async () => {
    try {
      const res = await caseService.getAll();
      if (res.data && res.data.length > 0) {
        setCases(res.data);
      } else {
        setCases(mockCases);
      }
    } catch (err) {
      setCases(mockCases);
    }
  };

  useEffect(() => {
    loadCases();
  }, []);

  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      await caseService.create(formData);
    } catch (err) {
      console.warn('Backend offline, creating local case');
    }

    const newCase = {
      id: `case-${Date.now()}`,
      ...formData,
      status: 'Open',
      created_at: new Date().toISOString(),
      evidence_count: 0,
      threats_count: 0,
      timeline_count: 0
    };

    setCases([newCase, ...cases]);
    onSelectCase(newCase);
    setIsModalOpen(false);
    setFormData({
      case_number: `CT-2026-00${cases.length + 2}`,
      title: '',
      description: '',
      investigator_name: 'Senior Forensic Examiner',
      severity: 'High',
      incident_type: 'Data Breach'
    });
  };

  const handleStatusChange = (caseId, newStatus) => {
    setCases(cases.map(c => c.id === caseId ? { ...c, status: newStatus } : c));
  };

  const columns = [
    {
      header: 'Case Number',
      accessor: 'case_number',
      render: (row) => <span className="font-mono text-cyan-400 font-bold">{row.case_number}</span>
    },
    {
      header: 'Incident Title & Scope',
      accessor: 'title',
      render: (row) => (
        <div>
          <p className="font-semibold text-slate-100">{row.title}</p>
          <p className="text-xs text-slate-400 truncate max-w-sm mt-0.5">{row.description}</p>
        </div>
      )
    },
    {
      header: 'Severity',
      accessor: 'severity',
      render: (row) => <StatusBadge status={row.severity} />
    },
    {
      header: 'Lifecycle Status',
      accessor: 'status',
      render: (row) => (
        <select
          value={row.status}
          onClick={(e) => e.stopPropagation()}
          onChange={(e) => handleStatusChange(row.id, e.target.value)}
          className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs text-slate-200 font-mono focus:border-cyan-500 cursor-pointer"
        >
          <option value="Open">Open</option>
          <option value="Investigating">Investigating</option>
          <option value="Pending Review">Pending Review</option>
          <option value="Closed">Closed</option>
        </select>
      )
    },
    {
      header: 'Lead Investigator',
      accessor: 'investigator_name',
      render: (row) => (
        <span className="text-xs text-slate-300 font-medium">{row.investigator_name}</span>
      )
    },
    {
      header: 'Actions',
      render: (row) => (
        <div className="flex items-center gap-2">
          <button
            onClick={() => onSelectCase(row)}
            className={`px-3 py-1 text-xs rounded-lg font-mono font-medium transition-all ${
              activeCase?.id === row.id
                ? 'bg-cyan-500 text-slate-950 font-bold shadow-cyan-glow'
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
            }`}
          >
            {activeCase?.id === row.id ? 'Active Dossier' : 'Set Active'}
          </button>
          <button
            onClick={() => setSelectedCaseDetail(row)}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white"
            title="Inspect Dossier"
          >
            <Eye className="w-4 h-4" />
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
            <span>Investigation Case Dossiers</span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
              Case Management
            </span>
          </h2>
          <p className="text-sm text-slate-400">
            Lifecycle management, investigator assignment, severity triage, and evidence correlation binder.
          </p>
        </div>
        <button
          onClick={() => setIsModalOpen(true)}
          className="px-4 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold rounded-xl text-sm flex items-center gap-2 shadow-cyan-glow"
        >
          <FolderPlus className="w-4 h-4" />
          <span>New Incident Case</span>
        </button>
      </div>

      <DataTable
        columns={columns}
        data={cases}
        searchPlaceholder="Filter cases by number, title, investigator, or status..."
      />

      {/* Initialize Case Modal */}
      <Modal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} title="Initialize New Forensic Investigation Case">
        <form onSubmit={handleCreate} className="space-y-4">
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Case Number Identifier</label>
            <input
              type="text"
              required
              value={formData.case_number}
              onChange={(e) => setFormData({ ...formData, case_number: e.target.value })}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-cyan-300 font-mono"
            />
          </div>
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Incident Title</label>
            <input
              type="text"
              required
              placeholder="e.g. Operation DarkWeb - Unauthorized SSH Access"
              value={formData.title}
              onChange={(e) => setFormData({ ...formData, title: e.target.value })}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Severity Rating</label>
              <select
                value={formData.severity}
                onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white"
              >
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Incident Category</label>
              <select
                value={formData.incident_type}
                onChange={(e) => setFormData({ ...formData, incident_type: e.target.value })}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white"
              >
                <option value="Data Breach">Data Breach</option>
                <option value="Malware Infection">Malware Infection</option>
                <option value="Ransomware Outbreak">Ransomware Outbreak</option>
                <option value="Unauthorized Access">Unauthorized Access</option>
                <option value="Insider Threat">Insider Threat</option>
                <option value="DDoS Attack">DDoS Attack</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Lead Forensic Investigator</label>
            <input
              type="text"
              required
              value={formData.investigator_name}
              onChange={(e) => setFormData({ ...formData, investigator_name: e.target.value })}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white"
            />
          </div>
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Initial Case Brief / Investigation Scope</label>
            <textarea
              rows={3}
              placeholder="Summary of initial incident detection, affected assets, and scope..."
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white"
            />
          </div>
          <div className="pt-3 flex justify-end gap-3 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsModalOpen(false)}
              className="px-4 py-2 bg-slate-800 text-slate-300 rounded-lg text-sm"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold rounded-lg text-sm shadow-cyan-glow"
            >
              Initialize Case
            </button>
          </div>
        </form>
      </Modal>

      {/* Case Detail Inspection Modal */}
      <Modal
        isOpen={!!selectedCaseDetail}
        onClose={() => setSelectedCaseDetail(null)}
        title={`Case Dossier – ${selectedCaseDetail?.case_number || ''}`}
        maxWidth="max-w-2xl"
      >
        {selectedCaseDetail && (
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-lg font-bold text-white">{selectedCaseDetail.title}</h3>
              <div className="flex items-center gap-2">
                <StatusBadge status={selectedCaseDetail.severity} />
                <StatusBadge status={selectedCaseDetail.status} />
              </div>
            </div>

            <p className="text-sm text-slate-300 leading-relaxed font-sans">
              {selectedCaseDetail.description}
            </p>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono text-slate-400">
              <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                <span className="text-slate-500 block">Lead Investigator</span>
                <span className="text-white font-semibold">{selectedCaseDetail.investigator_name}</span>
              </div>
              <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                <span className="text-slate-500 block">Incident Classification</span>
                <span className="text-cyan-300 font-semibold">{selectedCaseDetail.incident_type}</span>
              </div>
            </div>

            <div className="pt-4 flex justify-between items-center border-t border-slate-800">
              <button
                onClick={() => {
                  onSelectCase(selectedCaseDetail);
                  setSelectedCaseDetail(null);
                }}
                className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-lg text-xs font-mono shadow-cyan-glow"
              >
                Set as Active Dossier
              </button>
              <button
                onClick={() => setSelectedCaseDetail(null)}
                className="px-4 py-2 bg-slate-800 text-slate-300 rounded-lg text-xs"
              >
                Close
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
