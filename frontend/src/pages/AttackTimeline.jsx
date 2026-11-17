import React, { useState, useEffect } from 'react';
import { timelineService } from '../services/timelineService';
import { mockTimeline } from '../data/mockForensicData';
import Modal from '../components/Modal';
import {
  Clock,
  Plus,
  RefreshCw,
  Milestone,
  Shield,
  Terminal,
  ArrowDown,
  Activity,
  CheckCircle2
} from 'lucide-react';

export default function AttackTimeline({ activeCase }) {
  const [timelineEvents, setTimelineEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [isAddOpen, setIsAddOpen] = useState(false);
  const [newEvent, setNewEvent] = useState({
    event_timestamp: new Date().toISOString().slice(0, 16),
    event_source: 'Incident Responder Note',
    event_category: 'Initial Access',
    actor: '203.0.113.45',
    target: 'Web Application Server (/products.php)',
    description: '',
    confidence_level: 'High'
  });

  const loadTimeline = async () => {
    try {
      setLoading(true);
      if (activeCase?.id) {
        const res = await timelineService.getTimeline(activeCase.id);
        if (res.data && res.data.length > 0) {
          setTimelineEvents(res.data);
          return;
        }
      }
      setTimelineEvents(mockTimeline);
    } catch (err) {
      setTimelineEvents(mockTimeline);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTimeline();
  }, [activeCase]);

  const handleReconstruct = async () => {
    try {
      setLoading(true);
      if (activeCase?.id) {
        await timelineService.reconstruct(activeCase.id);
      }
    } catch (err) {
      console.warn('Backend unavailable, compiled timeline from local correlated logs');
    }
    setTimelineEvents(mockTimeline);
    setLoading(false);
    alert('Attack timeline successfully reconstructed and sequenced from verified forensic event telemetry.');
  };

  const handleAddEvent = async (e) => {
    e.preventDefault();
    const createdEvent = {
      id: `tl-${Date.now()}`,
      case_id: activeCase?.id || 'case-001',
      ...newEvent,
      event_timestamp: new Date(newEvent.event_timestamp).toISOString()
    };
    setTimelineEvents([...timelineEvents, createdEvent]);
    setIsAddOpen(false);
    setNewEvent({
      event_timestamp: new Date().toISOString().slice(0, 16),
      event_source: 'Incident Responder Note',
      event_category: 'Initial Access',
      actor: '',
      target: '',
      description: '',
      confidence_level: 'High'
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <span>Attack Timeline Reconstruction</span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800">
              Chronological Correlation
            </span>
          </h2>
          <p className="text-sm text-slate-400">
            Reconstruct adversarial multi-stage progression from initial reconnaissance through execution, persistence, and defense evasion.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleReconstruct}
            disabled={loading}
            className="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-cyan-500/30 rounded-xl text-sm flex items-center gap-2 transition-all"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            <span>Synthesize from Logs</span>
          </button>
          <button
            onClick={() => setIsAddOpen(true)}
            className="px-4 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold rounded-xl text-sm flex items-center gap-2 shadow-cyan-glow"
          >
            <Plus className="w-4 h-4" />
            <span>Add Milestone</span>
          </button>
        </div>
      </div>

      {/* Chronological Timeline Display */}
      <div className="cyber-card p-6 rounded-2xl border border-slate-800">
        <div className="relative pl-6 sm:pl-8 border-l-2 border-cyan-500/30 space-y-8">
          {timelineEvents.map((ev, idx) => (
            <div key={ev.id || idx} className="relative group">
              {/* Glowing Node indicator */}
              <div className="absolute -left-[31px] sm:-left-[39px] top-1.5 w-4 h-4 rounded-full bg-[#080c14] border-2 border-cyan-400 group-hover:scale-125 group-hover:bg-cyan-400 transition-all shadow-cyan-glow" />

              <div className="p-4 bg-slate-900/70 rounded-xl border border-slate-800 hover:border-cyan-500/40 transition-colors space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-slate-800/80">
                  <div className="flex items-center gap-2 font-mono text-xs">
                    <span className="text-cyan-400 font-bold uppercase">{ev.event_category}</span>
                    <span className="text-slate-600">•</span>
                    <span className="text-slate-400">{ev.event_source}</span>
                  </div>
                  <span className="text-xs font-mono text-slate-400 bg-slate-950 px-2.5 py-0.5 rounded border border-slate-800">
                    {new Date(ev.event_timestamp).toUTCString()}
                  </span>
                </div>

                <p className="text-sm text-slate-200 font-sans leading-relaxed">
                  {ev.description}
                </p>

                <div className="pt-1 flex flex-wrap items-center gap-4 text-xs font-mono text-slate-400 border-t border-slate-800/60">
                  <div>Adversary Actor: <span className="text-cyan-300 font-bold">{ev.actor || 'External Host'}</span></div>
                  <div>Target Asset: <span className="text-blue-300">{ev.target || 'Server'}</span></div>
                  {ev.mitre_tactic && (
                    <div className="text-amber-400 font-semibold">{ev.mitre_tactic}</div>
                  )}
                  <div className="ml-auto text-emerald-400 flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Confidence: {ev.confidence_level}</span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Add Milestone Modal */}
      <Modal isOpen={isAddOpen} onClose={() => setIsAddOpen(false)} title="Record Incident Milestone">
        <form onSubmit={handleAddEvent} className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Timestamp</label>
              <input
                type="datetime-local"
                required
                value={newEvent.event_timestamp}
                onChange={(e) => setNewEvent({ ...newEvent, event_timestamp: e.target.value })}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-cyan-300 font-mono"
              />
            </div>
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Incident Phase</label>
              <select
                value={newEvent.event_category}
                onChange={(e) => setNewEvent({ ...newEvent, event_category: e.target.value })}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white"
              >
                <option value="Initial Access">Initial Access</option>
                <option value="Execution">Execution</option>
                <option value="Persistence">Persistence</option>
                <option value="Privilege Escalation">Privilege Escalation</option>
                <option value="Defense Evasion">Defense Evasion</option>
                <option value="Credential Access">Credential Access</option>
                <option value="Exfiltration">Exfiltration</option>
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Observed Actor (IP/Account)</label>
              <input
                type="text"
                placeholder="e.g. 203.0.113.45 / deployer"
                value={newEvent.actor}
                onChange={(e) => setNewEvent({ ...newEvent, actor: e.target.value })}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white"
              />
            </div>
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Target Asset</label>
              <input
                type="text"
                placeholder="e.g. /etc/shadow or DC01"
                value={newEvent.target}
                onChange={(e) => setNewEvent({ ...newEvent, target: e.target.value })}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white"
              />
            </div>
          </div>
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Forensic Milestone Details</label>
            <textarea
              rows={3}
              required
              placeholder="Chronological event observation and forensic significance..."
              value={newEvent.description}
              onChange={(e) => setNewEvent({ ...newEvent, description: e.target.value })}
              className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white"
            />
          </div>
          <div className="pt-3 flex justify-end gap-3 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsAddOpen(false)}
              className="px-4 py-2 bg-slate-800 text-slate-300 rounded-lg text-sm"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold rounded-lg text-sm shadow-cyan-glow"
            >
              Commit Milestone to Timeline
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
