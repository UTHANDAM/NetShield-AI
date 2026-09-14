'use client';

import { useState, useEffect } from 'react';
import { api } from '../../../../lib/api';
import { useParams } from 'next/navigation';
import { 
  ShieldAlert, Clock, User, AlertCircle, FileText, 
  Activity, ArrowRight, MessageSquare, Terminal, CheckCircle
} from 'lucide-react';
import Link from 'next/link';
import Toast from '../../../../components/ui/Toast';

const STATUS_FLOW = [
  'detection', 'triage', 'investigation', 'containment', 
  'eradication', 'recovery', 'resolution', 'closed'
];

export default function IncidentDetailPage() {
  const params = useParams();
  const id = params.id;

  const [incident, setIncident] = useState(null);
  const [notes, setNotes] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [newNote, setNewNote] = useState('');
  const [toast, setToast] = useState(null);

  useEffect(() => {
    fetchData();
  }, [id]);

  const fetchData = async () => {
    try {
      const [incData, notesData, alertsData] = await Promise.all([
        api.incidents.get(id),
        api.incidents.getNotes(id),
        api.incidents.getAlerts(id)
      ]);
      setIncident(incData);
      setNotes(notesData);
      setAlerts(alertsData);
    } catch (err) {
      console.error(err);
      setToast({ message: 'Failed to load incident details', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const handleStatusChange = async (newStatus) => {
    try {
      await api.incidents.update(id, { status: newStatus });
      setToast({ message: `Status updated to ${newStatus}`, type: 'success' });
      fetchData();
    } catch (err) {
      console.error(err);
      setToast({ message: 'Failed to update status', type: 'error' });
    }
  };

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    try {
      await api.incidents.addNote(id, { content: newNote, note_type: 'investigation' });
      setNewNote('');
      fetchData();
      setToast({ message: 'Note added successfully', type: 'success' });
    } catch (err) {
      console.error(err);
      setToast({ message: 'Failed to add note', type: 'error' });
    }
  };

  const handleExecuteSoar = async (action_type, target) => {
    try {
      setToast({ message: `Executing SOAR action: ${action_type.toUpperCase()}...`, type: 'info' });
      const res = await api.incidents.executeSoar(id, { action_type, target });
      setToast({ message: `SOAR Action Success: ${res.result_summary}`, type: 'success' });
      fetchData();
    } catch (err) {
      console.error(err);
      setToast({ message: `SOAR Execution failed: ${err.message}`, type: 'error' });
    }
  };

  if (loading) return <div className="animate-pulse p-4 font-mono text-text-muted">Loading incident details...</div>;
  if (!incident) return <div className="p-4 font-mono text-threat">Incident not found</div>;

  const currentStatusIndex = STATUS_FLOW.indexOf(incident.status);

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Header */}
      <div className="bg-card border border-border rounded p-6">
        <div className="flex flex-col md:flex-row justify-between items-start gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <span className="text-threat font-bold font-mono bg-threat/10 px-2 py-1 rounded text-xs border border-threat/20">
                INC-{incident.id.toString().padStart(4, '0')}
              </span>
              <span className={`px-2 py-1 rounded text-[10px] uppercase font-bold border ${
                incident.severity === 'CRITICAL' ? 'bg-threat/10 border-threat/30 text-threat' : 
                'bg-orange-500/10 border-orange-500/30 text-orange-400'
              }`}>
                {incident.severity}
              </span>
              <span className="text-text-muted text-xs font-mono flex items-center gap-1">
                <Clock className="w-3 h-3" /> {new Date(incident.created_at).toLocaleString()}
              </span>
            </div>
            <h1 className="text-2xl font-bold font-sans text-text-main mb-2">{incident.title}</h1>
            <p className="text-sm font-mono text-text-muted max-w-3xl leading-relaxed">
              {incident.description}
            </p>
          </div>
          
          <div className="flex flex-col items-end gap-2 shrink-0">
            <div className="flex items-center gap-2 bg-surface px-3 py-1.5 rounded border border-border">
              <User className="w-4 h-4 text-text-muted" />
              <span className="text-xs font-mono text-text-muted uppercase">Assigned to:</span>
              <span className="text-sm font-mono text-text-main font-bold">{incident.assigned_analyst || 'Unassigned'}</span>
            </div>
          </div>
        </div>

        {/* Status Pipeline */}
        <div className="mt-8 pt-6 border-t border-border">
          <h3 className="text-xs font-mono uppercase text-text-muted mb-4">Response Pipeline</h3>
          <div className="flex flex-wrap gap-2 items-center">
            {STATUS_FLOW.map((status, idx) => {
              const isPast = idx < currentStatusIndex;
              const isCurrent = idx === currentStatusIndex;
              
              let btnClass = "px-3 py-1.5 rounded text-[10px] font-mono uppercase font-bold border transition-colors ";
              if (isCurrent) {
                btnClass += "bg-blue-500/20 text-blue-400 border-blue-500/50 shadow-[0_0_10px_rgba(59,130,246,0.2)]";
              } else if (isPast) {
                btnClass += "bg-safe/10 text-safe border-safe/30";
              } else {
                btnClass += "bg-surface text-text-muted border-border hover:bg-card hover:text-text-main cursor-pointer";
              }

              return (
                <div key={status} className="flex items-center gap-2">
                  <button 
                    className={btnClass}
                    onClick={() => handleStatusChange(status)}
                    disabled={isCurrent || isPast}
                  >
                    {status}
                  </button>
                  {idx < STATUS_FLOW.length - 1 && (
                    <ArrowRight className={`w-3 h-3 ${isPast ? 'text-safe' : 'text-text-muted'}`} />
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Col: Alerts & Indicators */}
        <div className="lg:col-span-2 space-y-6">
          
          <div className="bg-card border border-border rounded overflow-hidden">
            <div className="p-4 border-b border-border bg-surface/50 flex justify-between items-center">
              <h3 className="font-mono text-sm uppercase text-text-main font-bold flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-threat" /> Correlated Alerts ({alerts.length})
              </h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr>
                    <th>Alert ID</th>
                    <th>Timestamp</th>
                    <th>Type</th>
                    <th>Source IP</th>
                    <th>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.map(alert => (
                    <tr key={alert.id} className="hover:bg-surface/50 transition">
                      <td className="w-16">
                        <Link href={`/alert-detail/${alert.id}`} className="text-blue-400 hover:underline">
                          ALT-{alert.id}
                        </Link>
                      </td>
                      <td className="text-xs text-text-muted">{new Date(alert.detected_at).toLocaleString()}</td>
                      <td className="font-bold text-threat text-xs">{alert.attack_type}</td>
                      <td>{alert.source_ip}</td>
                      <td>
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-threat/10 text-threat border border-threat/20">
                          {alert.risk_score}
                        </span>
                      </td>
                    </tr>
                  ))}
                  {alerts.length === 0 && (
                    <tr><td colSpan="5" className="text-center p-4 text-text-muted font-mono text-xs">No alerts linked.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div className="bg-card border border-border rounded p-4">
            <h3 className="font-mono text-sm uppercase text-text-main font-bold flex items-center gap-2 mb-4 pb-3 border-b border-border">
              <Activity className="w-4 h-4 text-warning" /> Affected Assets
            </h3>
            <div className="flex flex-wrap gap-2">
              {incident.affected_assets && incident.affected_assets.length > 0 ? (
                incident.affected_assets.map((asset, i) => (
                  <span key={i} className="px-3 py-1 bg-surface border border-border rounded text-xs font-mono text-text-main">
                    {asset}
                  </span>
                ))
              ) : (
                <span className="text-xs text-text-muted font-mono">None documented</span>
              )}
            </div>
          </div>

          {/* SOAR Remediation Playbooks */}
          <div className="bg-card border border-border rounded p-5">
            <div className="flex items-center justify-between mb-4 pb-3 border-b border-border">
              <h3 className="font-mono text-sm uppercase text-text-main font-bold flex items-center gap-2">
                <Terminal className="w-4 h-4 text-blue-400" />
                SOAR Automated Remediation Playbooks
              </h3>
              <span className="text-[10px] bg-blue-500/20 text-blue-400 border border-blue-500/30 px-2 py-0.5 rounded font-mono">
                1-CLICK RESPONSE
              </span>
            </div>
            <p className="text-xs text-text-muted mb-4 font-mono">
              Execute active containment and eradication playbooks against detected indicators.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <button
                onClick={() => handleExecuteSoar('block_ip', alerts[0]?.source_ip || 'Attacker-IP')}
                className="p-3 bg-surface hover:bg-threat/10 border border-border hover:border-threat/30 rounded text-left transition group"
              >
                <div className="flex items-center gap-2 font-mono text-xs font-bold text-threat mb-1">
                  🛡️ Block Attacker IP
                </div>
                <div className="text-[11px] text-text-muted group-hover:text-text-main">
                  Inject firewall DROP rule for {alerts[0]?.source_ip || 'threat IP'}.
                </div>
              </button>

              <button
                onClick={() => handleExecuteSoar('isolate_host', incident.affected_assets?.[0] || 'Target Endpoint')}
                className="p-3 bg-surface hover:bg-yellow-500/10 border border-border hover:border-yellow-500/30 rounded text-left transition group"
              >
                <div className="flex items-center gap-2 font-mono text-xs font-bold text-yellow-400 mb-1">
                  🔒 Isolate Host / Quarantine
                </div>
                <div className="text-[11px] text-text-muted group-hover:text-text-main">
                  Shift endpoint switch port to isolated VLAN 999.
                </div>
              </button>

              <button
                onClick={() => handleExecuteSoar('revoke_session', 'compromised_account')}
                className="p-3 bg-surface hover:bg-purple-500/10 border border-border hover:border-purple-500/30 rounded text-left transition group"
              >
                <div className="flex items-center gap-2 font-mono text-xs font-bold text-purple-400 mb-1">
                  🛑 Revoke User Sessions
                </div>
                <div className="text-[11px] text-text-muted group-hover:text-text-main">
                  Invalidate active JWT/OAuth tokens and force MFA reset.
                </div>
              </button>

              <button
                onClick={() => handleExecuteSoar('rate_limit', `Port ${alerts[0]?.port || '80/443'}`)}
                className="p-3 bg-surface hover:bg-blue-500/10 border border-border hover:border-blue-500/30 rounded text-left transition group"
              >
                <div className="flex items-center gap-2 font-mono text-xs font-bold text-blue-400 mb-1">
                  ⚡ Apply Rate Limiting
                </div>
                <div className="text-[11px] text-text-muted group-hover:text-text-main">
                  Apply token-bucket QoS rate limiter to mitigate flood.
                </div>
              </button>
            </div>
          </div>

        </div>

        {/* Right Col: Timeline & Notes */}
        <div className="bg-card border border-border rounded flex flex-col h-[600px]">
          <div className="p-4 border-b border-border bg-surface/50">
            <h3 className="font-mono text-sm uppercase text-text-main font-bold flex items-center gap-2">
              <MessageSquare className="w-4 h-4 text-blue-400" /> Investigation Timeline
            </h3>
          </div>
          
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {notes.map(note => (
              <div key={note.id} className={`p-3 rounded border ${
                note.note_type === 'timeline' ? 'bg-surface/50 border-border' : 
                'bg-blue-900/10 border-blue-500/20'
              }`}>
                <div className="flex justify-between items-start mb-2">
                  <span className="text-xs font-bold font-mono text-text-main flex items-center gap-1">
                    {note.note_type === 'timeline' ? <Terminal className="w-3 h-3 text-text-muted" /> : <User className="w-3 h-3 text-blue-400" />}
                    {note.author}
                  </span>
                  <span className="text-[10px] font-mono text-text-muted">
                    {new Date(note.created_at).toLocaleTimeString()}
                  </span>
                </div>
                <p className="text-sm font-sans text-text-main leading-relaxed">
                  {note.content}
                </p>
              </div>
            ))}
          </div>

          <div className="p-4 border-t border-border bg-surface/30">
            <form onSubmit={handleAddNote} className="flex flex-col gap-2">
              <textarea 
                value={newNote}
                onChange={(e) => setNewNote(e.target.value)}
                placeholder="Add investigation note or finding..."
                className="w-full bg-bg border border-border rounded p-3 text-sm text-text-main focus:outline-none focus:border-blue-500/50 font-sans resize-none h-24"
              />
              <div className="flex justify-end">
                <button 
                  type="submit"
                  disabled={!newNote.trim()}
                  className="px-4 py-2 bg-card border border-border hover:bg-surface rounded text-xs font-mono uppercase font-bold transition disabled:opacity-50"
                >
                  Post Note
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>

      {toast && (
        <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />
      )}
    </div>
  );
}
