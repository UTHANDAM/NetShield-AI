'use client';

import { useState, useEffect } from 'react';
import { api } from '../../../../lib/api';
import { useParams } from 'next/navigation';
import { 
  ShieldAlert, Clock, User, Server, Network, 
  Activity, ArrowRight, Crosshair, MapPin
} from 'lucide-react';
import Link from 'next/link';
import Toast from '../../../../components/ui/Toast';

const STATUS_FLOW = ['new', 'acknowledged', 'investigating', 'escalated', 'resolved', 'closed'];

export default function AlertDetailPage() {
  const params = useParams();
  const id = params.id;

  const [alert, setAlert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [notes, setNotes] = useState('');
  const [toast, setToast] = useState(null);
  const [isUpdating, setIsUpdating] = useState(false);

  useEffect(() => {
    fetchAlert();
  }, [id]);

  const fetchAlert = async () => {
    try {
      const data = await api.alerts.getAlert(id);
      setAlert(data);
      setNotes(data.notes || '');
    } catch (err) {
      console.error(err);
      setToast({ message: 'Failed to load alert details', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const handleStatusChange = async (newStatus) => {
    try {
      await api.alerts.updateStatus(id, newStatus);
      setToast({ message: `Status updated to ${newStatus}`, type: 'success' });
      fetchAlert();
    } catch (err) {
      console.error(err);
      setToast({ message: 'Failed to update status', type: 'error' });
    }
  };

  const handleSaveNotes = async () => {
    setIsUpdating(true);
    try {
      await api.alerts.updateAlert(id, { notes });
      setToast({ message: 'Notes saved successfully', type: 'success' });
    } catch (err) {
      console.error(err);
      setToast({ message: 'Failed to save notes', type: 'error' });
    } finally {
      setIsUpdating(false);
    }
  };

  if (loading) return <div className="animate-pulse p-4 font-mono text-text-muted">Loading alert details...</div>;
  if (!alert) return <div className="p-4 font-mono text-threat">Alert not found</div>;

  const currentStatusIndex = STATUS_FLOW.indexOf(alert.status);

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Header */}
      <div className="bg-card border border-border rounded p-6">
        <div className="flex flex-col md:flex-row justify-between items-start gap-4">
          <div>
            <div className="flex items-center gap-3 mb-3">
              <span className="text-blue-400 font-bold font-mono bg-blue-500/10 px-2 py-1 rounded text-xs border border-blue-500/20">
                ALT-{alert.id.toString().padStart(5, '0')}
              </span>
              <span className={`px-2 py-1 rounded text-[10px] uppercase font-bold border ${
                alert.severity === 'CRITICAL' ? 'bg-threat/10 border-threat/30 text-threat' : 
                alert.severity === 'HIGH' ? 'bg-orange-500/10 border-orange-500/30 text-orange-400' :
                'bg-yellow-500/10 border-yellow-500/30 text-yellow-400'
              }`}>
                {alert.severity}
              </span>
              <span className="text-text-muted text-xs font-mono flex items-center gap-1">
                <Clock className="w-3 h-3" /> Detected: {new Date(alert.detected_at).toLocaleString()}
              </span>
            </div>
            <h1 className="text-3xl font-bold font-mono text-threat mb-1 flex items-center gap-3">
              <ShieldAlert className="w-6 h-6" /> {alert.attack_type}
            </h1>
            <p className="text-sm font-mono text-text-muted">Dataset Source: <span className="uppercase">{alert.dataset_source}</span></p>
          </div>
          
          <div className="flex flex-col items-end gap-2 shrink-0">
            <div className="flex flex-col items-end bg-surface p-3 rounded border border-border">
              <span className="text-[10px] font-mono text-text-muted uppercase mb-1">Risk Score</span>
              <span className="text-3xl font-bold font-mono text-white leading-none">{alert.risk_score}</span>
              <div className="w-full bg-bg h-1.5 mt-2 rounded overflow-hidden">
                <div className={`h-full ${alert.risk_score > 80 ? 'bg-threat' : 'bg-orange-500'}`} style={{ width: `${alert.risk_score}%` }}></div>
              </div>
            </div>
          </div>
        </div>

        {/* Status Pipeline */}
        <div className="mt-8 pt-6 border-t border-border">
          <h3 className="text-xs font-mono uppercase text-text-muted mb-4">Alert Lifecycle</h3>
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

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Network Context */}
        <div className="bg-card border border-border rounded p-6">
          <h3 className="font-mono text-sm uppercase text-text-main font-bold flex items-center gap-2 mb-6 border-b border-border pb-3">
            <Network className="w-4 h-4 text-blue-400" /> Network Context
          </h3>
          
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-mono uppercase text-text-muted mb-1 flex items-center gap-1"><Crosshair className="w-3 h-3" /> Source IP</p>
                <p className="font-mono text-lg text-threat font-bold">{alert.source_ip}</p>
              </div>
              <ArrowRight className="w-5 h-5 text-text-muted mx-4" />
              <div className="text-right">
                <p className="text-xs font-mono uppercase text-text-muted mb-1 flex items-center justify-end gap-1"><MapPin className="w-3 h-3" /> Destination IP</p>
                <p className="font-mono text-lg text-safe font-bold">{alert.dest_ip}</p>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 border-t border-border pt-4">
              <div>
                <p className="text-[10px] font-mono uppercase text-text-muted mb-1">Target Port</p>
                <p className="font-mono text-white">{alert.port || 'N/A'}</p>
              </div>
              <div>
                <p className="text-[10px] font-mono uppercase text-text-muted mb-1">Protocol</p>
                <p className="font-mono text-white uppercase">{alert.protocol || 'N/A'}</p>
              </div>
              <div>
                <p className="text-[10px] font-mono uppercase text-text-muted mb-1">ML Confidence</p>
                <p className="font-mono text-white">{(alert.confidence * 100).toFixed(2)}%</p>
              </div>
              <div>
                <p className="text-[10px] font-mono uppercase text-text-muted mb-1">MITRE Technique</p>
                <p className="font-mono text-white">{alert.mitre_technique || 'N/A'}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Investigation & Notes */}
        <div className="bg-card border border-border rounded flex flex-col">
          <div className="p-4 border-b border-border bg-surface/50 flex justify-between items-center">
            <h3 className="font-mono text-sm uppercase text-text-main font-bold flex items-center gap-2">
              <User className="w-4 h-4 text-warning" /> Analyst Workspace
            </h3>
          </div>
          
          <div className="p-4 flex-1 flex flex-col gap-4">
            {alert.incident_id && (
              <div className="bg-blue-900/20 border border-blue-500/30 rounded p-3 flex justify-between items-center">
                <div>
                  <p className="text-xs font-mono uppercase text-blue-400 mb-1">Linked Incident</p>
                  <p className="text-sm font-bold text-white">INC-{alert.incident_id.toString().padStart(4, '0')}</p>
                </div>
                <Link href={`/incidents/${alert.incident_id}`}>
                  <button className="px-3 py-1.5 bg-blue-500 text-white rounded text-xs font-mono uppercase font-bold hover:bg-blue-600 transition">
                    View
                  </button>
                </Link>
              </div>
            )}

            <div className="flex-1 flex flex-col">
              <label className="text-xs font-mono uppercase text-text-muted mb-2">Investigation Notes</label>
              <textarea 
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Document findings, IOCs, or response actions taken..."
                className="flex-1 min-h-[150px] bg-bg border border-border rounded p-3 text-sm text-text-main focus:outline-none focus:border-blue-500/50 font-sans resize-none"
              />
              <div className="flex justify-end mt-3">
                <button 
                  onClick={handleSaveNotes}
                  disabled={isUpdating}
                  className="px-4 py-2 bg-surface border border-border hover:bg-card rounded text-xs font-mono uppercase font-bold transition flex items-center gap-2"
                >
                  {isUpdating ? 'Saving...' : 'Save Notes'}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {toast && (
        <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />
      )}
    </div>
  );
}
