'use client';

import { useState, useEffect } from 'react';
import { api } from '../../../lib/api';
import { AlertTriangle, ShieldOff, ShieldAlert, CheckCircle, Clock, ArrowRight } from 'lucide-react';
import Link from 'next/link';

export default function ThreatAlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [alertsData, statsData] = await Promise.all([
        api.alerts.getAlerts({ limit: 100 }),
        api.alerts.getStats()
      ]);
      setAlerts(alertsData);
      setStats(statsData);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const updateStatus = async (id, status) => {
    try {
      await api.alerts.updateStatus(id, status);
      fetchData();
    } catch (err) {
      console.error(err);
    }
  };

  if (loading) {
    return <div className="animate-pulse text-text-muted font-mono">Loading alerts...</div>;
  }

  return (
    <div className="space-y-6">
      {/* Alert Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <StatCard title="Total Open" value={stats.open_count} icon={AlertTriangle} color="text-text-main" />
          <StatCard title="Critical" value={stats.critical} icon={ShieldOff} color="text-threat" bg="bg-threat/10" border="border-threat/30" />
          <StatCard title="High" value={stats.high} icon={ShieldAlert} color="text-orange-500" bg="bg-orange-500/10" border="border-orange-500/30" />
          <StatCard title="Medium" value={stats.medium} icon={AlertTriangle} color="text-yellow-500" bg="bg-yellow-500/10" border="border-yellow-500/30" />
          <StatCard title="Low" value={stats.low} icon={CheckCircle} color="text-blue-400" bg="bg-blue-400/10" border="border-blue-400/30" />
        </div>
      )}

      {/* Alerts Table */}
      <div className="bg-card border border-border rounded overflow-hidden">
        <div className="p-4 border-b border-border bg-surface/50">
          <h3 className="font-mono text-sm uppercase text-text-main font-bold">Active Threat Alerts</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Time Detected</th>
                <th>Source IP</th>
                <th>Destination</th>
                <th>Threat Signature</th>
                <th>Risk Score</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr key={alert.id} className={alert.severity === 'CRITICAL' ? 'flagged-threat' : ''}>
                  <td>
                    <span className={`px-2 py-0.5 rounded text-[10px] uppercase border font-bold ${
                      alert.severity === 'CRITICAL' ? 'bg-threat/10 text-threat border-threat/30' :
                      alert.severity === 'HIGH' ? 'bg-orange-500/10 text-orange-500 border-orange-500/30' :
                      alert.severity === 'MEDIUM' ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/30' :
                      'bg-blue-400/10 text-blue-400 border-blue-400/30'
                    }`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td className="text-text-muted whitespace-nowrap">
                    <div className="flex items-center gap-1.5">
                      <Clock className="w-3 h-3" />
                      {new Date(alert.detected_at).toLocaleString()}
                    </div>
                  </td>
                  <td className="font-mono">{alert.source_ip}</td>
                  <td className="font-mono">{alert.dest_ip}:{alert.port}</td>
                  <td className="font-bold">{alert.attack_type}</td>
                  <td>
                    <div className="flex items-center gap-2">
                      <span className={`font-mono font-bold ${alert.risk_score >= 80 ? 'text-threat' : alert.risk_score >= 60 ? 'text-yellow-500' : 'text-safe'}`}>
                        {alert.risk_score}
                      </span>
                      <div className="w-12 h-1 bg-surface rounded overflow-hidden">
                        <div 
                          className={`h-full ${alert.risk_score >= 80 ? 'bg-threat' : alert.risk_score >= 60 ? 'bg-yellow-500' : 'bg-safe'}`} 
                          style={{ width: `${alert.risk_score}%` }}
                        />
                      </div>
                    </div>
                  </td>
                  <td>
                    <span className="text-[10px] font-mono uppercase text-text-muted px-2 py-0.5 border border-border rounded bg-surface">
                      {alert.status}
                    </span>
                  </td>
                  <td>
                    <Link href={`/alert-detail/${alert.id}`}>
                      <button className="text-[10px] font-mono uppercase px-3 py-1.5 bg-blue-500/20 text-blue-400 border border-blue-500/50 rounded hover:bg-blue-500/40 transition flex items-center gap-1">
                        Investigate <ArrowRight className="w-3 h-3" />
                      </button>
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {alerts.length === 0 && (
            <div className="p-8 text-center text-text-muted font-mono">
              No alerts found. System is secure.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function StatCard({ title, value, icon: Icon, color, bg = "bg-surface", border = "border-border" }) {
  return (
    <div className={`bg-card border ${border} rounded p-4 relative overflow-hidden`}>
      <div className="flex justify-between items-start mb-2">
        <h3 className="text-[10px] font-mono uppercase text-text-muted">{title}</h3>
        <div className={`p-1.5 rounded ${bg} ${color}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>
      <p className={`text-2xl font-bold font-mono ${color}`}>{value}</p>
    </div>
  );
}
