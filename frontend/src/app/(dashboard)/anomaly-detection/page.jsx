'use client';

import { useState, useEffect } from 'react';
import { api } from '../../../lib/api';
import { ShieldAlert, Crosshair, Radar, Play, AlertCircle } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip } from 'recharts';

export default function AnomalyDetectionPage() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [detecting, setDetecting] = useState(false);
  const [detectionResults, setDetectionResults] = useState(null);

  useEffect(() => {
    fetchSummary();
  }, []);

  const fetchSummary = async () => {
    try {
      const data = await api.anomaly.getSummary();
      setSummary(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleRunDetection = async () => {
    setDetecting(true);
    setDetectionResults(null);
    try {
      const data = await api.anomaly.detect({ dataset: 'cicids2017', sample_size: 50 });
      setDetectionResults(data);
      fetchSummary(); // Refresh summary after detection
    } catch (err) {
      console.error(err);
    } finally {
      setDetecting(false);
    }
  };

  if (loading) {
    return <div className="animate-pulse text-text-muted font-mono">Initializing detection module...</div>;
  }

  // Format data for donut chart
  const donutData = summary ? Object.entries(summary.attack_distribution).map(([name, value], index) => {
    const colors = ['#FF3B3B', '#F59E0B', '#3B82F6', '#8B5CF6', '#EC4899', '#10B981'];
    return { name, value, color: colors[index % colors.length] };
  }) : [];

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center bg-card border border-border p-4 rounded">
        <div>
          <h2 className="text-lg font-bold font-mono text-text-main flex items-center gap-2">
            <Radar className="w-5 h-5 text-threat animate-pulse" />
            AI Threat Detection Engine
          </h2>
          <p className="text-xs text-text-muted font-mono mt-1 uppercase">Run real-time inference on network telemetry</p>
        </div>
        <button
          onClick={handleRunDetection}
          disabled={detecting}
          className={`flex items-center gap-2 px-4 py-2 rounded font-bold font-mono text-sm uppercase tracking-wider transition ${
            detecting ? 'bg-surface text-text-muted cursor-not-allowed' : 'bg-threat text-white hover:bg-red-600'
          }`}
        >
          {detecting ? (
            <><div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" /> Analyzing...</>
          ) : (
            <><Play className="w-4 h-4 fill-current" /> Run Scan</>
          )}
        </button>
      </div>

      {detectionResults && (
        <div className="bg-threat/5 border border-threat/20 rounded p-4 flex items-start gap-3">
          <ShieldAlert className="w-5 h-5 text-threat shrink-0 mt-0.5" />
          <div>
            <h4 className="font-bold font-mono text-threat text-sm uppercase mb-1">Scan Complete</h4>
            <p className="text-xs font-mono text-text-main">
              Analyzed {detectionResults.total_analyzed} records. 
              Found <span className="font-bold text-threat">{detectionResults.anomalies_detected} anomalies</span>. 
              Created {detectionResults.new_alerts_created} new alerts.
            </p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Classification Donut */}
        <div className="bg-card border border-border rounded p-5 flex flex-col">
          <h3 className="font-mono text-sm uppercase text-text-muted mb-4 flex items-center gap-2">
            <Crosshair className="w-4 h-4" /> Threat Classification
          </h3>
          <div className="flex-1 min-h-[250px] relative">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={donutData}
                  cx="50%"
                  cy="50%"
                  innerRadius={70}
                  outerRadius={90}
                  paddingAngle={2}
                  dataKey="value"
                  stroke="none"
                >
                  {donutData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <RechartsTooltip 
                  contentStyle={{ backgroundColor: '#1A1A1A', border: '1px solid #333', borderRadius: '4px', fontFamily: 'JetBrains Mono' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-2 mt-4 text-xs font-mono">
            {donutData.map((entry, i) => (
              <div key={i} className="flex items-center gap-2 truncate">
                <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: entry.color }}></span> 
                <span className="truncate" title={entry.name}>{entry.name}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Real-time Insights Table */}
        <div className="lg:col-span-2 bg-card border border-border rounded overflow-hidden flex flex-col">
          <div className="p-4 border-b border-border bg-surface/50 flex justify-between items-center">
            <h3 className="font-mono text-sm uppercase text-text-main font-bold">Real-Time Threat Detection Insights</h3>
            <span className="text-[10px] uppercase bg-threat/10 text-threat border border-threat/20 px-2 py-0.5 rounded animate-pulse">Live</span>
          </div>
          <div className="overflow-x-auto flex-1">
            <table className="w-full text-left">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Target IP</th>
                  <th>Predicted Threat</th>
                  <th>Confidence</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {summary?.recent_detections.map((alert, idx) => (
                  <tr key={idx} className={alert.severity === 'CRITICAL' ? 'flagged-threat' : ''}>
                    <td className="text-text-muted whitespace-nowrap">{new Date(alert.detected_at).toLocaleTimeString()}</td>
                    <td className={alert.severity === 'CRITICAL' ? 'text-threat font-bold' : ''}>{alert.source_ip}</td>
                    <td>{alert.dest_ip}</td>
                    <td className="font-bold text-threat">{alert.attack_type}</td>
                    <td>
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-surface rounded overflow-hidden">
                          <div 
                            className={`h-full ${alert.confidence > 0.9 ? 'bg-threat' : 'bg-yellow-500'}`} 
                            style={{ width: `${alert.confidence * 100}%` }}
                          />
                        </div>
                        <span className="text-xs">{(alert.confidence * 100).toFixed(1)}%</span>
                      </div>
                    </td>
                    <td>
                      <span className="px-2 py-0.5 rounded text-[10px] uppercase border bg-threat/10 text-threat border-threat/20">
                        {alert.status === 'open' ? 'Blocked' : 'Logged'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
