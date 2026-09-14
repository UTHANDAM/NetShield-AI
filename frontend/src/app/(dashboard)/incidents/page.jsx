'use client';

import { useState, useEffect } from 'react';
import { api } from '../../../lib/api';
import { Search, Filter, ShieldAlert, Activity, CheckCircle, Clock } from 'lucide-react';
import Link from 'next/link';

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [search, setSearch] = useState('');

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000); // Auto-refresh every 10s
    return () => clearInterval(interval);
  }, [statusFilter, severityFilter]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [listData, metricsData] = await Promise.all([
        api.incidents.list({ status: statusFilter || undefined, severity: severityFilter || undefined, search: search || undefined }),
        api.incidents.getMetrics()
      ]);
      setIncidents(listData);
      setMetrics(metricsData);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e) => {
    if (e.key === 'Enter') {
      fetchData();
    }
  };

  const severityColors = {
    CRITICAL: 'bg-threat/10 border-threat/30 text-threat',
    HIGH: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
    MEDIUM: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400',
    LOW: 'bg-blue-500/10 border-blue-500/30 text-blue-400',
  };

  const statusColors = {
    detection: 'bg-threat/10 text-threat border-threat/30',
    triage: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
    investigation: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
    containment: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    eradication: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
    recovery: 'bg-teal-500/10 text-teal-400 border-teal-500/30',
    resolution: 'bg-safe/10 text-safe border-safe/30',
    closed: 'bg-surface text-text-muted border-border',
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center bg-card border border-border p-4 rounded gap-4 flex-wrap">
        <div className="flex items-center gap-4 flex-1">
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
            <input 
              type="text" 
              placeholder="Search incidents..." 
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={handleSearch}
              className="w-full bg-surface border border-border rounded pl-9 pr-4 py-2 text-sm text-text-main focus:outline-none focus:border-threat/50"
            />
          </div>
          <select 
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-surface border border-border rounded px-4 py-2 text-sm text-text-main focus:outline-none focus:border-threat/50 appearance-none"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select 
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-surface border border-border rounded px-4 py-2 text-sm text-text-main focus:outline-none focus:border-threat/50 appearance-none"
          >
            <option value="">All Statuses</option>
            <option value="detection">Detection</option>
            <option value="triage">Triage</option>
            <option value="investigation">Investigation</option>
            <option value="containment">Containment</option>
            <option value="resolution">Resolution</option>
            <option value="closed">Closed</option>
          </select>
        </div>
        <button className="px-4 py-2 bg-threat text-white font-bold font-mono text-sm uppercase rounded hover:bg-red-600 transition shadow-[0_0_15px_rgba(255,59,59,0.3)] flex items-center gap-2">
          <ShieldAlert className="w-4 h-4" /> Create Incident
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-card border border-border rounded p-4 relative overflow-hidden">
          <div className="flex justify-between items-start mb-2">
            <h3 className="text-xs font-mono uppercase text-text-muted">Total Incidents</h3>
            <ShieldAlert className="w-4 h-4 text-text-muted" />
          </div>
          <p className="text-2xl font-bold font-mono text-text-main mt-2">{metrics?.total || 0}</p>
        </div>
        <div className="bg-card border border-threat/30 rounded p-4 relative overflow-hidden shadow-[0_0_10px_rgba(255,59,59,0.05)]">
          <div className="flex justify-between items-start mb-2">
            <h3 className="text-xs font-mono uppercase text-threat">Active Investigations</h3>
            <Activity className="w-4 h-4 text-threat" />
          </div>
          <p className="text-2xl font-bold font-mono text-threat mt-2">{metrics?.active || 0}</p>
        </div>
        <div className="bg-card border border-safe/30 rounded p-4 relative overflow-hidden">
          <div className="flex justify-between items-start mb-2">
            <h3 className="text-xs font-mono uppercase text-safe">Resolved</h3>
            <CheckCircle className="w-4 h-4 text-safe" />
          </div>
          <p className="text-2xl font-bold font-mono text-safe mt-2">{metrics?.by_status?.resolution || 0}</p>
        </div>
        <div className="bg-card border border-border rounded p-4 relative overflow-hidden">
          <div className="flex justify-between items-start mb-2">
            <h3 className="text-xs font-mono uppercase text-text-muted">MTTR (Avg)</h3>
            <Clock className="w-4 h-4 text-blue-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-blue-400 mt-2">{metrics?.mttr_hours ? `${metrics.mttr_hours}h` : 'N/A'}</p>
        </div>
      </div>

      <div className="bg-card border border-border rounded flex flex-col overflow-hidden">
        <div className="p-4 border-b border-border bg-surface/50">
          <h3 className="font-mono text-sm uppercase text-text-main font-bold">Incident Response Log</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr>
                <th>ID</th>
                <th>Title & Category</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Assigned To</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan="6" className="text-center p-8 text-text-muted">Loading incidents...</td></tr>
              ) : incidents.length === 0 ? (
                <tr><td colSpan="6" className="text-center p-8 text-text-muted font-mono">No incidents found</td></tr>
              ) : (
                incidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-surface/50 cursor-pointer group transition-colors">
                    <td className="w-16">
                      <Link href={`/incidents/${inc.id}`} className="text-blue-400 hover:underline">
                        INC-{inc.id.toString().padStart(4, '0')}
                      </Link>
                    </td>
                    <td>
                      <div className="font-sans font-medium text-text-main group-hover:text-white mb-1">
                        <Link href={`/incidents/${inc.id}`}>{inc.title}</Link>
                      </div>
                      <div className="text-xs text-text-muted">{inc.attack_category || 'General'}</div>
                    </td>
                    <td>
                      <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${severityColors[inc.severity]}`}>
                        {inc.severity}
                      </span>
                    </td>
                    <td>
                      <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${statusColors[inc.status] || statusColors.closed}`}>
                        {inc.status}
                      </span>
                    </td>
                    <td className="text-text-muted">{inc.assigned_analyst || 'Unassigned'}</td>
                    <td className="text-text-muted text-xs">{new Date(inc.created_at).toLocaleString()}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
