'use client';

import { useState, useEffect } from 'react';
import { api } from '../../../lib/api';
import { Search, ShieldAlert, Crosshair, MapPin, Database, Globe, Hash, AlertTriangle, ExternalLink, Shield, Terminal, Plus, Trash2 } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip, Legend } from 'recharts';

export default function ThreatIntelligencePage() {
  const [activeTab, setActiveTab] = useState('mitre'); // 'mitre' | 'iocs' | 'rules'
  const [summary, setSummary] = useState(null);
  const [indicators, setIndicators] = useState([]);
  const [mitreData, setMitreData] = useState(null);
  const [detectionRules, setDetectionRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [ruleEngineFilter, setRuleEngineFilter] = useState('');

  useEffect(() => {
    fetchData();
  }, [typeFilter, ruleEngineFilter, activeTab]);

  const fetchData = async () => {
    setLoading(true);
    try {
      if (activeTab === 'mitre') {
        const data = await api.threatIntel.getMitreMatrix();
        setMitreData(data);
      } else if (activeTab === 'rules') {
        const data = await api.threatIntel.getDetectionRules({ engine: ruleEngineFilter || undefined });
        setDetectionRules(data);
      } else {
        const [sumData, indData] = await Promise.all([
          api.threatIntel.getSummary(),
          api.threatIntel.getIndicators({ indicator_type: typeFilter || undefined, search: search || undefined })
        ]);
        setSummary(sumData);
        setIndicators(indData);
      }
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

  const getTypeIcon = (type) => {
    switch(type) {
      case 'ip': return <MapPin className="w-4 h-4 text-blue-400" />;
      case 'domain': return <Globe className="w-4 h-4 text-purple-400" />;
      case 'hash': return <Hash className="w-4 h-4 text-orange-400" />;
      case 'url': return <ExternalLink className="w-4 h-4 text-teal-400" />;
      case 'malware': return <Crosshair className="w-4 h-4 text-threat" />;
      default: return <Database className="w-4 h-4 text-text-muted" />;
    }
  };

  const severityColors = {
    CRITICAL: 'bg-threat/10 text-threat border-threat/30',
    HIGH: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
    MEDIUM: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
    LOW: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
  };

  const COLORS = ['#FF3B3B', '#F59E0B', '#3B82F6', '#8B5CF6', '#EC4899', '#10B981'];
  const typeChartData = summary ? Object.entries(summary.by_type).map(([name, value]) => ({ name: name.toUpperCase(), value })) : [];

  return (
    <div className="space-y-6">
      {/* Header Tabs */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-card border border-border p-4 rounded">
        <div>
          <h2 className="text-xl font-bold font-sans text-text-main flex items-center gap-2">
            <Shield className="w-5 h-5 text-blue-400" /> Threat Intelligence & MITRE ATT&CK
          </h2>
          <p className="text-xs text-text-muted font-mono mt-1">
            Correlate enterprise attack tactics, telemetry indicators of compromise, and SIEM detection rules.
          </p>
        </div>

        {/* Tab Buttons */}
        <div className="flex bg-surface p-1 rounded border border-border">
          <button
            onClick={() => setActiveTab('mitre')}
            className={`px-3 py-1.5 rounded text-xs font-mono font-bold transition ${
              activeTab === 'mitre' ? 'bg-blue-500 text-white' : 'text-text-muted hover:text-text-main'
            }`}
          >
            MITRE ATT&CK Matrix
          </button>
          <button
            onClick={() => setActiveTab('iocs')}
            className={`px-3 py-1.5 rounded text-xs font-mono font-bold transition ${
              activeTab === 'iocs' ? 'bg-blue-500 text-white' : 'text-text-muted hover:text-text-main'
            }`}
          >
            IOC Database
          </button>
          <button
            onClick={() => setActiveTab('rules')}
            className={`px-3 py-1.5 rounded text-xs font-mono font-bold transition ${
              activeTab === 'rules' ? 'bg-blue-500 text-white' : 'text-text-muted hover:text-text-main'
            }`}
          >
            Detection Rules
          </button>
        </div>
      </div>

      {/* TAB 1: MITRE ATT&CK MATRIX */}
      {activeTab === 'mitre' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="bg-card border border-border rounded p-4">
              <span className="text-xs font-mono uppercase text-text-muted">Enterprise Tactics</span>
              <p className="text-2xl font-bold font-mono text-text-main mt-1">{mitreData?.total_tactics || 7}</p>
            </div>
            <div className="bg-card border border-border rounded p-4">
              <span className="text-xs font-mono uppercase text-text-muted">Mapped Techniques</span>
              <p className="text-2xl font-bold font-mono text-blue-400 mt-1">{mitreData?.total_techniques || 14}</p>
            </div>
            <div className="bg-card border border-threat/30 rounded p-4">
              <span className="text-xs font-mono uppercase text-threat">Active Attack Hits</span>
              <p className="text-2xl font-bold font-mono text-threat mt-1">{mitreData?.active_threat_hits || 1105}</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {(mitreData?.tactics || []).map((tactic) => (
              <div key={tactic.id} className="bg-card border border-border rounded flex flex-col overflow-hidden">
                <div className="p-3 bg-surface border-b border-border flex justify-between items-center">
                  <div>
                    <span className="text-[10px] font-mono text-blue-400 font-bold">{tactic.id}</span>
                    <h4 className="text-xs font-bold text-text-main uppercase font-mono">{tactic.name}</h4>
                  </div>
                  <span className="text-[10px] bg-border px-1.5 py-0.5 rounded font-mono text-text-muted">
                    {tactic.techniques.length}
                  </span>
                </div>
                <div className="p-3 space-y-2 flex-1">
                  {tactic.techniques.map((tech) => (
                    <div
                      key={tech.id}
                      className="p-2.5 bg-surface/60 hover:bg-surface border border-border/60 hover:border-blue-500/40 rounded transition group"
                    >
                      <div className="flex justify-between items-start mb-1">
                        <span className="text-[10px] font-mono text-text-muted group-hover:text-blue-400 font-bold">
                          {tech.id}
                        </span>
                        <span className={`px-1.5 py-0.2 rounded text-[9px] font-mono uppercase font-bold border ${severityColors[tech.severity] || severityColors.LOW}`}>
                          {tech.severity}
                        </span>
                      </div>
                      <p className="text-xs text-text-main font-sans font-medium mb-1.5">{tech.name}</p>
                      <div className="flex justify-between items-center text-[10px] font-mono text-text-muted">
                        <span>Active Telemetry</span>
                        <span className="text-threat font-bold">{tech.active_hits} events</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 2: IOC DATABASE */}
      {activeTab === 'iocs' && (
        <div className="space-y-6">
          <div className="flex justify-between items-center bg-card border border-border p-4 rounded gap-4 flex-wrap">
            <div className="flex items-center gap-4 flex-1">
              <div className="relative flex-1 max-w-md">
                <Search className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
                <input 
                  type="text" 
                  placeholder="Search indicators of compromise (IOCs)..." 
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  onKeyDown={handleSearch}
                  className="w-full bg-surface border border-border rounded pl-9 pr-4 py-2 text-sm text-text-main focus:outline-none focus:border-threat/50"
                />
              </div>
              <select 
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="bg-surface border border-border rounded px-4 py-2 text-sm text-text-main focus:outline-none focus:border-threat/50 appearance-none"
              >
                <option value="">All Types</option>
                <option value="ip">IP Address</option>
                <option value="domain">Domain</option>
                <option value="hash">File Hash (MD5/SHA)</option>
                <option value="url">URL</option>
                <option value="malware">Malware Sig</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-card border border-border rounded p-4">
                  <h3 className="text-[10px] font-mono uppercase text-text-muted mb-1">Total IOCs</h3>
                  <p className="text-2xl font-bold font-mono text-text-main">{summary?.total_indicators || 0}</p>
                </div>
                <div className="bg-card border border-threat/30 rounded p-4">
                  <h3 className="text-[10px] font-mono uppercase text-threat mb-1">Active Threats</h3>
                  <p className="text-2xl font-bold font-mono text-threat">{summary?.active_indicators || 0}</p>
                </div>
              </div>

              <div className="bg-card border border-border rounded p-4 flex flex-col">
                <h3 className="font-mono text-sm uppercase text-text-main font-bold mb-4 flex items-center gap-2">
                  <Database className="w-4 h-4 text-text-muted" /> IOC Distribution
                </h3>
                <div className="flex-1 min-h-[200px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={typeChartData}
                        cx="50%" cy="50%"
                        innerRadius={50} outerRadius={70}
                        paddingAngle={2}
                        dataKey="value" stroke="none"
                      >
                        {typeChartData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <RechartsTooltip contentStyle={{ backgroundColor: '#1A1A1A', border: '1px solid #333' }} />
                      <Legend iconType="circle" wrapperStyle={{ fontSize: '10px', fontFamily: 'monospace' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            <div className="lg:col-span-2 bg-card border border-border rounded flex flex-col overflow-hidden">
              <div className="p-4 border-b border-border bg-surface/50">
                <h3 className="font-mono text-sm uppercase text-text-main font-bold">Threat Indicator Database</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <thead>
                    <tr>
                      <th>Indicator</th>
                      <th>Value</th>
                      <th>Category</th>
                      <th>Severity</th>
                      <th>Confidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {loading ? (
                      <tr><td colSpan="5" className="text-center p-8 text-text-muted">Loading indicators...</td></tr>
                    ) : indicators.length === 0 ? (
                      <tr><td colSpan="5" className="text-center p-8 text-text-muted font-mono">No indicators found</td></tr>
                    ) : (
                      indicators.map((ind) => (
                        <tr key={ind.id} className="hover:bg-surface/50 transition-colors">
                          <td>
                            <div className="flex items-center gap-2">
                              {getTypeIcon(ind.indicator_type)}
                              <span className="text-[10px] font-bold uppercase text-text-muted">{ind.indicator_type}</span>
                            </div>
                          </td>
                          <td className="font-mono font-bold text-sm text-text-main max-w-[200px] truncate" title={ind.value}>
                            {ind.value}
                          </td>
                          <td>
                            <span className="text-xs text-text-muted">{ind.threat_category || 'Unknown'}</span>
                          </td>
                          <td>
                            <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${severityColors[ind.severity] || severityColors.LOW}`}>
                              {ind.severity}
                            </span>
                          </td>
                          <td>
                            <div className="flex items-center gap-2">
                              <div className="w-12 h-1.5 bg-surface rounded overflow-hidden">
                                <div 
                                  className={`h-full ${ind.confidence > 0.9 ? 'bg-threat' : 'bg-warning'}`} 
                                  style={{ width: `${ind.confidence * 100}%` }}
                                />
                              </div>
                              <span className="text-xs text-text-muted">{(ind.confidence * 100).toFixed(0)}%</span>
                            </div>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: DETECTION RULES */}
      {activeTab === 'rules' && (
        <div className="space-y-6">
          <div className="flex justify-between items-center bg-card border border-border p-4 rounded gap-4 flex-wrap">
            <div className="flex items-center gap-4">
              <select 
                value={ruleEngineFilter}
                onChange={(e) => setRuleEngineFilter(e.target.value)}
                className="bg-surface border border-border rounded px-4 py-2 text-sm text-text-main focus:outline-none focus:border-threat/50 appearance-none"
              >
                <option value="">All Engines (Suricata, Zeek, YARA, Custom AI)</option>
                <option value="Suricata">Suricata</option>
                <option value="Zeek">Zeek</option>
                <option value="YARA">YARA</option>
                <option value="Custom AI">Custom AI</option>
              </select>
            </div>
            <button className="px-4 py-2 bg-blue-500 text-white font-bold font-mono text-sm uppercase rounded hover:bg-blue-600 transition flex items-center gap-2">
              <Plus className="w-4 h-4" /> Add Detection Rule
            </button>
          </div>

          <div className="bg-card border border-border rounded flex flex-col overflow-hidden">
            <div className="p-4 border-b border-border bg-surface/50">
              <h3 className="font-mono text-sm uppercase text-text-main font-bold">Configured SIEM / NIDS Rule Signatures</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr>
                    <th>Rule Name</th>
                    <th>Engine</th>
                    <th>Signature / Pattern</th>
                    <th>Severity</th>
                    <th>Hit Count</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {loading ? (
                    <tr><td colSpan="6" className="text-center p-8 text-text-muted">Loading detection rules...</td></tr>
                  ) : detectionRules.length === 0 ? (
                    <tr><td colSpan="6" className="text-center p-8 text-text-muted font-mono">No detection rules found</td></tr>
                  ) : (
                    detectionRules.map((rule) => (
                      <tr key={rule.id} className="hover:bg-surface/50 transition-colors">
                        <td>
                          <div className="font-bold text-sm text-text-main">{rule.name}</div>
                          <div className="text-xs text-text-muted">{rule.description}</div>
                        </td>
                        <td>
                          <span className="px-2 py-0.5 bg-surface border border-border rounded text-xs font-mono text-blue-400 font-bold">
                            {rule.engine_type}
                          </span>
                        </td>
                        <td>
                          <code className="text-[11px] font-mono bg-bg/80 border border-border/50 px-2 py-1 rounded text-text-muted block max-w-xs truncate" title={rule.pattern}>
                            {rule.pattern}
                          </code>
                        </td>
                        <td>
                          <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${severityColors[rule.severity] || severityColors.LOW}`}>
                            {rule.severity}
                          </span>
                        </td>
                        <td>
                          <span className="font-mono font-bold text-sm text-text-main">{rule.hit_count} hits</span>
                        </td>
                        <td>
                          <span className="px-2 py-0.5 bg-safe/10 text-safe border border-safe/30 rounded text-xs font-mono font-bold">
                            Active
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

