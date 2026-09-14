'use client';

import { useState, useEffect } from 'react';
import { api } from '../../../lib/api';
import { Shield, AlertTriangle, Activity, Database, ArrowUpRight, ArrowDownRight } from 'lucide-react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  PieChart, Pie, Cell
} from 'recharts';

export default function DashboardPage() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);

  const [simulating, setSimulating] = useState(false);
  const [simMsg, setSimMsg] = useState(null);

  const handleSimulate = async (scenario) => {
    setSimulating(true);
    setSimMsg(`Injecting ${scenario.toUpperCase()} traffic vector...`);
    try {
      const res = await api.traffic.simulateAttack(scenario);
      setSimMsg(`Attack Triggered! Alert #${res.alert_id} generated.`);
      // Refresh summary
      const data = await api.traffic.getSummary();
      setSummary(data);
    } catch (e) {
      setSimMsg(`Simulation error: ${e.message}`);
    } finally {
      setSimulating(false);
      setTimeout(() => setSimMsg(null), 5000);
    }
  };

  useEffect(() => {
    async function fetchData() {
      try {
        const data = await api.traffic.getSummary();
        setSummary(data);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  if (loading) {
    return <div className="animate-pulse text-text-muted font-mono">Loading telemetry...</div>;
  }

  if (!summary) {
    return <div className="text-threat font-mono">Failed to load dashboard data. Ensure backend is running.</div>;
  }

  // Mock data for the area chart based on summary
  const trafficData = Array.from({ length: 24 }).map((_, i) => ({
    time: `${i}:00`,
    traffic: Math.floor(Math.random() * 5000) + 1000,
    threats: Math.floor(Math.random() * 100),
  }));

  const donutData = [
    { name: 'Normal', value: summary.total_traffic - summary.threats_detected, color: '#3B82F6' },
    { name: 'Attack', value: summary.threats_detected, color: '#EF4444' }
  ];

  return (
    <div className="space-y-6">
      {/* KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KPICard 
          title="Total Traffic" 
          value={summary.total_traffic.toLocaleString()} 
          icon={Activity} 
          trend="+12.5%" 
          trendUp={true} 
        />
        <KPICard 
          title="Threats Detected" 
          value={summary.threats_detected.toLocaleString()} 
          icon={Shield} 
          trend="-2.4%" 
          trendUp={false} 
          alert={summary.threats_detected > 0}
        />
        <KPICard 
          title="Active Alerts" 
          value={summary.active_alerts.toLocaleString()} 
          icon={AlertTriangle} 
          alert={summary.active_alerts > 0}
        />
        <KPICard 
          title="Risk Score" 
          value={`${summary.risk_score}/100`} 
          icon={Database} 
          alert={summary.risk_score > 60}
          textColor={summary.risk_score > 80 ? 'text-threat' : summary.risk_score > 60 ? 'text-yellow-500' : 'text-safe'}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Chart */}
        <div className="lg:col-span-2 bg-card border border-border rounded p-5">
          <h3 className="font-mono text-sm uppercase text-text-muted mb-4">Traffic Volume (24h)</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trafficData}>
                <defs>
                  <linearGradient id="colorTraffic" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#3B82F6" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#2A2A2A" vertical={false} />
                <XAxis dataKey="time" stroke="#666" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#666" fontSize={12} tickLine={false} axisLine={false} />
                <RechartsTooltip 
                  contentStyle={{ backgroundColor: '#1A1A1A', border: '1px solid #333', borderRadius: '4px', fontFamily: 'JetBrains Mono' }}
                  itemStyle={{ color: '#E5E5E5' }}
                />
                <Area type="monotone" dataKey="traffic" stroke="#3B82F6" fillOpacity={1} fill="url(#colorTraffic)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Donut Chart */}
        <div className="bg-card border border-border rounded p-5 flex flex-col">
          <h3 className="font-mono text-sm uppercase text-text-muted mb-4">Traffic Classification</h3>
          <div className="flex-1 min-h-[200px] relative">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={donutData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
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
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-2xl font-bold font-mono">{summary.attack_percentage}%</span>
              <span className="text-[10px] text-text-muted uppercase">Threats</span>
            </div>
          </div>
          <div className="flex justify-center gap-4 mt-4 text-xs font-mono">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-sm bg-blue-500"></span> Normal
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-sm bg-threat"></span> Attack
            </div>
          </div>
        </div>
      </div>
      {/* Attack Simulation Quick Launcher & Recent Telemetry */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Simulation Control Card */}
        <div className="bg-card border border-border rounded p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-mono text-sm uppercase text-text-muted flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-threat animate-pulse"></span>
              Attack Simulation Engine
            </h3>
            <span className="text-[10px] bg-threat/20 text-threat px-2 py-0.5 rounded font-mono">SOC DEMO</span>
          </div>
          <p className="text-xs text-text-muted mb-4">
            Trigger real-time multi-vector network attack scenarios to validate AI anomaly detection and instant alerting.
          </p>
          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={() => handleSimulate('ddos')}
              disabled={simulating}
              className="px-3 py-2 bg-threat/10 hover:bg-threat/20 text-threat border border-threat/30 rounded text-xs font-mono transition flex items-center justify-center gap-1"
            >
              🌊 DDoS Flood
            </button>
            <button
              onClick={() => handleSimulate('port_scan')}
              disabled={simulating}
              className="px-3 py-2 bg-yellow-500/10 hover:bg-yellow-500/20 text-yellow-500 border border-yellow-500/30 rounded text-xs font-mono transition flex items-center justify-center gap-1"
            >
              🔍 SYN Port Scan
            </button>
            <button
              onClick={() => handleSimulate('brute_force')}
              disabled={simulating}
              className="px-3 py-2 bg-orange-500/10 hover:bg-orange-500/20 text-orange-500 border border-orange-500/30 rounded text-xs font-mono transition flex items-center justify-center gap-1"
            >
              🔑 SSH Spray
            </button>
            <button
              onClick={() => handleSimulate('sql_injection')}
              disabled={simulating}
              className="px-3 py-2 bg-purple-500/10 hover:bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded text-xs font-mono transition flex items-center justify-center gap-1"
            >
              💉 SQL Injection
            </button>
          </div>
          {simMsg && (
            <div className="mt-3 p-2 bg-surface border border-border text-safe text-xs font-mono rounded text-center animate-fade-in">
              {simMsg}
            </div>
          )}
        </div>

        {/* Protocol Distribution */}
        <div className="lg:col-span-2 bg-card border border-border rounded p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-mono text-sm uppercase text-text-muted">Top Network Protocols</h3>
            <span className="text-xs text-text-muted font-mono">Live Ingestion</span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { name: 'TCP', count: '45,210 pkts', pct: '62%', color: 'bg-blue-500' },
              { name: 'HTTPS (443)', count: '21,430 pkts', pct: '28%', color: 'bg-emerald-500' },
              { name: 'UDP', count: '5,120 pkts', pct: '7%', color: 'bg-yellow-500' },
              { name: 'DNS (53)', count: '2,190 pkts', pct: '3%', color: 'bg-purple-500' },
            ].map((p, idx) => (
              <div key={idx} className="bg-surface border border-border/50 rounded p-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold font-mono text-text-main">{p.name}</span>
                  <span className="text-[10px] font-mono text-text-muted">{p.pct}</span>
                </div>
                <div className="w-full bg-border h-1.5 rounded-full overflow-hidden mb-2">
                  <div className={`h-full ${p.color}`} style={{ width: p.pct }}></div>
                </div>
                <span className="text-[11px] text-text-muted font-mono">{p.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function KPICard({ title, value, icon: Icon, trend, trendUp, alert, textColor = "text-text-main" }) {
  return (
    <div className={`bg-card border ${alert ? 'border-threat/50 shadow-[0_0_15px_rgba(255,59,59,0.1)]' : 'border-border'} rounded p-5 relative overflow-hidden`}>
      {alert && <div className="absolute top-0 right-0 w-16 h-16 bg-threat/10 blur-2xl rounded-full" />}
      <div className="flex justify-between items-start mb-4">
        <h3 className="text-xs font-mono uppercase text-text-muted">{title}</h3>
        <div className={`p-2 rounded ${alert ? 'bg-threat/20 text-threat' : 'bg-surface text-text-muted'}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>
      <div className="flex items-end gap-3">
        <span className={`text-2xl font-bold font-mono ${textColor}`}>{value}</span>
        {trend && (
          <span className={`flex items-center text-xs font-mono mb-1 ${trendUp ? 'text-threat' : 'text-safe'}`}>
            {trendUp ? <ArrowUpRight className="w-3 h-3 mr-0.5" /> : <ArrowDownRight className="w-3 h-3 mr-0.5" />}
            {trend}
          </span>
        )}
      </div>
    </div>
  );
}
