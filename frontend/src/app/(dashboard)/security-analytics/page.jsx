'use client';

import { useState, useEffect } from 'react';
import { api } from '../../../lib/api';
import { Shield, Activity, Target, AlertTriangle, Crosshair, Network, Clock, BarChart2 } from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar, Legend
} from 'recharts';

export default function SecurityAnalyticsPage() {
  const [loading, setLoading] = useState(true);
  const [overview, setOverview] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [attackDist, setAttackDist] = useState(null);
  const [topAttackers, setTopAttackers] = useState([]);
  const [topTargets, setTopTargets] = useState([]);

  useEffect(() => {
    async function fetchData() {
      try {
        const [
          ovData,
          tlData,
          adData,
          taData,
          ttData
        ] = await Promise.all([
          api.analytics.getSecurityOverview(),
          api.analytics.getAlertsTimeline(),
          api.analytics.getAttackDistribution(),
          api.analytics.getTopAttackers(5),
          api.analytics.getTopTargets(5)
        ]);

        setOverview(ovData);
        setTimeline(tlData);
        setAttackDist(adData);
        setTopAttackers(taData);
        setTopTargets(ttData);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  if (loading) {
    return <div className="animate-pulse text-text-muted font-mono p-4">Loading security analytics...</div>;
  }

  const COLORS = ['#FF3B3B', '#F59E0B', '#3B82F6', '#8B5CF6', '#EC4899', '#10B981'];

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center bg-card border border-border p-4 rounded">
        <div>
          <h2 className="text-lg font-bold font-mono text-text-main flex items-center gap-2">
            <BarChart2 className="w-5 h-5 text-blue-500" />
            Security Analytics & Trends
          </h2>
          <p className="text-xs text-text-muted font-mono mt-1 uppercase">Aggregated threat telemetry and performance metrics</p>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-card border border-border rounded p-4 relative overflow-hidden">
          <div className="flex justify-between items-start mb-2">
            <h3 className="text-xs font-mono uppercase text-text-muted">Total Alerts</h3>
            <Shield className="w-4 h-4 text-threat" />
          </div>
          <p className="text-2xl font-bold font-mono text-text-main mt-2">{overview.total_alerts.toLocaleString()}</p>
          <p className="text-[10px] text-threat font-mono mt-1 uppercase">{overview.critical_alerts} Critical</p>
        </div>

        <div className="bg-card border border-border rounded p-4 relative overflow-hidden">
          <div className="flex justify-between items-start mb-2">
            <h3 className="text-xs font-mono uppercase text-text-muted">Active Incidents</h3>
            <Activity className="w-4 h-4 text-warning" />
          </div>
          <p className="text-2xl font-bold font-mono text-text-main mt-2">{overview.active_incidents.toLocaleString()}</p>
          <p className="text-[10px] text-text-muted font-mono mt-1 uppercase">Of {overview.total_incidents} Total</p>
        </div>

        <div className="bg-card border border-border rounded p-4 relative overflow-hidden">
          <div className="flex justify-between items-start mb-2">
            <h3 className="text-xs font-mono uppercase text-text-muted">Avg Risk Score</h3>
            <Target className="w-4 h-4 text-blue-500" />
          </div>
          <p className="text-2xl font-bold font-mono text-blue-500 mt-2">{overview.avg_risk_score.toFixed(1)}/100</p>
        </div>

        <div className="bg-card border border-border rounded p-4 relative overflow-hidden">
          <div className="flex justify-between items-start mb-2">
            <h3 className="text-xs font-mono uppercase text-text-muted">Incident MTTR</h3>
            <Clock className="w-4 h-4 text-safe" />
          </div>
          <p className="text-2xl font-bold font-mono text-safe mt-2">
            {overview.mttr_minutes ? (overview.mttr_minutes / 60).toFixed(1) : 'N/A'} <span className="text-sm">hrs</span>
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline Chart */}
        <div className="lg:col-span-2 bg-card border border-border rounded p-4 flex flex-col">
          <h3 className="font-mono text-sm uppercase text-text-main font-bold mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-text-muted" /> Alert Volume (7 Days)
          </h3>
          <div className="flex-1 min-h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#3B82F6" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#FF3B3B" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#FF3B3B" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#2A2A2A" vertical={false} />
                <XAxis dataKey="date" stroke="#666" fontSize={10} tickFormatter={(val) => val.substring(5)} />
                <YAxis stroke="#666" fontSize={10} />
                <RechartsTooltip 
                  contentStyle={{ backgroundColor: '#1A1A1A', border: '1px solid #333', borderRadius: '4px', fontFamily: 'JetBrains Mono' }}
                />
                <Area type="monotone" dataKey="total" stroke="#3B82F6" fillOpacity={1} fill="url(#colorTotal)" name="Total Alerts" />
                <Area type="monotone" dataKey="CRITICAL" stroke="#FF3B3B" fillOpacity={1} fill="url(#colorCritical)" name="Critical" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Attack Distribution Donut */}
        <div className="bg-card border border-border rounded p-4 flex flex-col">
          <h3 className="font-mono text-sm uppercase text-text-main font-bold mb-4 flex items-center gap-2">
            <Crosshair className="w-4 h-4 text-text-muted" /> Attack Types
          </h3>
          <div className="flex-1 min-h-[250px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={attackDist?.by_attack_type.slice(0, 6) || []}
                  cx="50%" cy="50%"
                  innerRadius={60} outerRadius={80}
                  paddingAngle={2}
                  dataKey="value" stroke="none"
                >
                  {attackDist?.by_attack_type.map((entry, index) => (
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

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Attackers */}
        <div className="bg-card border border-border rounded flex flex-col">
          <div className="p-4 border-b border-border">
            <h3 className="font-mono text-sm uppercase text-text-main font-bold flex items-center gap-2">
              <Network className="w-4 h-4 text-threat" /> Top Attacker IPs
            </h3>
          </div>
          <div className="p-4 flex-1">
            <div className="space-y-4">
              {topAttackers.map((ip, idx) => (
                <div key={idx} className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono text-text-muted w-4">{idx + 1}.</span>
                    <span className="text-sm font-mono text-text-main">{ip.ip}</span>
                    <span className={`text-[9px] uppercase px-1.5 py-0.5 rounded border ${
                      ip.max_severity === 'CRITICAL' ? 'bg-threat/10 border-threat/30 text-threat' : 
                      'bg-warning/10 border-warning/30 text-warning'
                    }`}>
                      {ip.max_severity}
                    </span>
                  </div>
                  <span className="text-sm font-bold font-mono text-text-muted">{ip.count.toLocaleString()} alerts</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Top Targets */}
        <div className="bg-card border border-border rounded flex flex-col">
          <div className="p-4 border-b border-border">
            <h3 className="font-mono text-sm uppercase text-text-main font-bold flex items-center gap-2">
              <Target className="w-4 h-4 text-safe" /> Top Targeted IPs
            </h3>
          </div>
          <div className="p-4 flex-1">
            <div className="space-y-4">
              {topTargets.map((ip, idx) => (
                <div key={idx} className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono text-text-muted w-4">{idx + 1}.</span>
                    <span className="text-sm font-mono text-text-main">{ip.ip}</span>
                  </div>
                  <span className="text-sm font-bold font-mono text-text-muted">{ip.count.toLocaleString()} alerts</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
