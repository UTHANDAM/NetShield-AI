'use client';

import { useState, useEffect } from 'react';
import { api } from '../../../lib/api';
import { Activity, Search, Filter, Server, ArrowDownUp, ShieldOff, CheckCircle } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';

export default function NetworkTrafficPage() {
  const [records, setRecords] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [dataset, setDataset] = useState(''); // empty means all
  const [page, setPage] = useState(0);

  useEffect(() => {
    fetchData();
  }, [dataset, page]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [recordsData, statsData] = await Promise.all([
        api.traffic.getRecords({ dataset: dataset || undefined, limit: 50, offset: page * 50 }),
        api.traffic.getStats(dataset || undefined)
      ]);
      setRecords(recordsData);
      setStats(statsData);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const protocolData = stats ? Object.entries(stats.protocol_distribution).map(([name, value]) => ({ name, value })) : [];

  return (
    <div className="space-y-6">
      {/* Controls & Search */}
      <div className="flex flex-col sm:flex-row justify-between items-center bg-card border border-border p-4 rounded gap-4">
        <div className="flex items-center gap-4 w-full sm:w-auto">
          <div className="relative flex-1 sm:w-64">
            <Search className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
            <input 
              type="text" 
              placeholder="Search IP or Protocol..." 
              className="w-full bg-surface border border-border rounded pl-9 pr-4 py-2 text-sm text-text-main focus:outline-none focus:border-threat/50"
            />
          </div>
          <select 
            value={dataset}
            onChange={(e) => { setDataset(e.target.value); setPage(0); }}
            className="bg-surface border border-border rounded px-4 py-2 text-sm text-text-main focus:outline-none focus:border-threat/50 appearance-none"
          >
            <option value="">All Datasets</option>
            <option value="cicids2017">CICIDS2017</option>
            <option value="unsw_nb15">UNSW-NB15</option>
          </select>
        </div>
        <div className="flex gap-2">
          <button className="flex items-center gap-2 px-3 py-2 bg-surface border border-border rounded text-sm text-text-muted hover:text-text-main transition">
            <Filter className="w-4 h-4" /> Filter
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Stats */}
        <div className="space-y-6">
          <div className="bg-card border border-border rounded p-5">
            <h3 className="font-mono text-sm uppercase text-text-muted mb-4 flex items-center gap-2">
              <Activity className="w-4 h-4" /> Traffic Overview
            </h3>
            {stats ? (
              <div className="space-y-4">
                <div className="flex justify-between items-end border-b border-border pb-3">
                  <span className="text-xs text-text-muted uppercase">Total Records</span>
                  <span className="text-xl font-bold font-mono">{stats.total_records.toLocaleString()}</span>
                </div>
                <div className="flex justify-between items-end border-b border-border pb-3">
                  <span className="text-xs text-text-muted uppercase flex items-center gap-2"><CheckCircle className="w-3 h-3 text-safe" /> Normal Traffic</span>
                  <span className="text-xl font-bold font-mono text-safe">{stats.normal_count.toLocaleString()}</span>
                </div>
                <div className="flex justify-between items-end">
                  <span className="text-xs text-text-muted uppercase flex items-center gap-2"><ShieldOff className="w-3 h-3 text-threat" /> Malicious Traffic</span>
                  <span className="text-xl font-bold font-mono text-threat">{stats.attack_count.toLocaleString()}</span>
                </div>
              </div>
            ) : (
              <div className="animate-pulse h-32 bg-surface/50 rounded"></div>
            )}
          </div>

          {/* Protocol Chart */}
          <div className="bg-card border border-border rounded p-5 flex flex-col">
            <h3 className="font-mono text-sm uppercase text-text-muted mb-4 flex items-center gap-2">
              <Server className="w-4 h-4" /> Protocol Distribution
            </h3>
            <div className="flex-1 min-h-[200px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={protocolData} layout="vertical" margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#2A2A2A" horizontal={false} />
                  <XAxis type="number" stroke="#666" fontSize={10} tickLine={false} axisLine={false} />
                  <YAxis dataKey="name" type="category" stroke="#888" fontSize={10} tickLine={false} axisLine={false} width={50} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1A1A1A', border: '1px solid #333', borderRadius: '4px', fontFamily: 'JetBrains Mono' }}
                    cursor={{ fill: '#2A2A2A' }}
                  />
                  <Bar dataKey="value" fill="#3B82F6" radius={[0, 4, 4, 0]}>
                    {protocolData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={['#3B82F6', '#8B5CF6', '#10B981'][index % 3]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Right Column: Table */}
        <div className="lg:col-span-2 bg-card border border-border rounded flex flex-col overflow-hidden">
          <div className="p-4 border-b border-border bg-surface/50 flex justify-between items-center">
            <h3 className="font-mono text-sm uppercase text-text-main font-bold">Raw Telemetry Data</h3>
            <span className="text-xs text-text-muted">Showing page {page + 1}</span>
          </div>
          <div className="overflow-x-auto flex-1">
            <table className="w-full text-left">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Dest IP</th>
                  <th>Port</th>
                  <th>Proto</th>
                  <th>Dataset</th>
                  <th>Label</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan="7" className="text-center p-8 text-text-muted">Loading data...</td></tr>
                ) : records.map((record) => (
                  <tr key={record.id} className={record.label !== 'BENIGN' && record.label !== 'Normal' ? 'bg-threat/5' : ''}>
                    <td className="text-text-muted whitespace-nowrap">{new Date(record.timestamp).toLocaleTimeString()}</td>
                    <td>{record.source_ip}</td>
                    <td>{record.dest_ip}</td>
                    <td>{record.port}</td>
                    <td><span className="px-1.5 py-0.5 rounded bg-surface border border-border text-[10px] uppercase">{record.protocol}</span></td>
                    <td><span className="text-[10px] text-text-muted uppercase tracking-wider">{record.dataset_source}</span></td>
                    <td>
                      {record.label === 'BENIGN' || record.label === 'Normal' ? (
                        <span className="text-safe text-xs uppercase font-bold tracking-wider">Normal</span>
                      ) : (
                        <span className="text-threat text-xs uppercase font-bold tracking-wider flex items-center gap-1">
                          <ShieldOff className="w-3 h-3" /> Attack
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="p-3 border-t border-border flex justify-between items-center bg-surface/30">
            <button 
              onClick={() => setPage(Math.max(0, page - 1))}
              disabled={page === 0}
              className="px-3 py-1.5 bg-card border border-border rounded text-xs font-mono uppercase hover:bg-surface disabled:opacity-50"
            >
              Previous
            </button>
            <button 
              onClick={() => setPage(page + 1)}
              disabled={records.length < 50}
              className="px-3 py-1.5 bg-card border border-border rounded text-xs font-mono uppercase hover:bg-surface disabled:opacity-50"
            >
              Next Page
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
