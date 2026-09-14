'use client';

import { useState, useEffect } from 'react';
import { api } from '../../../lib/api';
import { FileText, Download, FileSpreadsheet, Plus, Clock, ShieldAlert } from 'lucide-react';

export default function ReportsPage() {
  const [reports, setReports] = useState([]);
  const [riskSummary, setRiskSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [formData, setFormData] = useState({ title: '', report_type: 'pdf' });

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [reportsData, summaryData] = await Promise.all([
        api.reports.list(),
        api.reports.getRiskSummary()
      ]);
      setReports(reportsData);
      setRiskSummary(summaryData);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerate = async (e) => {
    e.preventDefault();
    setGenerating(true);
    try {
      await api.reports.generate(formData);
      setShowModal(false);
      setFormData({ title: '', report_type: 'pdf' });
      fetchData();
    } catch (err) {
      console.error(err);
    } finally {
      setGenerating(false);
    }
  };

  const downloadReport = (id) => {
    window.open(api.reports.downloadUrl(id), '_blank');
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center bg-card border border-border p-4 rounded">
        <div>
          <h2 className="text-lg font-bold font-mono text-text-main flex items-center gap-2">
            <FileText className="w-5 h-5 text-threat" />
            Security Reports & Audits
          </h2>
          <p className="text-xs text-text-muted font-mono mt-1 uppercase">Generate compliance and threat reports</p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-threat text-white rounded font-bold font-mono text-sm uppercase tracking-wider hover:bg-red-600 transition"
        >
          <Plus className="w-4 h-4" /> Generate Report
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Overall Risk Summary */}
        <div className="bg-card border border-border rounded p-5 relative overflow-hidden flex flex-col">
          <h3 className="font-mono text-sm uppercase text-text-muted mb-6 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4" /> Platform Risk Posture
          </h3>
          
          {riskSummary ? (
            <div className="flex flex-col flex-1 justify-center items-center">
              <div className="relative mb-6">
                <div className={`w-32 h-32 rounded-full border-8 flex items-center justify-center ${
                  riskSummary.risk_level === 'CRITICAL' ? 'border-threat/30' :
                  riskSummary.risk_level === 'HIGH' ? 'border-orange-500/30' :
                  riskSummary.risk_level === 'MEDIUM' ? 'border-yellow-500/30' : 'border-safe/30'
                }`}>
                  <span className={`text-4xl font-bold font-mono ${
                    riskSummary.risk_level === 'CRITICAL' ? 'text-threat' :
                    riskSummary.risk_level === 'HIGH' ? 'text-orange-500' :
                    riskSummary.risk_level === 'MEDIUM' ? 'text-yellow-500' : 'text-safe'
                  }`}>{riskSummary.overall_risk_score}</span>
                </div>
                {/* SVG Circle for progress */}
                <svg className="absolute top-0 left-0 w-32 h-32 transform -rotate-90" viewBox="0 0 100 100">
                  <circle cx="50" cy="50" r="46" fill="transparent" stroke="currentColor" strokeWidth="8"
                    strokeDasharray={`${riskSummary.overall_risk_score * 2.89} 289`}
                    className={`${
                      riskSummary.risk_level === 'CRITICAL' ? 'text-threat' :
                      riskSummary.risk_level === 'HIGH' ? 'text-orange-500' :
                      riskSummary.risk_level === 'MEDIUM' ? 'text-yellow-500' : 'text-safe'
                    }`}
                  />
                </svg>
              </div>
              <p className={`font-mono font-bold uppercase tracking-widest ${
                    riskSummary.risk_level === 'CRITICAL' ? 'text-threat' :
                    riskSummary.risk_level === 'HIGH' ? 'text-orange-500' :
                    riskSummary.risk_level === 'MEDIUM' ? 'text-yellow-500' : 'text-safe'
                  }`}>{riskSummary.risk_level} RISK</p>
              
              <div className="w-full mt-8 space-y-2">
                {Object.entries(riskSummary.risk_breakdown).map(([severity, pct]) => (
                  <div key={severity} className="flex justify-between items-center text-xs font-mono">
                    <span className="text-text-muted uppercase">{severity}</span>
                    <span className="text-text-main">{pct}%</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex-1 animate-pulse bg-surface/50 rounded" />
          )}
        </div>

        {/* Report Archive List */}
        <div className="lg:col-span-2 bg-card border border-border rounded overflow-hidden">
          <div className="p-4 border-b border-border bg-surface/50">
            <h3 className="font-mono text-sm uppercase text-text-main font-bold">Report Archive</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr>
                  <th>Report Info</th>
                  <th>Type</th>
                  <th>Records</th>
                  <th>Generated</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan="5" className="text-center p-8 text-text-muted">Loading reports...</td></tr>
                ) : reports.length === 0 ? (
                  <tr><td colSpan="5" className="text-center p-8 text-text-muted">No reports generated yet.</td></tr>
                ) : reports.map((report) => (
                  <tr key={report.id}>
                    <td>
                      <div className="font-bold text-text-main">{report.title}</div>
                    </td>
                    <td>
                      <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-surface border border-border flex items-center gap-1 w-max">
                        {report.report_type === 'csv' ? <FileSpreadsheet className="w-3 h-3" /> : <FileText className="w-3 h-3" />}
                        {report.report_type}
                      </span>
                    </td>
                    <td className="font-mono">{report.record_count.toLocaleString()}</td>
                    <td className="text-text-muted text-xs flex items-center gap-1">
                      <Clock className="w-3 h-3" /> {new Date(report.created_at).toLocaleString()}
                    </td>
                    <td>
                      <button 
                        onClick={() => downloadReport(report.id)}
                        className="px-3 py-1.5 bg-threat/10 text-threat border border-threat/20 hover:bg-threat hover:text-white rounded text-xs font-mono uppercase transition flex items-center gap-1"
                      >
                        <Download className="w-3 h-3" /> Download
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Generate Report Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-bg/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-card border border-border rounded shadow-2xl w-full max-w-md p-6">
            <h3 className="font-mono text-lg font-bold text-text-main mb-4 border-b border-border pb-3">Generate New Report</h3>
            <form onSubmit={handleGenerate} className="space-y-4">
              <div>
                <label className="block text-xs font-mono uppercase text-text-muted mb-1.5">Report Title</label>
                <input 
                  type="text" 
                  required
                  value={formData.title}
                  onChange={e => setFormData({...formData, title: e.target.value})}
                  className="w-full bg-surface border border-border rounded px-3 py-2 text-sm text-text-main focus:outline-none focus:border-threat/50"
                  placeholder="e.g. Weekly Threat Audit"
                />
              </div>
              <div>
                <label className="block text-xs font-mono uppercase text-text-muted mb-1.5">Export Format</label>
                <div className="grid grid-cols-2 gap-3">
                  <label className={`border rounded p-3 cursor-pointer flex items-center gap-3 transition ${formData.report_type === 'pdf' ? 'border-threat bg-threat/10' : 'border-border bg-surface hover:bg-surface/80'}`}>
                    <input type="radio" name="type" value="pdf" checked={formData.report_type === 'pdf'} onChange={() => setFormData({...formData, report_type: 'pdf'})} className="hidden" />
                    <FileText className={`w-5 h-5 ${formData.report_type === 'pdf' ? 'text-threat' : 'text-text-muted'}`} />
                    <span className="text-sm font-mono uppercase font-bold">Text / PDF</span>
                  </label>
                  <label className={`border rounded p-3 cursor-pointer flex items-center gap-3 transition ${formData.report_type === 'csv' ? 'border-threat bg-threat/10' : 'border-border bg-surface hover:bg-surface/80'}`}>
                    <input type="radio" name="type" value="csv" checked={formData.report_type === 'csv'} onChange={() => setFormData({...formData, report_type: 'csv'})} className="hidden" />
                    <FileSpreadsheet className={`w-5 h-5 ${formData.report_type === 'csv' ? 'text-threat' : 'text-text-muted'}`} />
                    <span className="text-sm font-mono uppercase font-bold">CSV</span>
                  </label>
                </div>
              </div>
              <div className="flex gap-3 mt-6">
                <button type="button" onClick={() => setShowModal(false)} className="flex-1 py-2 px-4 bg-surface border border-border hover:bg-white/5 rounded font-mono text-sm uppercase">Cancel</button>
                <button type="submit" disabled={generating} className="flex-1 py-2 px-4 bg-threat text-white hover:bg-red-600 rounded font-mono text-sm uppercase flex justify-center items-center gap-2 disabled:opacity-50">
                  {generating ? 'Generating...' : <><Download className="w-4 h-4" /> Create</>}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
