'use client';

import { useState, useEffect } from 'react';
import { api } from '../../../lib/api';
import { BrainCircuit, CheckCircle, Clock, Database, GitBranch, Target, Zap } from 'lucide-react';

export default function AIModelsPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchData() {
      try {
        const result = await api.models.getComparison();
        setData(result);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  if (loading) {
    return <div className="animate-pulse text-text-muted font-mono">Loading model metrics...</div>;
  }

  if (!data) {
    return <div className="text-threat font-mono">Failed to load models data.</div>;
  }

  const bestModel = data.models.find(m => m.is_best) || data.models[0];

  return (
    <div className="space-y-6">
      {/* Header Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-card border border-threat/50 shadow-[0_0_15px_rgba(255,59,59,0.1)] rounded p-5 relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-threat/10 blur-2xl rounded-full" />
          <div className="flex justify-between items-start mb-2">
            <h3 className="text-xs font-mono uppercase text-text-muted">Primary Active Model</h3>
            <BrainCircuit className="w-4 h-4 text-threat" />
          </div>
          <p className="text-lg font-bold font-mono text-text-main mt-2">{data.best_model}</p>
        </div>

        <div className="bg-card border border-border rounded p-5 relative overflow-hidden">
          <div className="flex justify-between items-start mb-2">
            <h3 className="text-xs font-mono uppercase text-text-muted">Peak Accuracy</h3>
            <Target className="w-4 h-4 text-safe" />
          </div>
          <p className="text-3xl font-bold font-mono text-safe mt-2">{data.best_accuracy}</p>
        </div>

        <div className="bg-card border border-border rounded p-5 relative overflow-hidden">
          <div className="flex justify-between items-start mb-2">
            <h3 className="text-xs font-mono uppercase text-text-muted">F1-Score (Macro)</h3>
            <CheckCircle className="w-4 h-4 text-blue-500" />
          </div>
          <p className="text-3xl font-bold font-mono text-blue-500 mt-2">{data.best_f1}</p>
        </div>
      </div>

      {/* Model Comparison Table */}
      <div className="bg-card border border-border rounded overflow-hidden">
        <div className="p-4 border-b border-border bg-surface/50">
          <h3 className="text-sm font-mono uppercase font-bold text-text-main">Model Training & Comparison</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr>
                <th>Model Architecture</th>
                <th>Dataset</th>
                <th>Type</th>
                <th>Accuracy</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>F1-Score</th>
                <th>ROC-AUC</th>
                <th>Train Time</th>
              </tr>
            </thead>
            <tbody>
              {data.models.map((model, idx) => (
                <tr key={idx} className={model.is_best ? 'bg-threat/5' : ''}>
                  <td className="font-bold flex items-center gap-2">
                    {model.is_best && <Zap className="w-3 h-3 text-threat" />}
                    {model.model_name}
                  </td>
                  <td>
                    <span className="px-2 py-0.5 rounded bg-surface border border-border text-xs uppercase">
                      {model.dataset}
                    </span>
                  </td>
                  <td className="uppercase text-xs text-text-muted">{model.model_type}</td>
                  <td className={model.accuracy > 90 ? 'text-safe' : 'text-yellow-500'}>{model.accuracy}%</td>
                  <td>{model.precision}%</td>
                  <td>{model.recall}%</td>
                  <td className="font-bold text-blue-400">{model.f1_score}%</td>
                  <td>{model.roc_auc || 'N/A'}</td>
                  <td className="text-text-muted">{model.training_time_ms}ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Visualizations Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <div className="bg-card border border-border rounded p-4">
          <h4 className="text-xs font-mono uppercase text-text-muted mb-4 border-b border-border pb-2">Confusion Matrices</h4>
          <div className="bg-white rounded overflow-hidden flex items-center justify-center p-2">
            {/* The images were copied to public/plots/ */}
            <img src="/plots/binary_confusion_matrices.png" alt="Confusion Matrix" className="w-full h-auto object-contain" />
          </div>
        </div>
        
        <div className="bg-card border border-border rounded p-4">
          <h4 className="text-xs font-mono uppercase text-text-muted mb-4 border-b border-border pb-2">ROC Curves</h4>
          <div className="bg-white rounded overflow-hidden flex items-center justify-center p-2">
            <img src="/plots/roc_curves.png" alt="ROC Curves" className="w-full h-auto object-contain" />
          </div>
        </div>

        <div className="bg-card border border-border rounded p-4">
          <h4 className="text-xs font-mono uppercase text-text-muted mb-4 border-b border-border pb-2">Feature Importances (Top 15)</h4>
          <div className="bg-white rounded overflow-hidden flex items-center justify-center p-2">
            <img src="/plots/feature_importances.png" alt="Feature Importances" className="w-full h-auto object-contain" />
          </div>
        </div>
      </div>
    </div>
  );
}
