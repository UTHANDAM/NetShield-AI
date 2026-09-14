'use client';

import { useState, useEffect } from 'react';
import { api } from '../../../lib/api';
import { Settings, Server, Shield, Bell, User, Cpu, Database } from 'lucide-react';

export default function SettingsPage() {
  const [profile, setProfile] = useState(null);
  
  useEffect(() => {
    async function loadProfile() {
      try {
        const data = await api.auth.getMe();
        setProfile(data);
      } catch (err) {
        console.error("Failed to load profile", err);
        // Fallback to local storage if API fails
        const localUser = localStorage.getItem('netshield_user');
        if (localUser) setProfile(JSON.parse(localUser));
      }
    }
    loadProfile();
  }, []);

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="bg-card border border-border p-4 rounded">
        <h2 className="text-lg font-bold font-mono text-text-main flex items-center gap-2">
          <Settings className="w-5 h-5 text-threat" />
          System Configuration
        </h2>
        <p className="text-xs text-text-muted font-mono mt-1 uppercase">Manage operator profile and SOC settings</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Navigation / Tabs */}
        <div className="space-y-2">
          <SettingsTab icon={User} label="Operator Profile" active={true} />
          <SettingsTab icon={Shield} label="Detection Rules" />
          <SettingsTab icon={Database} label="Data Retention" />
          <SettingsTab icon={Bell} label="Alert Notifications" />
          <SettingsTab icon={Cpu} label="ML Engine Config" />
          <SettingsTab icon={Server} label="System Status" />
        </div>

        {/* Content Area */}
        <div className="md:col-span-2 space-y-6">
          <div className="bg-card border border-border rounded p-6">
            <h3 className="font-mono text-sm uppercase text-text-main font-bold mb-6 border-b border-border pb-2">Operator Profile</h3>
            
            {profile ? (
              <div className="space-y-5">
                <div>
                  <label className="block text-xs font-mono uppercase text-text-muted mb-1.5">Full Name</label>
                  <input type="text" readOnly value={profile.name} className="w-full bg-surface border border-border rounded px-4 py-2.5 text-sm text-text-main opacity-70 cursor-not-allowed" />
                </div>
                <div>
                  <label className="block text-xs font-mono uppercase text-text-muted mb-1.5">Operator ID (Email)</label>
                  <input type="text" readOnly value={profile.email} className="w-full bg-surface border border-border rounded px-4 py-2.5 text-sm text-text-main opacity-70 cursor-not-allowed" />
                </div>
                <div>
                  <label className="block text-xs font-mono uppercase text-text-muted mb-1.5">Clearance Level</label>
                  <div className="w-full bg-threat/10 border border-threat/20 text-threat rounded px-4 py-2.5 text-sm font-bold font-mono uppercase">
                    {profile.role}
                  </div>
                </div>
              </div>
            ) : (
              <div className="animate-pulse space-y-4">
                <div className="h-10 bg-surface/50 rounded w-full"></div>
                <div className="h-10 bg-surface/50 rounded w-full"></div>
                <div className="h-10 bg-surface/50 rounded w-full"></div>
              </div>
            )}
          </div>

          <div className="bg-card border border-border rounded p-6">
            <h3 className="font-mono text-sm uppercase text-text-main font-bold mb-4 border-b border-border pb-2 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-threat" /> Inference Engine
            </h3>
            <div className="space-y-4 text-sm font-mono">
              <div className="flex justify-between items-center py-2 border-b border-surface">
                <span className="text-text-muted">Primary Model</span>
                <span className="font-bold text-text-main">XGBoost (Binary/Multiclass)</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-surface">
                <span className="text-text-muted">Confidence Threshold</span>
                <span className="font-bold text-safe">85.0%</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-surface">
                <span className="text-text-muted">Auto-blocking</span>
                <span className="px-2 py-0.5 bg-threat/10 text-threat border border-threat/20 rounded text-xs">Enabled</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function SettingsTab({ icon: Icon, label, active }) {
  return (
    <button className={`w-full flex items-center gap-3 px-4 py-3 rounded font-mono text-sm uppercase transition ${
      active ? 'bg-surface border border-border text-text-main font-bold' : 'text-text-muted hover:bg-surface/50 hover:text-text-main'
    }`}>
      <Icon className={`w-4 h-4 ${active ? 'text-threat' : ''}`} />
      {label}
    </button>
  );
}
