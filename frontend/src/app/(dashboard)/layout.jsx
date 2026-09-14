'use client';

import { useState, useEffect } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  Shield, LayoutDashboard, Activity, AlertTriangle, Cpu, BrainCircuit, FileText, Settings, LogOut, User as UserIcon, Bell, Radio, Database, Network, Radar, Boxes
} from 'lucide-react';
import NotificationCenter from '../../components/ui/NotificationCenter';

const NAV_ITEMS = [
  { name: 'Overview', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Analytics', href: '/security-analytics', icon: Activity },
  { name: 'Incidents', href: '/incidents', icon: Shield },
  { name: 'Threat Alerts', href: '/threat-alerts', icon: AlertTriangle },
  { name: 'Threat Intelligence', href: '/threat-intelligence', icon: Database },
  { name: 'Live Monitoring', href: '/network-traffic', icon: Network },
  { name: 'Anomaly Detection', href: '/anomaly-detection', icon: Cpu },
  { name: 'Intrusion Prediction', href: '/intrusion-prediction', icon: Radar },
  { name: 'AI Models', href: '/ai-models', icon: BrainCircuit },
  { name: 'Architecture', href: '/architecture', icon: Boxes },
  { name: 'Reports', href: '/reports', icon: FileText },
  { name: 'Team', href: '/team', icon: UserIcon },
  { name: 'Settings', href: '/settings', icon: Settings },
];

export default function DashboardLayout({ children }) {
  const pathname = usePathname();
  const router = useRouter();
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const storedUser = localStorage.getItem('netshield_user');
    const token = localStorage.getItem('netshield_token');

    if (!token || !storedUser) {
      router.push('/login');
      return;
    }

    try {
      setUser(JSON.parse(storedUser));
    } catch {
      router.push('/login');
    } finally {
      setLoading(false);
    }
  }, [router]);

  const handleLogout = () => {
    localStorage.removeItem('netshield_token');
    localStorage.removeItem('netshield_user');
    router.push('/login');
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-bg flex items-center justify-center font-mono text-text-muted">
        <div className="flex items-center gap-3">
          <div className="w-4 h-4 bg-threat rounded-full animate-ping" />
          <span>INITIALIZING SOC TERMINAL...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-bg text-text-main flex">
      {/* Fixed Left Sidebar */}
      <aside className="w-64 bg-sidebar border-r border-border flex flex-col fixed inset-y-0 left-0 z-30">
        {/* Brand Header */}
        <div className="p-5 border-b border-border flex items-center gap-3">
          <div className="w-9 h-9 bg-card border border-border rounded flex items-center justify-center text-threat">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h1 className="font-bold text-base tracking-tight flex items-center gap-1 text-text-main">
              NETSHIELD <span className="text-threat font-mono text-sm">AI</span>
            </h1>
            <p className="text-[10px] font-mono text-text-muted tracking-widest uppercase">
              SOC Threat Monitor
            </p>
          </div>
        </div>

        {/* Live System Indicator */}
        <div className="px-5 py-3 border-b border-border/50 bg-surface/50 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 bg-safe rounded-full animate-pulse" />
            <span className="text-xs font-mono text-text-muted uppercase">Engine Status</span>
          </div>
          <span className="text-xs font-mono text-safe font-bold">ONLINE</span>
        </div>

        {/* Navigation Menu */}
        <nav className="flex-1 py-4 px-3 space-y-1 overflow-y-auto">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-3 px-3 py-2.5 rounded text-xs font-mono transition-all group relative ${
                  isActive
                    ? 'bg-surface text-text-main font-semibold border-l-4 border-threat pl-2'
                    : 'text-text-muted hover:bg-surface/50 hover:text-text-main'
                }`}
              >
                <Icon className={`w-4 h-4 transition-colors ${isActive ? 'text-threat' : 'group-hover:text-text-main'}`} />
                <span>{item.name}</span>
                {item.name === 'Threat Alerts' && (
                  <span className="ml-auto w-2 h-2 bg-threat rounded-full animate-pulse-red" />
                )}
              </Link>
            );
          })}
        </nav>

        {/* User Info & Logout Footer */}
        <div className="p-4 border-t border-border bg-surface/30">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 overflow-hidden">
              <div className="w-8 h-8 rounded bg-card border border-border flex items-center justify-center text-text-muted shrink-0">
                <UserIcon className="w-4 h-4" />
              </div>
              <div className="overflow-hidden">
                <p className="text-xs font-bold font-mono text-text-main truncate">
                  {user?.name || 'Operator'}
                </p>
                <span className="inline-block text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-threat/10 text-threat border border-threat/20">
                  {user?.role || 'Analyst'}
                </span>
              </div>
            </div>
            <button
              onClick={handleLogout}
              title="Logout session"
              className="p-2 hover:bg-threat/10 hover:text-threat rounded text-text-muted transition"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 pl-64 flex flex-col min-h-screen">
        {/* Top Bar */}
        <header className="h-16 bg-surface border-b border-border px-8 flex items-center justify-between sticky top-0 z-20">
          <div className="flex items-center gap-4">
            <h2 className="text-sm font-mono uppercase tracking-wider text-text-muted flex items-center gap-2">
              <Radio className="w-4 h-4 text-threat animate-pulse" />
              <span className="text-text-main font-bold">
                {NAV_ITEMS.find((n) => n.href === pathname)?.name || 'Overview'}
              </span>
            </h2>
          </div>

          <div className="flex items-center gap-6 text-xs font-mono">
            <NotificationCenter />
            <div className="flex items-center gap-2 bg-card px-3 py-1.5 rounded border border-border">
              <span className="text-text-muted">DATASETS:</span>
              <span className="text-safe font-bold">CICIDS2017 & UNSW-NB15</span>
            </div>

            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-threat animate-pulse-red" />
              <span className="text-threat uppercase tracking-wider font-bold">LIVE TELEMETRY</span>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 p-8 bg-bg">
          {children}
        </main>
      </div>
    </div>
  );
}
