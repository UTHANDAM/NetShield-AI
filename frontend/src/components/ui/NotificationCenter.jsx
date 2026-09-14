'use client';

import { useState, useEffect, useRef } from 'react';
import { Bell, X, Check, CheckCheck, AlertTriangle, ShieldAlert, Info, ExternalLink } from 'lucide-react';
import { api } from '../../lib/api';

const severityConfig = {
  CRITICAL: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', icon: ShieldAlert, dot: 'bg-red-500' },
  HIGH:     { bg: 'bg-orange-500/10', border: 'border-orange-500/30', text: 'text-orange-400', icon: AlertTriangle, dot: 'bg-orange-500' },
  MEDIUM:   { bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', text: 'text-yellow-400', icon: AlertTriangle, dot: 'bg-yellow-500' },
  LOW:      { bg: 'bg-blue-500/10', border: 'border-blue-500/30', text: 'text-blue-400', icon: Info, dot: 'bg-blue-500' },
  INFO:     { bg: 'bg-blue-500/10', border: 'border-blue-500/30', text: 'text-blue-400', icon: Info, dot: 'bg-blue-400' },
};

export default function NotificationCenter() {
  const [open, setOpen] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const panelRef = useRef(null);

  const fetchNotifications = async () => {
    try {
      const [notifs, countData] = await Promise.all([
        api.notifications.list({ limit: 20 }),
        api.notifications.getUnreadCount(),
      ]);
      setNotifications(notifs);
      setUnreadCount(countData.unread_count);
    } catch (err) {
      console.error('Failed to fetch notifications:', err);
    }
  };

  useEffect(() => {
    fetchNotifications();
    const interval = setInterval(fetchNotifications, 30000); // Poll every 30s
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const handleClickOutside = (e) => {
      if (panelRef.current && !panelRef.current.contains(e.target)) {
        setOpen(false);
      }
    };
    if (open) document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [open]);

  const handleMarkRead = async (id) => {
    try {
      await api.notifications.markRead(id);
      setNotifications(prev => prev.map(n => n.id === id ? { ...n, is_read: true } : n));
      setUnreadCount(prev => Math.max(0, prev - 1));
    } catch (err) {
      console.error(err);
    }
  };

  const handleMarkAllRead = async () => {
    try {
      await api.notifications.markAllRead();
      setNotifications(prev => prev.map(n => ({ ...n, is_read: true })));
      setUnreadCount(0);
    } catch (err) {
      console.error(err);
    }
  };

  const getNavigateUrl = (notif) => {
    if (notif.related_type === 'alert' && notif.related_id) return `/alert-detail/${notif.related_id}`;
    if (notif.related_type === 'incident' && notif.related_id) return `/incidents/${notif.related_id}`;
    return null;
  };

  const formatTime = (dateStr) => {
    if (!dateStr) return '';
    const d = new Date(dateStr);
    const now = new Date();
    const diffMs = now - d;
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHrs = Math.floor(diffMins / 60);
    if (diffHrs < 24) return `${diffHrs}h ago`;
    return `${Math.floor(diffHrs / 24)}d ago`;
  };

  return (
    <div className="relative" ref={panelRef}>
      {/* Bell Button */}
      <button
        onClick={() => { setOpen(!open); if (!open) fetchNotifications(); }}
        className="relative p-2 rounded-lg hover:bg-card border border-transparent hover:border-border transition group"
      >
        <Bell className="w-5 h-5 text-text-muted group-hover:text-text-main transition" />
        {unreadCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 w-5 h-5 bg-threat text-white text-[10px] font-bold rounded-full flex items-center justify-center animate-pulse">
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </button>

      {/* Dropdown Panel */}
      {open && (
        <div className="absolute right-0 top-full mt-2 w-[420px] max-h-[500px] bg-card border border-border rounded-lg shadow-2xl shadow-black/50 z-50 flex flex-col overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-surface/50">
            <div className="flex items-center gap-2">
              <Bell className="w-4 h-4 text-threat" />
              <h3 className="text-sm font-bold font-mono uppercase text-text-main">Notifications</h3>
              {unreadCount > 0 && (
                <span className="text-[10px] bg-threat/20 text-threat border border-threat/30 px-1.5 py-0.5 rounded font-mono">
                  {unreadCount} new
                </span>
              )}
            </div>
            <div className="flex items-center gap-1">
              {unreadCount > 0 && (
                <button
                  onClick={handleMarkAllRead}
                  className="text-[10px] font-mono uppercase text-text-muted hover:text-safe transition px-2 py-1 rounded hover:bg-safe/10"
                >
                  <CheckCheck className="w-3.5 h-3.5 inline mr-1" />Mark all read
                </button>
              )}
              <button onClick={() => setOpen(false)} className="p-1 hover:bg-surface rounded">
                <X className="w-4 h-4 text-text-muted" />
              </button>
            </div>
          </div>

          {/* Notification List */}
          <div className="overflow-y-auto flex-1">
            {notifications.length === 0 ? (
              <div className="p-8 text-center text-text-muted font-mono text-xs">
                No notifications
              </div>
            ) : (
              notifications.map((notif) => {
                const config = severityConfig[notif.severity] || severityConfig.INFO;
                const Icon = config.icon;
                const navUrl = getNavigateUrl(notif);

                return (
                  <div
                    key={notif.id}
                    className={`px-4 py-3 border-b border-border/50 hover:bg-surface/50 transition cursor-pointer ${
                      !notif.is_read ? 'bg-surface/30' : ''
                    }`}
                    onClick={() => {
                      if (!notif.is_read) handleMarkRead(notif.id);
                      if (navUrl) window.location.href = navUrl;
                    }}
                  >
                    <div className="flex items-start gap-3">
                      <div className={`p-1.5 rounded ${config.bg} border ${config.border} shrink-0 mt-0.5`}>
                        <Icon className={`w-3.5 h-3.5 ${config.text}`} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          {!notif.is_read && <span className={`w-2 h-2 rounded-full ${config.dot} shrink-0`} />}
                          <h4 className={`text-xs font-bold truncate ${notif.is_read ? 'text-text-muted' : 'text-text-main'}`}>
                            {notif.title}
                          </h4>
                        </div>
                        <p className="text-[11px] text-text-muted mt-1 line-clamp-2 font-mono leading-relaxed">
                          {notif.message}
                        </p>
                        <div className="flex items-center justify-between mt-1.5">
                          <span className="text-[10px] text-text-muted font-mono">{formatTime(notif.created_at)}</span>
                          <div className="flex items-center gap-1">
                            <span className={`text-[9px] uppercase px-1.5 py-0.5 rounded border font-mono ${config.bg} ${config.border} ${config.text}`}>
                              {notif.notif_type}
                            </span>
                            {navUrl && <ExternalLink className="w-3 h-3 text-text-muted" />}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Footer */}
          <div className="px-4 py-2 border-t border-border bg-surface/30 text-center">
            <a href="/threat-alerts" className="text-[10px] font-mono uppercase text-text-muted hover:text-threat transition">
              View All Alerts →
            </a>
          </div>
        </div>
      )}
    </div>
  );
}
