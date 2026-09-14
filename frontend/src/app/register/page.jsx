'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { Shield, Lock, Mail, AlertCircle, Phone, User as UserIcon } from 'lucide-react';
import { api } from '../../lib/api';

export default function RegisterPage() {
  const router = useRouter();
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    phone: '',
    password: '',
    role: 'analyst'
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const data = await api.auth.register(formData);
      localStorage.setItem('netshield_token', data.access_token);
      localStorage.setItem('netshield_user', JSON.stringify(data.user));
      router.push('/dashboard');
    } catch (err) {
      setError(err.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-bg flex items-center justify-center p-4 font-mono">
      <div className="w-full max-w-md bg-card border border-border rounded shadow-2xl p-8 relative overflow-hidden">
        {/* Decorative Grid */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:24px_24px] pointer-events-none" />

        <div className="relative z-10">
          <div className="flex flex-col items-center mb-8">
            <div className="w-16 h-16 bg-surface border border-border rounded-lg flex items-center justify-center text-threat mb-4 shadow-[0_0_15px_rgba(255,59,59,0.2)]">
              <Shield className="w-8 h-8" />
            </div>
            <h1 className="text-2xl font-bold font-sans tracking-tight text-text-main">
              NETSHIELD <span className="text-threat">AI</span>
            </h1>
            <p className="text-xs text-text-muted mt-2 tracking-widest uppercase">
              Operator Authorization
            </p>
          </div>

          {error && (
            <div className="mb-6 p-3 bg-threat/10 border border-threat/20 rounded flex items-start gap-3 text-threat text-sm">
              <AlertCircle className="w-5 h-5 shrink-0 mt-0.5" />
              <p>{error}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs text-text-muted mb-1.5 uppercase tracking-wider">Full Name</label>
              <div className="relative">
                <UserIcon className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  required
                  value={formData.name}
                  onChange={(e) => setFormData({...formData, name: e.target.value})}
                  className="w-full bg-surface border border-border rounded pl-10 pr-4 py-2.5 text-sm text-text-main focus:outline-none focus:border-threat/50 transition-colors"
                  placeholder="John Doe"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs text-text-muted mb-1.5 uppercase tracking-wider">Email Address</label>
              <div className="relative">
                <Mail className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="email"
                  required
                  value={formData.email}
                  onChange={(e) => setFormData({...formData, email: e.target.value})}
                  className="w-full bg-surface border border-border rounded pl-10 pr-4 py-2.5 text-sm text-text-main focus:outline-none focus:border-threat/50 transition-colors"
                  placeholder="operator@netshield.ai"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs text-text-muted mb-1.5 uppercase tracking-wider">Phone (Optional)</label>
              <div className="relative">
                <Phone className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="tel"
                  value={formData.phone}
                  onChange={(e) => setFormData({...formData, phone: e.target.value})}
                  className="w-full bg-surface border border-border rounded pl-10 pr-4 py-2.5 text-sm text-text-main focus:outline-none focus:border-threat/50 transition-colors"
                  placeholder="+1-555-0100"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs text-text-muted mb-1.5 uppercase tracking-wider">Operator Role</label>
              <select
                value={formData.role}
                onChange={(e) => setFormData({...formData, role: e.target.value})}
                className="w-full bg-surface border border-border rounded px-4 py-2.5 text-sm text-text-main focus:outline-none focus:border-threat/50 transition-colors appearance-none"
              >
                <option value="admin">Administrator (Full Access)</option>
                <option value="soc_manager">SOC Manager (Team & Response)</option>
                <option value="analyst">Security Analyst (Operations)</option>
                <option value="viewer">SOC Viewer (Read Only)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs text-text-muted mb-1.5 uppercase tracking-wider">Access Code (Password)</label>
              <div className="relative">
                <Lock className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="password"
                  required
                  value={formData.password}
                  onChange={(e) => setFormData({...formData, password: e.target.value})}
                  className="w-full bg-surface border border-border rounded pl-10 pr-4 py-2.5 text-sm text-text-main focus:outline-none focus:border-threat/50 transition-colors"
                  placeholder="••••••••"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-threat hover:bg-red-600 text-white font-bold py-2.5 rounded transition-colors uppercase tracking-widest text-sm mt-6 flex justify-center items-center"
            >
              {loading ? 'Initializing...' : 'Authorize Access'}
            </button>
          </form>

          <div className="mt-6 text-center">
            <p className="text-xs text-text-muted">
              Already have authorization?{' '}
              <Link href="/login" className="text-threat hover:underline">
                Initialize Session
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
