import React from 'react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import { FaChartLine } from 'react-icons/fa';

const WeeklyAttackTrend = ({ data = [], height = 280, showTitle = true }) => {
  return (
    <div className="netshield-card" style={{ width: '100%', minWidth: 0, boxSizing: 'border-box' }}>
      {showTitle && (
        <div className="netshield-card-header">
          <div className="netshield-card-title">
            <FaChartLine style={{ color: 'var(--primary-green)' }} />
            <span>Weekly Attack Trend</span>
          </div>
          <span className="cyber-chip">Last 7 Days</span>
        </div>
      )}

      {data && data.length >= 2 ? (
        <ResponsiveContainer width="100%" height={height}>
          <AreaChart data={data} margin={{ top: 10, right: 20, left: -10, bottom: 0 }}>
            <defs>
              <linearGradient id="attackGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#22C55E" stopOpacity={0.45}/>
                <stop offset="95%" stopColor="#22C55E" stopOpacity={0.0}/>
              </linearGradient>
              <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#EF4444" stopOpacity={0.5}/>
                <stop offset="95%" stopColor="#EF4444" stopOpacity={0.0}/>
              </linearGradient>
            </defs>
            <XAxis dataKey="short_day" stroke="#64748B" fontSize={11} tickLine={false} />
            <YAxis stroke="#64748B" fontSize={11} tickLine={false} />
            <Tooltip
              contentStyle={{
                backgroundColor: '#0a1628',
                borderColor: 'rgba(34, 197, 94, 0.4)',
                borderRadius: 8,
                color: '#f8fafc',
                fontSize: '0.82rem'
              }}
              labelFormatter={(label, payload) => {
                const item = payload && payload[0]?.payload;
                return item ? `${item.day} (${item.display_date || item.date})` : label;
              }}
            />
            <Legend wrapperStyle={{ fontSize: '0.78rem', paddingTop: 10 }} />
            <Area
              type="monotone"
              dataKey="attacks"
              name="Total Attacks"
              stroke="#22C55E"
              strokeWidth={2.5}
              fillOpacity={1}
              fill="url(#attackGrad)"
              dot={{ r: 4, fill: '#22C55E' }}
              activeDot={{ r: 6 }}
            />
            <Area
              type="monotone"
              dataKey="critical_count"
              name="Critical Threats"
              stroke="#EF4444"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#critGrad)"
              dot={{ r: 4, fill: '#EF4444' }}
              activeDot={{ r: 6 }}
            />
          </AreaChart>
        </ResponsiveContainer>
      ) : data && data.length === 1 ? (
        <div className="single-day-telemetry-container">
          {/* Status Badge */}
          <div className="insufficient-trend-pill">
            <span style={{ fontSize: '0.65rem' }}>●</span> Insufficient trend data
          </div>

          {/* Subtitle & Date */}
          <div className="single-day-subtitle">
            Single-Day Telemetry
          </div>
          <div className="single-day-date">
            {data[0].day ? (data[0].display_date ? `${data[0].day}, ${data[0].display_date}` : data[0].day) : (data[0].display_date || data[0].date || 'Single-Day')}
          </div>

          {/* Compact Aligned Metric Cards */}
          <div className="single-day-metrics-row">
            <div className="single-day-metric-box">
              <div className="single-day-metric-value" style={{ color: 'var(--primary-green, #22C55E)' }}>
                {data[0].attacks?.toLocaleString() ?? 0}
              </div>
              <div className="single-day-metric-label">
                Total Incursions
              </div>
            </div>

            <div className="single-day-metric-box">
              <div className="single-day-metric-value" style={{ color: '#EF4444' }}>
                {data[0].critical_count?.toLocaleString() ?? 0}
              </div>
              <div className="single-day-metric-label">
                Critical Threats
              </div>
            </div>
          </div>

          {/* Explanatory Message - exact user requested wording */}
          <div className="single-day-footer-note">
            Multi-day trend visualization will appear when verified traffic is available across 2 or more distinct days.
          </div>
        </div>
      ) : (
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            textAlign: 'center',
            padding: '30px 20px',
            color: 'var(--text-muted)'
          }}
        >
          <div style={{ fontWeight: 600, color: '#94a3b8', fontSize: '0.95rem', marginBottom: 4 }}>
            No verified trend data available.
          </div>
          <div style={{ fontSize: '0.8rem', color: '#64748b', maxWidth: 360 }}>
            No attack trend telemetry available for the past 7 days.
          </div>
        </div>
      )}
    </div>
  );
};

export default WeeklyAttackTrend;
