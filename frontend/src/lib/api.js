const API_BASE_URL = typeof process !== 'undefined' && process.env && process.env.NEXT_PUBLIC_API_URL 
  ? `${process.env.NEXT_PUBLIC_API_URL}/api`
  : 'https://netshield-ai-2.onrender.com/api';

/**
 * Helper to get the auth token from local storage
 */
function getToken() {
  if (typeof window !== 'undefined') {
    return localStorage.getItem('netshield_token');
  }
  return null;
}

/**
 * Standardized fetch wrapper that includes auth token and error handling
 */
async function fetchWithAuth(endpoint, options = {}) {
  const token = getToken();
  
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    ...options.headers,
  };

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errorMessage = 'An error occurred';
    try {
      const errorData = await response.json();
      errorMessage = errorData.detail || errorData.message || errorMessage;
    } catch {
      errorMessage = response.statusText;
    }
    throw new Error(errorMessage);
  }

  return response.json();
}

/**
 * Helper to build query strings without undefined/null values
 */
function buildQueryString(params = {}) {
  const clean = Object.fromEntries(Object.entries(params).filter(([_, v]) => v != null && v !== ''));
  return new URLSearchParams(clean).toString();
}

export const api = {
  // Auth
  auth: {
    login: (data) => fetchWithAuth('/auth/login', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
    register: (data) => fetchWithAuth('/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
    getMe: () => fetchWithAuth('/auth/me'),
  },

  // Traffic
  traffic: {
    getSummary: () => fetchWithAuth('/traffic/summary'),
    getStats: (dataset) => fetchWithAuth(`/traffic/stats${dataset ? `?dataset=${dataset}` : ''}`),
    getRecords: (params = {}) => {
      const qs = buildQueryString(params);
      return fetchWithAuth(`/traffic/records?${qs}`);
    },
    getProtocols: () => fetchWithAuth('/traffic/protocols'),
    getPorts: () => fetchWithAuth('/traffic/ports'),
    simulateAttack: (scenario = 'ddos') => fetchWithAuth(`/traffic/simulate-attack?scenario=${scenario}`, {
      method: 'POST',
    }),
  },

  // Alerts
  alerts: {
    getStats: () => fetchWithAuth('/alerts/stats'),
    getAlerts: (params = {}) => {
      const qs = buildQueryString(params);
      return fetchWithAuth(`/alerts/?${qs}`);
    },
    getAlert: (alertId) => fetchWithAuth(`/alerts/${alertId}`),
    updateStatus: (alertId, status) => fetchWithAuth(`/alerts/${alertId}/status?new_status=${status}`, {
      method: 'PATCH',
    }),
    updateAlert: (alertId, data) => fetchWithAuth(`/alerts/${alertId}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
    getTimeline: (days = 7) => fetchWithAuth(`/alerts/timeline?days=${days}`),
    getAttackTypes: () => fetchWithAuth('/alerts/attack-types'),
  },

  // Anomaly Detection
  anomaly: {
    getSummary: () => fetchWithAuth('/anomaly/summary'),
    detect: (data) => fetchWithAuth('/anomaly/detect', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
    predictSingle: (data) => fetchWithAuth('/anomaly/predict', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  },

  // Models
  models: {
    getComparison: () => fetchWithAuth('/models/comparison'),
    getAvailable: () => fetchWithAuth('/models/available'),
    getMetrics: (dataset) => fetchWithAuth(`/models/metrics${dataset ? `/${dataset}` : ''}`),
    getInfo: (modelKey) => fetchWithAuth(`/models/info/${modelKey}`),
  },

  // Reports
  reports: {
    getRiskSummary: () => fetchWithAuth('/reports/risk-summary'),
    list: () => fetchWithAuth('/reports/'),
    generate: (data) => fetchWithAuth('/reports/generate', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
    downloadUrl: (reportId) => `${API_BASE_URL}/reports/download/${reportId}`,
  },

  // Incidents & SOAR
  incidents: {
    list: (params = {}) => {
      const qs = buildQueryString(params);
      return fetchWithAuth(`/incidents/?${qs}`);
    },
    get: (id) => fetchWithAuth(`/incidents/${id}`),
    create: (data) => fetchWithAuth('/incidents/', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
    update: (id, data) => fetchWithAuth(`/incidents/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
    getNotes: (id) => fetchWithAuth(`/incidents/${id}/notes`),
    addNote: (id, data) => fetchWithAuth(`/incidents/${id}/notes`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),
    getAlerts: (id) => fetchWithAuth(`/incidents/${id}/alerts`),
    linkAlerts: (id, alertIds) => fetchWithAuth(`/incidents/${id}/link-alerts`, {
      method: 'POST',
      body: JSON.stringify(alertIds),
    }),
    getMetrics: () => fetchWithAuth('/incidents/metrics'),
    executeSoar: (id, data) => fetchWithAuth(`/incidents/${id}/soar`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),
    getSoarActions: (id) => fetchWithAuth(`/incidents/${id}/soar-actions`),
    getRecentSoarActions: () => fetchWithAuth('/incidents/soar-actions/recent'),
  },

  // Notifications
  notifications: {
    list: (params = {}) => {
      const qs = buildQueryString(params);
      return fetchWithAuth(`/notifications/?${qs}`);
    },
    getUnreadCount: () => fetchWithAuth('/notifications/unread-count'),
    markRead: (id) => fetchWithAuth(`/notifications/${id}/read`, { method: 'PATCH' }),
    markAllRead: () => fetchWithAuth('/notifications/mark-all-read', { method: 'POST' }),
    delete: (id) => fetchWithAuth(`/notifications/${id}`, { method: 'DELETE' }),
  },

  // Threat Intelligence & Rules
  threatIntel: {
    getIndicators: (params = {}) => {
      const qs = buildQueryString(params);
      return fetchWithAuth(`/threat-intel/indicators?${qs}`);
    },
    getIndicator: (id) => fetchWithAuth(`/threat-intel/indicators/${id}`),
    createIndicator: (data) => fetchWithAuth('/threat-intel/indicators', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
    getSummary: () => fetchWithAuth('/threat-intel/summary'),
    getReport: () => fetchWithAuth('/threat-intel/report'),
    getMitreMatrix: () => fetchWithAuth('/threat-intel/mitre-matrix'),
    getDetectionRules: (params = {}) => {
      const qs = buildQueryString(params);
      return fetchWithAuth(`/threat-intel/detection-rules?${qs}`);
    },
    createDetectionRule: (data) => fetchWithAuth('/threat-intel/detection-rules', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
    updateDetectionRule: (id, data) => fetchWithAuth(`/threat-intel/detection-rules/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
    deleteDetectionRule: (id) => fetchWithAuth(`/threat-intel/detection-rules/${id}`, {
      method: 'DELETE',
    }),
  },

  // Analytics
  analytics: {
    getSecurityOverview: () => fetchWithAuth('/analytics/security-overview'),
    getAlertsTimeline: () => fetchWithAuth('/analytics/alerts-timeline'),
    getAttackDistribution: () => fetchWithAuth('/analytics/attack-distribution'),
    getTopAttackers: (limit = 10) => fetchWithAuth(`/analytics/top-attackers?limit=${limit}`),
    getTopTargets: (limit = 10) => fetchWithAuth(`/analytics/top-targets?limit=${limit}`),
    getNetworkAnalytics: () => fetchWithAuth('/analytics/network-analytics'),
    getIncidentMetrics: () => fetchWithAuth('/analytics/incident-metrics'),
  },

  platform: {
    users: () => fetchWithAuth('/users'),
    audit: () => fetchWithAuth('/audit'),
    webhooks: () => fetchWithAuth('/webhooks'),
    createWebhook: (data) => fetchWithAuth('/webhooks', { method: 'POST', body: JSON.stringify(data) }),
  },
};
