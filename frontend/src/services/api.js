import axios from 'axios';

const getApiBaseUrl = () => {
  if (process.env.REACT_APP_API_URL) {
    const envUrl = process.env.REACT_APP_API_URL.trim();
    return envUrl.endsWith('/api') ? envUrl : `${envUrl.replace(/\/+$/, '')}/api`;
  }
  if (typeof window !== 'undefined' && window.location && window.location.origin) {
    if (!window.location.hostname.includes('localhost') && !window.location.hostname.includes('127.0.0.1')) {
      return `${window.location.origin}/api`;
    }
  }
  return 'http://localhost:5000/api';
};

export const API_BASE_URL = getApiBaseUrl();
export const API_HOST_URL = API_BASE_URL.replace(/\/api\/?$/, '');

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Request interceptor adding JWT token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('netshield_token');
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor handling 401 Unauthorized
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('netshield_token');
      localStorage.removeItem('netshield_user');
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

export default api;
