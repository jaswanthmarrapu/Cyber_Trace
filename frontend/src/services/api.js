import axios from 'axios';

// In production (Vercel deployment), VITE_API_URL points to the Render backend (e.g. https://cybertrace-api.onrender.com/api/v1)
// In local development or proxy mode, it seamlessly defaults to '/api/v1'
const rawBaseUrl = import.meta.env.VITE_API_URL || '/api/v1';
const baseURL = rawBaseUrl.endsWith('/') ? rawBaseUrl.slice(0, -1) : rawBaseUrl;

const api = axios.create({
  baseURL: baseURL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
});

// Attach JWT Bearer Token to all outgoing requests
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('cybertrace_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status;
    const url = error.config?.url || '';

    // Handle 401 Unauthorized (ignore for login/register/forgot-password attempts)
    if (status === 401 && !url.includes('/auth/login') && !url.includes('/auth/register') && !url.includes('/auth/forgot-password')) {
      console.warn('[CyberTrace Auth]: Session expired or unauthorized. Clearing credentials.');
      localStorage.removeItem('cybertrace_token');
      localStorage.removeItem('cybertrace_user');
      window.dispatchEvent(new Event('cybertrace-unauthorized'));
    }

    const errorMsg =
      error.response?.data?.detail ||
      error.response?.data?.message ||
      error.message ||
      'An unknown network error occurred';
    console.error('[CyberTrace API Error]:', errorMsg);
    return Promise.reject(error);
  }
);

export default api;

