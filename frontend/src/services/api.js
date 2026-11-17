import axios from 'axios';

// In production (Vercel deployment), VITE_API_URL points to the Render backend (e.g. https://cyber-trace-2htc.onrender.com/api/v1)
// In local development or proxy mode, it seamlessly defaults to '/api/v1'
let rawBaseUrl = (import.meta.env.VITE_API_URL || '').trim();

// Fallback/auto-detect if missing or pointing to outdated placeholder domain
if (!rawBaseUrl || rawBaseUrl.includes('cybertrace-api.onrender.com')) {
  if (typeof window !== 'undefined' && window.location.hostname.includes('vercel.app')) {
    rawBaseUrl = 'https://cyber-trace-2htc.onrender.com/api/v1';
  } else {
    rawBaseUrl = '/api/v1';
  }
}

// Strip any trailing slashes
let baseURL = rawBaseUrl.replace(/\/+$/, '');

// Ensure /api/v1 path suffix is present if a bare host domain was supplied
if (baseURL.startsWith('http') && !baseURL.endsWith('/api/v1')) {
  baseURL = `${baseURL}/api/v1`;
}

const api = axios.create({
  baseURL: baseURL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 60000, // 60s timeout accommodates Render free-tier cold-start wakeups
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
  async (error) => {
    const config = error.config;

    // Dual-channel resilience: If a direct cross-origin call to Render encounters a Network Error
    // on a Vercel deployment (e.g. aggressive browser adblock/CORS shielding), seamlessly retry
    // through the Vercel edge reverse proxy (/api/v1) before reporting failure.
    if (
      error.message === 'Network Error' &&
      config &&
      !config._isRetry &&
      typeof window !== 'undefined' &&
      window.location.hostname.includes('vercel.app') &&
      config.baseURL &&
      config.baseURL.includes('onrender.com')
    ) {
      config._isRetry = true;
      console.warn('[CyberTrace API]: Direct Render CORS connection blocked or sleeping. Retrying seamlessly via Vercel Reverse Proxy...');
      config.baseURL = '/api/v1';
      return api(config);
    }

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

