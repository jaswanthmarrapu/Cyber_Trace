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

api.interceptors.response.use(
  (response) => response,
  (error) => {
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

