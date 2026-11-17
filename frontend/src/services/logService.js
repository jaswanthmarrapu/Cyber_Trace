import api from './api';

export const logService = {
  uploadLogs: (formData) => api.post('/logs/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }),
  getEvents: (params) => api.get('/logs/events', { params }),
};

