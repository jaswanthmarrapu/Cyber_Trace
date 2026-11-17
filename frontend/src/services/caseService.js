import api from './api';

export const caseService = {
  getAll: (status) => api.get('/cases', { params: { status } }),
  getById: (id) => api.get(`/cases/${id}`),
  create: (data) => api.post('/cases', data),
  updateStatus: (id, status) => api.patch(`/cases/${id}/status`, { status }),
  getDashboardStats: () => api.get('/dashboard/stats'),
};

