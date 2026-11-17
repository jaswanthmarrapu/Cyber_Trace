import api from './api';

export const ipService = {
  investigate: (ipAddress, caseId) => api.post('/ip/investigate', { ip_address: ipAddress, case_id: caseId }),
  getHistory: (caseId) => api.get('/ip/history', { params: { case_id: caseId } }),
};

