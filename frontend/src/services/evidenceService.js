import api from './api';

export const evidenceService = {
  getAll: (caseId) => api.get('/evidence', { params: { case_id: caseId } }),
  getById: (id) => api.get(`/evidence/${id}`),
  upload: (formData) => api.post('/evidence/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }),
  verify: (id, verifierName) => api.post(`/evidence/${id}/verify`, null, {
    params: { verifier_name: verifierName },
  }),
  getChainOfCustody: (id) => api.get(`/evidence/${id}/chain-of-custody`),
  addChainOfCustodyEntry: (id, data) => api.post(`/evidence/${id}/chain-of-custody`, data),
  quickVerifyFile: (formData) => api.post('/integrity/verify-file', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }),
};

