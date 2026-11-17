import api from './api';

export const reportService = {
  getAll: (caseId) => api.get('/reports', { params: { case_id: caseId } }),
  generate: (caseId, generatedBy) => api.post('/reports/generate', { case_id: caseId, generated_by: generatedBy }),
  getDownloadUrl: (reportId) => `/api/v1/reports/${reportId}/download`,
};

