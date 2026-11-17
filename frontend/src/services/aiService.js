import api from './api';

export const aiService = {
  getSummary: (caseId) => api.get(`/ai/summary/${caseId}`),
};

