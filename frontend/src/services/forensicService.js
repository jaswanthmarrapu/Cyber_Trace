import api from './api';

export const forensicService = {
  analyze: (evidenceId) => api.post(`/forensics/analyze/${evidenceId}`),
  getResults: (evidenceId) => api.get(`/forensics/results/${evidenceId}`),
};

