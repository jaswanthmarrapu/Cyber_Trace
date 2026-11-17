import api from './api';

export const timelineService = {
  getTimeline: (caseId) => api.get(`/timeline/${caseId}`),
  reconstruct: (caseId) => api.post(`/timeline/${caseId}/reconstruct`),
  addEvent: (caseId, eventData) => api.post(`/timeline/${caseId}/add-event`, eventData),
};

