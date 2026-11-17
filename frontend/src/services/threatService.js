import api from './api';

export const threatService = {
  getDetections: (caseId) => api.get('/threats/detections', { params: { case_id: caseId } }),
};

