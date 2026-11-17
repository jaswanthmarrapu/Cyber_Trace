import { useState, useEffect } from 'react';
import { caseService } from '../services/caseService';
import { mockCases } from '../data/mockForensicData';

export function useCases() {
  const [cases, setCases] = useState(mockCases);
  const [activeCase, setActiveCase] = useState(mockCases[0]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchCases = async () => {
    try {
      setLoading(true);
      const res = await caseService.getAll();
      const caseList = res?.data;
      if (Array.isArray(caseList) && caseList.length > 0) {
        setCases(caseList);
        if (!activeCase) {
          setActiveCase(caseList[0]);
        }
      } else {
        setCases(mockCases);
        if (!activeCase) setActiveCase(mockCases[0]);
      }
      setError(null);
    } catch (err) {
      // Graceful offline fallback to comprehensive mock case data
      setCases(mockCases);
      if (!activeCase) setActiveCase(mockCases[0]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  return {
    cases,
    activeCase,
    setActiveCase,
    loading,
    error,
    refreshCases: fetchCases
  };
}
