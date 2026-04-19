import { useQuery } from '@tanstack/react-query';
import api from '../services/api';
import useStore from '../store/useStore';

export const useAlerts = (limit = 100) => {
  const setLastUpdated = useStore((state) => state.setLastUpdated);

  return useQuery({
    queryKey: ['alerts', limit],
    queryFn: async () => {
      const { data } = await api.get(`/alerts?limit=${limit}`);
      setLastUpdated(new Date().toISOString());
      // Normalise: backend may return null/undefined on empty DB
      return Array.isArray(data) ? data : [];
    },
    // Poll every 10 s as WebSocket fallback
    refetchInterval: 10_000,
    staleTime: 5_000,
    // Retry twice with exponential back-off before surfacing an error
    retry: 2,
    retryDelay: (attempt) => Math.min(1_000 * 2 ** attempt, 15_000),
    // Keep previous data visible while a background refresh is running
    placeholderData: (prev) => prev,
  });
};
