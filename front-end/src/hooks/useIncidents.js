import { useQuery } from '@tanstack/react-query';
import api from '../services/api';
import useStore from '../store/useStore';

export const useIncidents = () => {
  const setLastUpdated = useStore((state) => state.setLastUpdated);

  return useQuery({
    queryKey: ['incidents'],
    queryFn: async () => {
      const { data } = await api.get('/incidents');
      setLastUpdated(new Date().toISOString());
      return Array.isArray(data) ? data : [];
    },
    // Rely on WebSocket for real-time updates; no polling needed
    refetchInterval: false,
    refetchIntervalInBackground: false,
    staleTime: Infinity,
    // Retry twice with exponential back-off before surfacing an error
    retry: 2,
    retryDelay: (attempt) => Math.min(1_000 * 2 ** attempt, 15_000),
    // Keep previous data visible during background refetch
    placeholderData: (prev) => prev,
    select: (data) => {
      if (!Array.isArray(data)) return [];
      const seen = new Set();
      return data.reduce((acc, item) => {
        // Backend uses incident_id; normalise to `id` for UI consistency
        const id = item.incident_id || item.id;
        if (id && !seen.has(id)) {
          seen.add(id);
          acc.push({ ...item, id });
        }
        return acc;
      }, []);
    },
  });
};
