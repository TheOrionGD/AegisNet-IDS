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
      return data;
    },
    refetchInterval: 10000, // Poll every 10s as a fallback to WebSockets
    staleTime: 5000,
  });
};
