import { useQuery } from '@tanstack/react-query';
import api from '../services/api';
import useStore from '../store/useStore';

export const useAnomalies = (limit = 50) => {
  const setLastUpdated = useStore((state) => state.setLastUpdated);

  return useQuery({
    queryKey: ['anomalies', limit],
    queryFn: async () => {
      const { data } = await api.get(`/anomalies?limit=${limit}`);
      setLastUpdated(new Date().toISOString());
      return data;
    },
    refetchInterval: 15000,
    staleTime: 10000,
  });
};
