import { useQuery } from '@tanstack/react-query';
import api from '../services/api';

export const useTopIPs = (limit = 10) => {
  return useQuery({
    queryKey: ['ips', 'top', limit],
    queryFn: async () => {
      const { data } = await api.get(`/ips/top?limit=${limit}`);
      return data.data || [];
    },
    refetchInterval: 30000,
    staleTime: 20000,
  });
};
