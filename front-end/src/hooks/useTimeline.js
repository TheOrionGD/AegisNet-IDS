import { useQuery } from '@tanstack/react-query';
import api from '../services/api';

export const useTimeline = (hours = 24) => {
  return useQuery({
    queryKey: ['timeline', hours],
    queryFn: async () => {
      const { data } = await api.get(`/timeline?hours=${hours}`);
      return data.data || [];
    },
    refetchInterval: 60000,
    staleTime: 30000,
  });
};
