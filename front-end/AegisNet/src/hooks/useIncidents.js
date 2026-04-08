import { useQuery } from '@tanstack/react-query';
import api from '../services/api';
import useStore from '../store/useStore';

export const useIncidents = () => {
  const setLastUpdated = useStore((state) => state.setLastUpdated);

  return useQuery({
    queryKey: ['incidents'],
    queryFn: async () => {
      const { data } = await api.get('/incidents');
      // Update global timestamp when data arrives
      setLastUpdated(new Date().toISOString());
      return data;
    },
    // Disable REST polling - relying on WebSockets for real-time updates
    refetchInterval: false,
    refetchIntervalInBackground: false,
    staleTime: Infinity,
    // Attempt deduplication based on ID just in case
    select: (data) => {
      if (!Array.isArray(data)) return [];
      const unique = [];
      const ids = new Set();
      data.forEach(item => {
        if (!ids.has(item.id)) {
          unique.push(item);
          ids.add(item.id);
        }
      });
      return unique;
    }
  });
};
