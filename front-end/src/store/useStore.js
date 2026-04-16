import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';

const useStore = create(
  persist(
    (set) => ({
      // --- Auth State ---
      user: null,
      token: null,
      isAuthenticated: false,
      
      setUser: (user) => set({ user, isAuthenticated: !!user }),
      setToken: (token) => set({ token }),
      
      login: (userData, token) => set({ 
        user: userData, 
        token, 
        isAuthenticated: true 
      }),
      
      logout: () => set({ 
        user: null, 
        token: null, 
        isAuthenticated: false,
        selectedIncident: null 
      }),

      // --- UI State ---
      isSidebarOpen: true,
      toggleSidebar: () => set((state) => ({ isSidebarOpen: !state.isSidebarOpen })),

      // --- SIEM State ---
      selectedIncident: null,
      setSelectedIncident: (incident) => set({ selectedIncident: incident }),
      
      lastUpdated: new Date().toISOString(),
      setLastUpdated: (timestamp) => set({ lastUpdated: timestamp }),
    }),
    {
      name: 'cns-siem-store', // name of the item in storage (must be unique)
      storage: createJSONStorage(() => localStorage),
    }
  )
);

export default useStore;

