import { create } from 'zustand';

const useStore = create((set) => ({
  // Global configuration
  isSidebarOpen: true,
  toggleSidebar: () => set((state) => ({ isSidebarOpen: !state.isSidebarOpen })),

  // Theme settings could go here (currently hardcoded as dark)

  // Incident filters & selection 
  selectedIncident: null,
  setSelectedIncident: (incident) => set({ selectedIncident: incident }),
  
  // Dashboard global refresh state 
  lastUpdated: new Date().toISOString(),
  setLastUpdated: (timestamp) => set({ lastUpdated: timestamp }),
}));

export default useStore;
