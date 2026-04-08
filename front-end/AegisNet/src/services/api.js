import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL,
  // Note: No authentication required for Phase 1-3
  // In the future add a token via interceptors.
});

export default api;
