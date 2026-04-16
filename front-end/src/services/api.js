import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:2345',
});

// Request interceptor: Attach JWT token if available
api.interceptors.request.use(
  (config) => {
    try {
      const storage = localStorage.getItem('cns-siem-store');
      if (storage) {
        const { state } = JSON.parse(storage);
        if (state.token) {
          config.headers.Authorization = `Bearer ${state.token}`;
        }
      }
    } catch (err) {
      console.error('Error reading token from storage:', err);
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor: Handle expired tokens
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      // Clear store and redirect if unauthorized
      localStorage.removeItem('cns-siem-store');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default api;

