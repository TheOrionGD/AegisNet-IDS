import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:2346',
});

// Request interceptor: Attach JWT token if available
api.interceptors.request.use(
  (config) => {
    try {
      const storage = localStorage.getItem('cns-siem-store');
      if (storage) {
        const { state } = JSON.parse(storage);
        if (state?.token) {
          config.headers.Authorization = `Bearer ${state.token}`;
        }
      }
    } catch (err) {
      console.error('[CNS-API] Error reading token from storage:', err);
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor: Centralised error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response) {
      const { status, data } = error.response;
      let userMessage = 'An unexpected error occurred';
      switch (status) {
        case 401:
          userMessage = 'Session expired. Please log in again.';
          localStorage.removeItem('cns-siem-store');
          window.location.href = '/login';
          break;
        case 403:
          userMessage = 'Access denied. You do not have permission to perform this action.';
          break;
        case 404:
          userMessage = 'The requested resource was not found.';
          break;
        case 503:
          userMessage = 'Service unavailable. The server is temporarily unable to handle the request.';
          break;
        case 500:
          userMessage = 'Server error. Our team has been notified. Please try again later.';
          break;
        default:
          userMessage = data?.detail || error.message;
      }
      // Attach user-friendly message to error object for components
      error.userMessage = userMessage;
      console.error(
        `[CNS-API] Server error ${status} on ${error.config?.url}:`,
        data?.detail || error.message
      );
    } else if (error.request) {
      const userMessage = 'Network error: Unable to reach the server. Check your connection.';
      error.userMessage = userMessage;
      console.error(
        '[CNS-API] No response received. Possible CORS misconfiguration or server unreachable.',
        error.message
      );
    } else {
      const userMessage = 'Request setup error: ' + error.message;
      error.userMessage = userMessage;
      console.error('[CNS-API] Request setup error:', error.message);
    }
    return Promise.reject(error);
  }
);

export default api;
