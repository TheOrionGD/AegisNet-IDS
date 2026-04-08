import { useEffect, useCallback, useRef, useState } from 'react';

/**
 * Custom hook for real-time WebSocket communication in the SOC Dashboard.
 * Handles auto-reconnection, heartbeats, and event routing.
 */
const useSocket = (url) => {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState('connecting');
  const ws = useRef(null);
  const reconnectTimeout = useRef(null);

  const connect = useCallback(() => {
    try {
      console.log(`Connecting to SOC Event Stream: ${url}`);
      ws.current = new WebSocket(url);

      ws.current.onopen = () => {
        console.log('SOC Stream Connected');
        setStatus('connected');
        // Clear any existing reconnect timer
        if (reconnectTimeout.current) clearTimeout(reconnectTimeout.current);
      };

      ws.current.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          // Standard payload structure: { type: "alert", data: {...}, timestamp: "..." }
          setData(payload);
        } catch (err) {
          console.error('WS Data parsing error:', err);
        }
      };

      ws.current.onclose = () => {
        console.warn('SOC Stream Disconnected. Reconnecting in 3s...');
        setStatus('disconnected');
        reconnectTimeout.current = setTimeout(connect, 3000);
      };

      ws.current.onerror = (err) => {
        console.error('WS Error:', err);
        ws.current.close();
      };
    } catch (err) {
      console.error('Failed to establish WS connection:', err);
      reconnectTimeout.current = setTimeout(connect, 3000);
    }
  }, [url]);

  useEffect(() => {
    connect();
    return () => {
      if (ws.current) ws.current.close();
      if (reconnectTimeout.current) clearTimeout(reconnectTimeout.current);
    };
  }, [connect]);

  const send = useCallback((message) => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.send(typeof message === 'string' ? message : JSON.stringify(message));
    }
  }, []);

  return { data, status, send };
};

export default useSocket;
