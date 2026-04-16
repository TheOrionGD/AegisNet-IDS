import { useEffect, useCallback, useRef, useState } from 'react';

/**
 * Custom hook for real-time WebSocket communication in the SOC Dashboard.
 * Handles auto-reconnection, heartbeats, and event routing.
 */
const useSocket = (url, options = {}) => {
  const { onMessage } = options;
  const [data, setData] = useState(null);
  const [status, setStatus] = useState('connecting');
  const ws = useRef(null);
  const reconnectTimeout = useRef(null);
  const onMessageRef = useRef(onMessage);
  const isUnmounted = useRef(false);

  // Keep the ref updated with the latest onMessage callback
  useEffect(() => {
    onMessageRef.current = onMessage;
  }, [onMessage]);

  const connect = useCallback(function connectFn() {
    if (isUnmounted.current) return;

    try {
      console.log(`Connecting to SOC Event Stream: ${url}`);
      ws.current = new WebSocket(url);

      ws.current.onopen = () => {
        if (isUnmounted.current) {
          ws.current.close();
          return;
        }
        console.log('SOC Stream Connected');
        setStatus('connected');
        // Clear any existing reconnect timer
        if (reconnectTimeout.current) clearTimeout(reconnectTimeout.current);
      };

      ws.current.onmessage = (event) => {
        if (isUnmounted.current) return;
        try {
          const payload = JSON.parse(event.data);
          setData(payload);
          if (onMessageRef.current) onMessageRef.current(payload);
        } catch (err) {
          console.error('WS Data parsing error:', err);
        }
      };

      ws.current.onclose = () => {
        if (isUnmounted.current) return;
        console.warn('SOC Stream Disconnected. Reconnecting in 3s...');
        setStatus('disconnected');
        reconnectTimeout.current = setTimeout(connectFn, 3000);
      };

      ws.current.onerror = (err) => {
        if (isUnmounted.current) return;
        console.error('WS Error:', err);
        // Browser triggers close automatically after error in many cases, 
        // but we ensure it's handled.
        if (ws.current && ws.current.readyState === WebSocket.OPEN) {
          ws.current.close();
        }
      };
    } catch (err) {
      if (isUnmounted.current) return;
      console.error('Failed to establish WS connection:', err);
      reconnectTimeout.current = setTimeout(connectFn, 3000);
    }
  }, [url]);

  useEffect(() => {
    isUnmounted.current = false;
    connect();
    return () => {
      isUnmounted.current = true;
      if (reconnectTimeout.current) clearTimeout(reconnectTimeout.current);
      if (ws.current) {
        // Only close if it's not already closed or closing
        if (ws.current.readyState !== WebSocket.CLOSED && ws.current.readyState !== WebSocket.CLOSING) {
          ws.current.close();
        }
        // Remove listeners to avoid side effects during unmount
        ws.current.onopen = null;
        ws.current.onmessage = null;
        ws.current.onclose = null;
        ws.current.onerror = null;
      }
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
