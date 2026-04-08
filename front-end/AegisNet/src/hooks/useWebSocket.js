import { useEffect, useState, useRef, useCallback } from 'react';

export const useWebSocket = (url) => {
  const [lastMessage, setLastMessage] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState(null);
  const ws = useRef(null);

  const connect = useCallback(() => {
    try {
      ws.current = new WebSocket(url);

      ws.current.onopen = () => {
        setIsConnected(true);
        setError(null);
        console.log(`[WebSocket] Connected to ${url}`);
      };

      ws.current.onmessage = (event) => {
        if (event.data === 'pong') return;
        try {
          const message = JSON.parse(event.data);
          setLastMessage(message);
        } catch (err) {
          console.error('[WebSocket] parse error:', err);
        }
      };

      ws.current.onerror = (err) => {
        console.error('[WebSocket] Error:', err);
        setError('Connection Error');
      };

      ws.current.onclose = () => {
        setIsConnected(false);
        console.warn('[WebSocket] disconnected. Reconnecting in 5s...');
        // Auto-reconnect with 5s delay
        setTimeout(connect, 5000);
      };
    } catch (err) {
      console.error('[WebSocket] initialization error:', err);
      setTimeout(connect, 5000);
    }
  }, [url]);

  useEffect(() => {
    connect();
    
    // Heartbeat to keep connection alive
    const interval = setInterval(() => {
      if (ws.current && ws.current.readyState === WebSocket.OPEN) {
        ws.current.send('ping');
      }
    }, 15000);

    return () => {
      clearInterval(interval);
      if (ws.current) {
        // Prevent auto-reconnect on unmount
        ws.current.onclose = null;
        ws.current.close();
      }
    };
  }, [connect]);

  return { lastMessage, isConnected, error };
};
