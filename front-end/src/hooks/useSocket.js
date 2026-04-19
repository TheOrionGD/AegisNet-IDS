import { useEffect, useCallback, useRef, useState } from 'react';

const BASE_RECONNECT_DELAY = 2_000;   // 2 s initial
const MAX_RECONNECT_DELAY  = 30_000;  // 30 s cap

/**
 * Custom hook for real-time WebSocket communication in the SOC Dashboard.
 *
 * Key design decisions:
 *  - Per-connection identity check (`ws.current !== socket`) prevents stale
 *    onclose handlers from scheduling spurious reconnects — critical for
 *    React 19 StrictMode which double-invokes effects.
 *  - `isUnmounted` ref provides an additional unmount guard.
 *  - Exponential backoff capped at MAX_RECONNECT_DELAY.
 *  - `send` silently queues-and-drops if socket isn't OPEN yet to avoid
 *    "readyState CONNECTING" errors.
 */
const useSocket = (url, options = {}) => {
  const { onMessage } = options;

  const [data, setData]     = useState(null);
  const [status, setStatus] = useState('connecting');

  const ws               = useRef(null);
  const reconnectTimeout = useRef(null);
  const reconnectDelay   = useRef(BASE_RECONNECT_DELAY);
  const onMessageRef     = useRef(onMessage);
  const isUnmounted      = useRef(false);

  // Keep the callback ref fresh without re-triggering the connect effect
  useEffect(() => {
    onMessageRef.current = onMessage;
  }, [onMessage]);

  const connect = useCallback(function connectFn() {
    if (isUnmounted.current) return;

    // Tear down any lingering socket before opening a new one
    if (ws.current) {
      const old = ws.current;
      old.onopen    = null;
      old.onmessage = null;
      old.onclose   = null;
      old.onerror   = null;
      if (old.readyState !== WebSocket.CLOSED && old.readyState !== WebSocket.CLOSING) {
        old.close();
      }
    }

    let socket;
    try {
      socket = new WebSocket(url);
      ws.current = socket;
    } catch (err) {
      console.error('[WS] Failed to create WebSocket:', err);
      if (!isUnmounted.current) {
        setStatus('disconnected');
        reconnectTimeout.current = setTimeout(connectFn, reconnectDelay.current);
        reconnectDelay.current = Math.min(reconnectDelay.current * 2, MAX_RECONNECT_DELAY);
      }
      return;
    }

    socket.onopen = () => {
      // Stale check: a new connection may have been opened since this one
      if (isUnmounted.current || ws.current !== socket) return;
      console.log('[WS] SOC Stream Connected');
      setStatus('connected');
      reconnectDelay.current = BASE_RECONNECT_DELAY; // Reset backoff on success
      if (reconnectTimeout.current) clearTimeout(reconnectTimeout.current);
    };

    socket.onmessage = (event) => {
      if (isUnmounted.current || ws.current !== socket) return;
      try {
        const payload = JSON.parse(event.data);
        setData(payload);
        onMessageRef.current?.(payload);
      } catch (err) {
        console.error('[WS] Message parse error:', err);
      }
    };

    socket.onclose = (event) => {
      // Ignore if this is a stale socket that was replaced
      if (isUnmounted.current || ws.current !== socket) return;
      console.warn(`[WS] Disconnected (code ${event.code}). Reconnecting in ${reconnectDelay.current / 1000}s…`);
      setStatus('disconnected');
      reconnectTimeout.current = setTimeout(connectFn, reconnectDelay.current);
      reconnectDelay.current = Math.min(reconnectDelay.current * 2, MAX_RECONNECT_DELAY);
    };

    socket.onerror = (err) => {
      // Don't reconnect here — onclose will fire immediately after onerror
      console.error('[WS] Error:', err);
      if (isUnmounted.current || ws.current !== socket) return;
      setStatus('error');
    };
  }, [url]);

  useEffect(() => {
    isUnmounted.current = false;
    connect();

    return () => {
      isUnmounted.current = true;
      if (reconnectTimeout.current) clearTimeout(reconnectTimeout.current);

      if (ws.current) {
        // Remove handlers BEFORE close so the onclose handler doesn't
        // schedule a reconnect during cleanup
        ws.current.onopen    = null;
        ws.current.onmessage = null;
        ws.current.onclose   = null;
        ws.current.onerror   = null;
        if (
          ws.current.readyState !== WebSocket.CLOSED &&
          ws.current.readyState !== WebSocket.CLOSING
        ) {
          ws.current.close();
        }
        ws.current = null;
      }
    };
  }, [connect]);

  /** Send a message only when the socket is OPEN. */
  const send = useCallback((message) => {
    if (ws.current?.readyState === WebSocket.OPEN) {
      ws.current.send(typeof message === 'string' ? message : JSON.stringify(message));
    } else {
      console.warn('[WS] send() called while socket is not OPEN — message dropped.');
    }
  }, []);

  return { data, status, send };
};

export default useSocket;
