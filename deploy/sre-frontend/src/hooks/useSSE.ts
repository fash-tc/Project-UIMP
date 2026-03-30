'use client';

import { useEffect, useRef, useState } from 'react';
import { SSEEvent } from '@/lib/types';

export function useSSE(
  url: string,
  onEvent: (event: SSEEvent) => void,
): { connected: boolean } {
  const [connected, setConnected] = useState(false);
  const onEventRef = useRef(onEvent);
  onEventRef.current = onEvent;

  useEffect(() => {
    const es = new EventSource(url);

    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);

    es.addEventListener('state_change', (e: MessageEvent) => {
      try {
        const data: SSEEvent = JSON.parse(e.data);
        onEventRef.current(data);
      } catch {
        // Ignore malformed events
      }
    });

    es.addEventListener('reset', () => {
      // Server says gap is too large — trigger full refetch
      onEventRef.current({ type: '_reset', timestamp: new Date().toISOString() });
    });

    return () => {
      es.close();
      setConnected(false);
    };
  }, [url]);

  return { connected };
}
