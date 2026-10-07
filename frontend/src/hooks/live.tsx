import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { getToken } from "@/api/client";
import type { DemoState, LiveEvent, MetricPoint } from "@/types";

type Listener = (e: LiveEvent) => void;
interface EventsState { connected: boolean; events: LiveEvent[]; phase: { name: string; at: number } | null; subscribe: (fn: Listener) => () => void }
interface MetricsState { metrics: Record<string, Record<string, unknown>>; history: Record<string, MetricPoint[]>; ts: string | null }

const EventsCtx = createContext<EventsState>(null as unknown as EventsState);
const MetricsCtx = createContext<MetricsState>({ metrics: {}, history: {}, ts: null });
const DemoCtx = createContext<DemoState | null>(null);
export const useLive = () => useContext(EventsCtx);
export const useMetrics = () => useContext(MetricsCtx);
export const useDemo = () => useContext(DemoCtx);

export function useLiveEvents(fn: Listener) {
  const { subscribe } = useLive();
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => subscribe((e) => ref.current(e)), [subscribe]);
}

export function LiveProvider({ children, token }: { children: ReactNode; token: string | null }) {
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [phase, setPhase] = useState<EventsState["phase"]>(null);
  const [metrics, setMetrics] = useState<MetricsState>({ metrics: {}, history: {}, ts: null });
  const [demo, setDemo] = useState<DemoState | null>(null);
  const listeners = useRef(new Set<Listener>());
  const subscribe = useCallback((fn: Listener) => {
    listeners.current.add(fn);
    return () => listeners.current.delete(fn);
  }, []);

  useEffect(() => {
    if (!token) return;
    let ws: WebSocket | null = null;
    let retry = 1000;
    let stopped = false;
    let timer: number | undefined;
    const connect = () => {
      const t = getToken();
      if (!t) return;
      ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws?token=${encodeURIComponent(t)}`);
      ws.onopen = () => { setConnected(true); retry = 1000; };
      ws.onclose = () => {
        setConnected(false);
        if (!stopped) timer = window.setTimeout(connect, (retry = Math.min(retry * 2, 10000)));
      };
      ws.onmessage = (msg) => {
        const data = JSON.parse(msg.data);
        if (data.kind === "event") {
          const ev = data.event as LiveEvent;
          if (ev.type === "SELFTEST") return;
          setEvents((prev) => [ev, ...prev].slice(0, 300));
          if (ev.type !== "AUTH_FAILURE") setPhase({ name: ev.phase, at: Date.now() });
          listeners.current.forEach((fn) => fn(ev));
        } else if (data.kind === "metrics") {
          setMetrics((prev) => {
            const history = { ...prev.history };
            for (const [id, m] of Object.entries(data.devices as Record<string, Record<string, number | null>>)) {
              history[id] = [...(history[id] ?? []), { ts: data.ts, cpu: m.cpu ?? null, mem: m.mem ?? null, net: m.net_in_kbps ?? null, latency: m.latency_ms ?? null }].slice(-120);
            }
            return { metrics: data.devices, history, ts: data.ts };
          });
        } else if (data.kind === "demo" || (data.kind === "hello" && data.demo)) {
          setDemo(data.kind === "demo" ? data.state : data.demo);
        }
      };
    };
    connect();
    return () => { stopped = true; window.clearTimeout(timer); ws?.close(); };
  }, [token]);

  return (
    <EventsCtx.Provider value={{ connected, events, phase, subscribe }}>
      <MetricsCtx.Provider value={metrics}>
        <DemoCtx.Provider value={demo}>{children}</DemoCtx.Provider>
      </MetricsCtx.Provider>
    </EventsCtx.Provider>
  );
}
