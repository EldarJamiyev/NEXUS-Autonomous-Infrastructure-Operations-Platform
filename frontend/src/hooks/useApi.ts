import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "@/api/client";
import { useLiveEvents } from "./live";

interface Options { refreshOn?: string[]; interval?: number }

/** GET a resource and keep it fresh: refetches when a live event matches one of `refreshOn` (type prefixes). */
export function useApi<T>(path: string | null, opts: Options = {}) {
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);
  const timer = useRef<number | undefined>(undefined);
  const refreshOn = opts.refreshOn ?? [];

  const load = useCallback(async () => {
    if (!path) return;
    try {
      const result = await api.get<T>(path);
      setData(result);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, String(e)));
    } finally {
      setLoading(false);
    }
  }, [path]);

  useEffect(() => {
    setLoading(true);
    load();
  }, [load]);

  useEffect(() => {
    if (!opts.interval) return;
    const id = window.setInterval(load, opts.interval);
    return () => window.clearInterval(id);
  }, [load, opts.interval]);

  useLiveEvents((e) => {
    if (!refreshOn.length) return;
    if (refreshOn.some((p) => p === "*" || e.type.startsWith(p))) {
      window.clearTimeout(timer.current);
      timer.current = window.setTimeout(load, 450);
    }
  });

  return { data, error, loading, reload: load, setData };
}
