export class ApiError extends Error {
  constructor(public status: number, public detail: string) {
    super(detail);
  }
}

const KEY = "nexus-token";
let token: string | null = sessionStorage.getItem(KEY);

export function setToken(value: string | null) {
  token = value;
  if (value) sessionStorage.setItem(KEY, value);
  else sessionStorage.removeItem(KEY);
}
export const getToken = () => token;

function detailOf(data: unknown, fallback: string): string {
  if (typeof data === "string") return data || fallback;
  const d = (data as { detail?: unknown })?.detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) return d.map((x: { loc?: string[]; msg?: string }) => `${(x.loc ?? []).slice(1).join(".")}: ${x.msg}`).join("; ");
  return fallback;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401) window.dispatchEvent(new Event("nexus:unauthorized"));
  const type = res.headers.get("content-type") ?? "";
  const data = type.includes("json") ? await res.json() : await res.text();
  if (!res.ok) throw new ApiError(res.status, detailOf(data, res.statusText));
  return data as T;
}

export const api = {
  get: <T,>(path: string) => request<T>("GET", path),
  post: <T,>(path: string, body: unknown = {}) => request<T>("POST", path, body),
  put: <T,>(path: string, body: unknown = {}) => request<T>("PUT", path, body),
};

export const qs = (params: Record<string, string | number | undefined | null>) =>
  new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== "").map(([k, v]) => [k, String(v)])).toString();
