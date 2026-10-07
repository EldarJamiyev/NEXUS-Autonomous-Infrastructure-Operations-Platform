import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, getToken, setToken } from "./client";

export type Role = "VIEWER" | "OPERATOR" | "ENGINEER" | "ADMIN";
export interface Principal { user_id: string; name: string; role: Role; method: string }
interface AuthConfig { demo_auth: boolean; users: { id: string; name: string; role: Role }[]; environment: string; version: string }
interface AuthState { principal: Principal | null; config: AuthConfig | null; login: (user: string) => Promise<void>; useKey: (key: string) => Promise<void>; can: (role: Role) => boolean; ready: boolean }

const RANK: Record<Role, number> = { VIEWER: 0, OPERATOR: 1, ENGINEER: 2, ADMIN: 3 };
const Ctx = createContext<AuthState>(null as unknown as AuthState);
export const useAuth = () => useContext(Ctx);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const [ready, setReady] = useState(false);

  const login = useCallback(async (user: string) => {
    const r = await api.post<{ token: string; principal: Principal }>("/api/auth/demo-login", { user_id: user });
    setToken(r.token);
    localStorage.setItem("nexus-operator", user);
    setPrincipal(r.principal);
  }, []);

  const useKey = useCallback(async (key: string) => {
    setToken(key);
    setPrincipal(await api.get<Principal>("/api/auth/me"));
  }, []);

  useEffect(() => {
    (async () => {
      const cfg = await api.get<AuthConfig>("/api/auth/config");
      setConfig(cfg);
      try {
        if (getToken()) setPrincipal(await api.get<Principal>("/api/auth/me"));
        else if (cfg.demo_auth) await login(localStorage.getItem("nexus-operator") ?? "eldar");
      } catch {
        setToken(null);
        if (cfg.demo_auth) await login(localStorage.getItem("nexus-operator") ?? "eldar");
      }
      setReady(true);
    })().catch(() => setReady(true));
  }, [login]);

  useEffect(() => {
    const onExpired = () => {
      if (config?.demo_auth) login(localStorage.getItem("nexus-operator") ?? "eldar").catch(() => undefined);
      else setPrincipal(null);
    };
    window.addEventListener("nexus:unauthorized", onExpired);
    return () => window.removeEventListener("nexus:unauthorized", onExpired);
  }, [config, login]);

  const can = useCallback((role: Role) => !!principal && RANK[principal.role] >= RANK[role], [principal]);
  return <Ctx.Provider value={{ principal, config, login, useKey, can, ready }}>{children}</Ctx.Provider>;
}
