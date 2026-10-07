import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import {
  BookOpen, Bot, Cable, CalendarClock, FileClock, FileText, Fingerprint, FlaskConical, Gauge, GitBranch, GitCompare, History, KeyRound, LayoutDashboard,
  LifeBuoy, Menu, MessagesSquare, Moon, Network, Play, ScrollText, Search, Server, Settings, ShieldCheck, Siren, Sun, Sunrise, Workflow, Wrench,
} from "lucide-react";
import { useAuth } from "@/api/auth";
import { api } from "@/api/client";
import { useApi } from "@/hooks/useApi";
import { useLive } from "@/hooks/live";
import type { Status } from "@/types";
import { LoopStrip } from "@/components/live";
import { Button, Pill, cx, inputClass } from "@/components/ui";
import { useAction } from "@/components/feedback";
import { CommandPalette } from "@/components/CommandPalette";
import { Presentation } from "@/components/Presentation";
import { Copilot } from "@/components/Copilot";

type NavItem = [string, string, typeof LayoutDashboard, string?];
const NAV: { group: string; items: NavItem[] }[] = [
  { group: "Observe", items: [["/", "Overview", LayoutDashboard], ["/twin", "Digital twin", Network], ["/network", "Network", Cable], ["/devices", "Devices", Server], ["/identity", "Identity", Fingerprint]] },
  { group: "Decide", items: [["/risk", "Risk", Gauge], ["/access", "Access", KeyRound], ["/policies", "Policies", ScrollText], ["/drift", "Drift", GitCompare, "drift"], ["/changes", "Changes", CalendarClock], ["/approvals", "Approvals", ShieldCheck, "approvals"]] },
  { group: "Act", items: [["/incidents", "Incidents", Siren, "incidents"], ["/autoheal", "Auto-healing", Wrench], ["/runbooks", "Runbooks", BookOpen], ["/chaos", "Chaos lab", FlaskConical]] },
  { group: "Understand", items: [["/timemachine", "Time machine", History], ["/whatif", "What-if", GitBranch], ["/dependencies", "Dependencies", Workflow], ["/audit", "Audit", FileClock], ["/chatops", "ChatOps", MessagesSquare], ["/reports", "Reports", FileText]] },
  { group: "Operate", items: [["/operations", "Daily operations", Sunrise], ["/troubleshooting", "Troubleshooting", LifeBuoy], ["/system", "System", Settings]] },
];
const MODE_TONE: Record<string, "ok" | "warn" | "info" | "crit"> = { NORMAL: "ok", DEGRADED: "warn", RECOVERY: "info", EMERGENCY: "crit" };

function ThemeToggle() {
  const system = () => (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const [pinned, setPinned] = useState<string | null>(localStorage.getItem("nexus-color-scheme"));
  const effective = pinned ?? system();
  const toggle = () => {
    const next = pinned ? null : effective === "dark" ? "light" : "dark";
    const meta = document.querySelector('meta[name="color-scheme"]') as HTMLMetaElement;
    if (next) { localStorage.setItem("nexus-color-scheme", next); document.documentElement.dataset.theme = next; meta.content = next; }
    else { localStorage.removeItem("nexus-color-scheme"); delete document.documentElement.dataset.theme; meta.content = "light dark"; }
    setPinned(next);
  };
  return (
    <button onClick={toggle} className="rounded p-1.5 text-muted hover:bg-inset hover:text-ink" aria-label={pinned ? "Follow system theme" : `Switch to ${effective === "dark" ? "light" : "dark"} theme`}
      title={pinned ? "Follow system theme" : `Switch to ${effective === "dark" ? "light" : "dark"}`}>
      {effective === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
    </button>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const { principal, config, login } = useAuth();
  const { data: status, reload } = useApi<Status>("/api/status", { refreshOn: ["INCIDENT", "DRIFT", "APPROVAL", "SYSTEM_MODE", "QUARANTINE", "LEASE", "REMEDIATION", "SETTING"], interval: 15000 });
  const [palette, setPalette] = useState(false);
  const [copilot, setCopilot] = useState(false);
  const [navOpen, setNavOpen] = useState(false);
  const { run, busy } = useAction();
  const location = useLocation();
  const { connected } = useLive();
  useEffect(() => setNavOpen(false), [location.pathname]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPalette((p) => !p); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  const badges: Record<string, number> = { incidents: status?.counts.open_incidents ?? 0, approvals: status?.counts.pending_approvals ?? 0, drift: status?.counts.drift_events ?? 0 };
  const mode = status?.mode.mode ?? "NORMAL";

  return (
    <div className="flex h-full">
      <aside className={cx("fixed inset-y-0 left-0 z-40 w-[214px] shrink-0 overflow-y-auto border-r border-line bg-panel transition-transform lg:static lg:translate-x-0", navOpen ? "translate-x-0" : "-translate-x-full")}>
        <div className="flex h-12 items-center gap-2 border-b border-line px-4">
          <img src="/favicon.svg" alt="" className="h-6 w-6" />
          <div className="leading-tight">
            <div className="font-cond text-[15px] font-semibold tracking-[0.06em]">NEXUS OMNIS</div>
            <div className="font-mono text-[10px] text-muted">v{status?.version ?? config?.version ?? "0.1.0"}</div>
          </div>
        </div>
        <nav className="px-2 py-3" aria-label="Main">
          {NAV.map((g) => (
            <div key={g.group} className="mb-3">
              <div className="px-2 pb-1 text-[11px] font-medium text-muted">{g.group}</div>
              {g.items.map(([to, label, Icon, badge]) => (
                <NavLink key={to} to={to} end={to === "/"}
                  className={({ isActive }) => cx("flex items-center gap-2.5 rounded px-2 py-1.5 text-sm", isActive ? "bg-accent/10 font-medium text-accent" : "text-ink/85 hover:bg-inset")}>
                  <Icon className="h-4 w-4 shrink-0" />
                  <span className="flex-1">{label}</span>
                  {badge && badges[badge] > 0 && <span className={cx("rounded px-1.5 font-mono text-[11px]", badge === "incidents" ? "bg-crit/15 text-crit" : "bg-warn/15 text-warn")}>{badges[badge]}</span>}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="border-t border-line px-4 py-3 text-[11px] leading-4 text-muted">
          Prototype. In SIMULATION mode no real infrastructure is changed.
        </div>
      </aside>
      {navOpen && <div className="fixed inset-0 z-30 bg-black/30 lg:hidden" onClick={() => setNavOpen(false)} />}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex h-12 shrink-0 items-center gap-3 border-b border-line bg-panel/95 px-3 backdrop-blur">
          <button className="rounded p-1.5 text-muted hover:bg-inset lg:hidden" aria-label="Open navigation" onClick={() => setNavOpen(true)}><Menu className="h-5 w-5" /></button>
          <Pill tone={status?.environment === "REAL LAB" ? "high" : "info"} title="Environment">{status?.environment ?? "SIMULATION"}</Pill>
          <NavLink to="/system" title={(status?.mode.reasons ?? []).join("; ") || "System mode"}>
            <Pill tone={MODE_TONE[mode]}>{mode === "NORMAL" ? "NORMAL" : `SYSTEM MODE: ${mode}`}</Pill>
          </NavLink>
          <span className={cx("hidden items-center gap-1 text-xs md:flex", connected ? "text-muted" : "text-warn")} title="Live event channel">
            <span className={cx("h-1.5 w-1.5 rounded-full", connected ? "bg-ok" : "bg-warn")} />{connected ? "Live" : "Offline"}
          </span>
          <div className="mx-auto min-w-0"><LoopStrip /></div>
          <button onClick={() => setPalette(true)} className={cx(inputClass, "hidden w-56 items-center gap-2 text-left text-muted md:flex")} aria-label="Search and commands">
            <Search className="h-4 w-4" /><span className="flex-1 text-sm">Search or run…</span><kbd className="rounded border border-line px-1 font-mono text-[10px]">Ctrl K</kbd>
          </button>
          <Button size="sm" icon={<Bot className="h-3.5 w-3.5" />} onClick={() => setCopilot(true)}>Ask NEXUS</Button>
          <Button size="sm" variant="auto" icon={<Play className="h-3.5 w-3.5" />} loading={busy === "demo"}
            onClick={() => run("demo", () => api.post("/api/demo/start"), "Guided demo started")}>Run demo</Button>
          <ThemeToggle />
          {config?.demo_auth ? (
            <select aria-label="Operator" value={principal?.user_id ?? ""} onChange={(e) => login(e.target.value).then(() => reload())}
              className="h-8 rounded border border-line bg-panel px-1.5 text-xs">
              {config.users.map((u) => <option key={u.id} value={u.id}>{u.name.split(" ")[0]} · {u.role}</option>)}
            </select>
          ) : <span className="text-xs text-muted">{principal?.name}</span>}
        </header>
        {status && mode !== "NORMAL" && (
          <div className={cx("border-b px-4 py-1.5 text-sm", mode === "EMERGENCY" ? "border-crit/40 bg-crit/10" : mode === "DEGRADED" ? "border-warn/40 bg-warn/10" : "border-info/40 bg-info/10")}>
            <span className="font-cond font-semibold">SYSTEM MODE: {mode}</span>
            {status.mode.reasons.length > 0 && <span className="text-ink/85"> · {status.mode.reasons.join("; ")}</span>}
            {status.mode.behaviors.length > 0 && <span className="text-muted"> — {status.mode.behaviors.join(" · ")}</span>}
          </div>
        )}
        <main className="min-h-0 flex-1 overflow-y-auto px-4 py-4 lg:px-6">{children}</main>
      </div>
      <CommandPalette open={palette} onClose={() => setPalette(false)} onCopilot={() => setCopilot(true)} />
      <Copilot open={copilot} onClose={() => setCopilot(false)} />
      <Presentation />
    </div>
  );
}
