import { useEffect, useState } from "react";
import { Clock, RefreshCw, RotateCcw, ShieldCheck } from "lucide-react";
import { api } from "@/api/client";
import { useApi } from "@/hooks/useApi";
import { useAuth } from "@/api/auth";
import { Button, Field, KV, Mono, PageHeader, Panel, Pill, Skeleton, cx, inputClass } from "@/components/ui";
import { ConfirmButton, useAction } from "@/components/feedback";

const LEVEL_TEXT: Record<number, string> = { 0: "Observe and record only", 1: "Raise alerts and incidents", 2: "Recommend actions; humans execute", 3: "Automatically run SAFE and confident REVERSIBLE fixes (default)",
  4: "Also HIGH_IMPACT fixes inside change windows when confidence ≥ 90%", 5: "Also quarantine managed devices autonomously" };

export default function SystemPage() {
  const { can } = useAuth();
  const { run, busy } = useAction();
  const { data: sys, reload } = useApi<any>("/api/system", { refreshOn: ["SETTING", "SYSTEM_MODE", "MAINTENANCE"] });
  const [test, setTest] = useState<any>(null);
  const [time, setTime] = useState("19:30");
  const runTest = () => run("st", () => api.get<any>("/api/system/selftest")).then((r) => r && setTest(r));
  useEffect(() => { runTest(); }, []);  // eslint-disable-line
  if (!sys) return <Skeleton rows={10} />;
  return (
    <div className="space-y-4">
      <PageHeader title="System" description={`NEXUS OMNIS v${sys.version} · environment ${sys.environment} · ${sys.policy_count} policies`}
        meta={<><Pill tone={sys.environment === "SIMULATION" ? "info" : "high"}>ENVIRONMENT: {sys.environment}</Pill><Pill value={sys.mode?.mode ?? "NORMAL"}>SYSTEM MODE: {sys.mode?.mode ?? "NORMAL"}</Pill></>} />
      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title={test ? `Self test · ${test.summary}` : "Self test"} actions={<Button size="sm" icon={<RefreshCw className="h-3.5 w-3.5" />} loading={busy === "st"} onClick={runTest}>Run</Button>} className="xl:col-span-2">
          {!test ? <Skeleton rows={6} /> : (
            <ul className="grid gap-1.5 md:grid-cols-2">{test.checks.map((c: any) => (
              <li key={c.component} className="flex items-start gap-2 rounded border border-line px-2 py-1.5"><ShieldCheck className={cx("mt-0.5 h-4 w-4 shrink-0", c.status === "HEALTHY" ? "text-ok" : c.status === "WARNING" ? "text-warn" : "text-crit")} />
                <span className="min-w-0"><span className="text-sm font-medium">{c.component}</span> <Pill value={c.status} /><span className="block truncate text-xs text-muted" title={c.detail}>{c.detail}</span></span></li>
            ))}</ul>
          )}
        </Panel>
        <Panel title="System mode" subtitle={sys.mode?.since ? `since ${String(sys.mode.since).slice(11, 19)}` : undefined}>
          <Pill value={sys.mode?.mode ?? "NORMAL"} className="text-[14px]" />
          {sys.mode?.reasons?.length > 0 && <ul className="mt-2 list-disc pl-5 text-sm">{sys.mode.reasons.map((r: string) => <li key={r}>{r}</li>)}</ul>}
          <h3 className="mt-3 text-xs text-muted">Current behaviour</h3><ul className="list-disc pl-5 text-sm">{(sys.mode?.behaviors ?? []).map((b: string) => <li key={b}>{b}</li>)}</ul>
        </Panel>
      </div>
      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title="Autonomy level" subtitle="What NEXUS may do without a human (ADMIN)">
          <ol className="space-y-1">{sys.autonomy.levels.map((l: any) => (
            <li key={l.level}><label className={cx("flex cursor-pointer gap-2 rounded border px-2 py-1.5", sys.autonomy.level === l.level ? "border-accent bg-accent/10" : "border-line")}>
              <input type="radio" name="autonomy" checked={sys.autonomy.level === l.level} disabled={!can("ADMIN")} onChange={() => run("al", () => api.put("/api/system/autonomy", { level: l.level }), `Autonomy level ${l.level}`).then(reload)} />
              <span><span className="font-mono text-xs">{l.level}</span> <span className="text-sm font-medium">{l.name}</span><span className="block text-xs text-muted">{LEVEL_TEXT[l.level]}</span></span>
            </label></li>
          ))}</ol>
        </Panel>
        <Panel title="Simulation clock" subtitle={`${sys.clock.site_time} ${sys.clock.site_timezone}${sys.clock.wall_clock ? " · wall clock" : ` · offset ${sys.clock.offset_seconds}s ×${sys.clock.acceleration}`}`}>
          <p className="mb-3 text-sm text-muted">Temporal policies (POL-IT-ADMIN is approval-only outside 08:00-18:00) and lease expiry use this clock. Jump the clock to demonstrate after-hours access.</p>
          <div className="flex flex-wrap items-end gap-2">
            <Field label="Set site time"><input type="time" value={time} onChange={(e) => setTime(e.target.value)} className={inputClass} /></Field>
            <Button icon={<Clock className="h-4 w-4" />} disabled={!can("ADMIN")} onClick={() => run("ct", () => api.put("/api/system/clock", { mode: "set", time }), `Clock set to ${time}`).then(reload)}>Set</Button>
            <Button disabled={!can("ADMIN")} onClick={() => run("ca", () => api.put("/api/system/clock", { mode: "accelerate", factor: 60 }), "Clock ×60").then(reload)}>×60</Button>
            <Button disabled={!can("ADMIN")} onClick={() => run("cr", () => api.put("/api/system/clock", { mode: "real" }), "Wall clock restored").then(reload)}>Real time</Button>
          </div>
        </Panel>
        <Panel title="Demo environment">
          <p className="mb-3 text-sm text-muted">Wipe the database and rebuild the simulated enterprise with fresh engine-generated history. Use before a presentation.</p>
          <ConfirmButton label="Reset demo environment" variant="danger" icon={<RotateCcw className="h-4 w-4" />} disabled={!can("ADMIN")} busy={busy === "reset"} confirmTitle="Reset the demo environment?"
            confirmText="All incidents, leases, audit records, snapshots and reports are deleted and the simulated enterprise is re-seeded. Only available in SIMULATION." onConfirm={() => run("reset", () => api.post("/api/demo/reset"), "Demo environment reset")} />
        </Panel>
      </div>
      <Panel title="Adapters and intervals">
        <KV cols={3} items={[["Firewall", <span>{sys.adapters.firewall.name} <Pill tone="neutral">{sys.adapters.firewall.mode}</Pill></span>], ["Identity", <span>{sys.adapters.identity.name} <Pill tone="neutral">{sys.adapters.identity.mode}</Pill></span>],
          ["Executor", <span>{sys.adapters.executor.name} <Pill tone="neutral">{sys.adapters.executor.mode}</Pill></span>], ["Verification probes", sys.adapters.probes.mode], ["ChatOps", sys.adapters.chatops.configured ? sys.adapters.chatops.provider : "dry run"],
          ["Event bus", sys.adapters.event_bus], ["Database", sys.adapters.database], ["Reconcile interval", `${sys.intervals.reconcile} s`], ["Detection interval", `${sys.intervals.detection} s`],
          ["Simulation tick", `${sys.intervals.simulation_tick} s`], ["Snapshot interval", `${sys.intervals.snapshot} s`], ["Step pacing", `${sys.intervals.step_delay_ms} ms`],
          ["Change windows", (sys.change_windows ?? []).map((w: any) => `${w.name}: ${w.days.join(",")} ${w.start}-${w.end}`).join("; ")], ["Next window", sys.next_window], ["Demo login", sys.demo_auth ? "enabled" : "disabled (API keys)"]]} />
        <p className="mt-3 text-xs text-muted">Real-lab adapters (pfSense REST, AD inventory push, Ansible executor, network probes) are optional and clearly marked. In SIMULATION nothing touches real infrastructure.</p>
      </Panel>
    </div>
  );
}
