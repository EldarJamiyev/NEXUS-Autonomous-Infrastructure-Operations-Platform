import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ArrowRight, Play } from "lucide-react";
import { api } from "@/api/client";
import { useApi } from "@/hooks/useApi";
import { Button, Field, Mono, PageHeader, Panel, Pill, Skeleton, Empty, inputClass } from "@/components/ui";
import { useAction } from "@/components/feedback";

const PRESETS: [string, string, Record<string, any>][] = [["DC01 fails", "device_down", { device: "DC01" }], ["DNS fails", "service_down", { service: "dns@DC01" }],
  ["VLAN 30 fails", "vlan_down", { vlan: 30 }], ["pfSense API unavailable", "firewall_api_down", {}], ["LINUX01 loses SSH", "ssh_loss", { device: "LINUX01" }],
  ["PC-023 becomes high risk", "device_high_risk", { device: "PC-023", risk: 85 }], ["POL-IT-ADMIN removed", "policy_removed", { policy: "POL-IT-ADMIN" }],
  ["FW-100 disappears", "rule_removed", { rule: "FW-100" }], ["Disaster recovery lab", "disaster", {}]];

export default function WhatIf() {
  const [params] = useSearchParams();
  const { run, busy } = useAction();
  const { data: scenarios } = useApi<any[]>("/api/whatif/scenarios");
  const { data: devices } = useApi<any[]>("/api/devices");
  const { data: deps } = useApi<any>("/api/dependencies");
  const { data: fw } = useApi<any>("/api/firewall");
  const { data: policies } = useApi<any[]>("/api/policies");
  const [scenario, setScenario] = useState("vlan_down");
  const [p, setP] = useState<Record<string, any>>({ vlan: 30 });
  const [result, setResult] = useState<any>(null);
  const simulate = (sc = scenario, prm = p) => run("sim", () => api.post<any>("/api/whatif", { scenario: sc, params: prm })).then((r) => r && setResult(r));
  useEffect(() => { if (params.get("preset") === "disaster") { setScenario("disaster"); setP({}); simulate("disaster", {}); } }, []);  // eslint-disable-line
  if (!scenarios || !devices) return <Skeleton rows={10} />;
  const needs = scenarios.find((s) => s.id === scenario)?.params ?? [];
  const imp = result?.impact;
  return (
    <div className="space-y-4">
      <PageHeader title="What-if simulator" description="Ask what would happen before it happens. Runs on a read-only copy of the current state model; nothing is changed." />
      <div className="flex flex-wrap gap-2">{PRESETS.map(([label, sc, prm]) => <Button key={label} size="sm" onClick={() => { setScenario(sc); setP(prm); simulate(sc, prm); }}>{label}</Button>)}</div>
      <Panel title="Scenario">
        <div className="flex flex-wrap items-end gap-3">
          <Field label="Question"><select className={inputClass} value={scenario} onChange={(e) => { setScenario(e.target.value); setP({}); }}>{scenarios.map((s) => <option key={s.id} value={s.id}>{s.question}</option>)}</select></Field>
          {needs.includes("device") && <Field label="Device"><select className={inputClass} value={p.device ?? ""} onChange={(e) => setP({ ...p, device: e.target.value })}><option value="">choose</option>{devices.map((d) => <option key={d.id}>{d.id}</option>)}</select></Field>}
          {needs.includes("service") && <Field label="Service"><select className={inputClass} value={p.service ?? ""} onChange={(e) => setP({ ...p, service: e.target.value })}><option value="">choose</option>{(deps?.nodes ?? []).map((n: any) => <option key={n.id}>{n.id}</option>)}</select></Field>}
          {needs.includes("vlan") && <Field label="VLAN"><select className={inputClass} value={p.vlan ?? ""} onChange={(e) => setP({ ...p, vlan: Number(e.target.value) })}>{[10, 20, 30, 40, 50, 99].map((v) => <option key={v}>{v}</option>)}</select></Field>}
          {needs.includes("rule") && <Field label="Firewall rule"><select className={inputClass} value={p.rule ?? ""} onChange={(e) => setP({ ...p, rule: e.target.value })}><option value="">choose</option>{(fw?.rules ?? []).map((r: any) => <option key={r.id}>{r.id}</option>)}</select></Field>}
          {needs.includes("policy") && <Field label="Policy"><select className={inputClass} value={p.policy ?? ""} onChange={(e) => setP({ ...p, policy: e.target.value })}><option value="">choose</option>{(policies ?? []).filter((x) => x.kind === "AccessPolicy").map((x) => <option key={x.id}>{x.id}</option>)}</select></Field>}
          <Button variant="primary" icon={<Play className="h-4 w-4" />} loading={busy === "sim"} onClick={() => simulate()}>Simulate</Button>
        </div>
      </Panel>
      {!result ? <Empty title="Pick a preset or build a scenario" /> : (
        <>
          <div className="grid items-stretch gap-2 lg:grid-cols-[1fr_auto_1fr_auto_1.3fr_auto_1fr]">
            <Panel title="Current state"><ul className="space-y-1 text-sm">{Object.entries(result.current).map(([k, v]) => <li key={k} className="flex justify-between"><span className="text-muted">{k.replace("_", " ")}</span><span className="font-mono">{String(v)}</span></li>)}</ul></Panel>
            <ArrowRight className="hidden h-5 w-5 self-center text-muted lg:block" />
            <Panel title="Simulated change"><p className="text-sm">{result.change}</p><p className="mt-2 text-xs text-muted">{result.note}</p></Panel>
            <ArrowRight className="hidden h-5 w-5 self-center text-muted lg:block" />
            <Panel title="Impact propagation" bodyClass="max-h-[280px] overflow-y-auto p-3"><ol className="space-y-1 text-xs">{result.propagation.map((s: any, k: number) => <li key={k}><Mono className="text-high">{s.entity}</Mono> <span className="text-muted">{s.reason}</span></li>)}</ol>{!result.propagation.length && <p className="text-sm text-muted">No propagation</p>}</Panel>
            <ArrowRight className="hidden h-5 w-5 self-center text-muted lg:block" />
            <Panel title="Expected result">
              <div className="flex flex-wrap gap-2"><Pill value={result.expected.priority} /><Pill value={imp.level} /><Pill value={result.expected.system_mode} /></div>
              <dl className="mt-3 grid grid-cols-2 gap-2 text-center">{(["devices", "users", "services", "leases"] as const).map((k) => <div key={k} className="rounded border border-line py-1"><dt className="text-[11px] text-muted">{k}</dt><dd className="font-cond text-xl font-semibold">{imp.counts[k]}</dd></div>)}</dl>
            </Panel>
          </div>
          <div className="grid gap-4 xl:grid-cols-3">
            <Panel title="Who and what is affected"><dl className="space-y-2 text-sm">
              <div><dt className="text-xs text-muted">Users</dt><dd>{imp.user_names.join(", ") || "none"}</dd></div><div><dt className="text-xs text-muted">Devices</dt><dd className="font-mono text-xs">{imp.devices.join(", ") || "none"}</dd></div>
              <div><dt className="text-xs text-muted">Services</dt><dd className="font-mono text-xs">{imp.services.join(", ") || "none"}</dd></div><div><dt className="text-xs text-muted">Leases</dt><dd className="font-mono text-xs">{imp.leases.join(", ") || "none"}</dd></div>
              {imp.tightest_rto_minutes && <div><dt className="text-xs text-muted">Tightest RTO</dt><dd>{imp.tightest_rto_minutes} min</dd></div>}
            </dl>
              {result.expected.consequences && <ul className="mt-3 list-disc pl-5 text-sm">{result.expected.consequences.map((c: string, k: number) => <li key={k}>{c}</li>)}</ul>}
              {result.expected.flows && <ul className="mt-3 space-y-1 text-xs">{result.expected.flows.map((f: any, k: number) => <li key={k}><Mono>{f.flow}</Mono>: <Pill value={f.before} /> → <Pill value={f.after} /></li>)}</ul>}
            </Panel>
            <Panel title="What NEXUS would do" bodyClass="p-0"><table className="w-full text-left text-sm"><tbody>{result.expected.nexus_responses.map((r: any, k: number) => (
              <tr key={k} className="border-t border-line first:border-0"><td className="px-3 py-1.5 font-mono text-xs">{r.alert}</td><td className="text-xs">{r.target}</td><td className="text-xs">{r.nexus_action}</td><td className="px-3"><Pill tone={r.mode === "automatic" ? "ok" : r.mode === "approval" || r.mode.includes("human") ? "warn" : "info"}>{r.mode}</Pill></td></tr>
            ))}</tbody></table>{!result.expected.nexus_responses.length && <p className="p-3 text-sm text-muted">No alerts expected</p>}</Panel>
            <Panel title="Suggested recovery order"><ol className="space-y-1 text-sm">{result.recovery_order.map((r: any) => <li key={r.order}><span className="font-mono text-muted">{r.order}.</span> <Mono>{r.service}</Mono> <span className="text-xs text-muted">{r.reason}{r.rto_minutes ? ` · RTO ${r.rto_minutes} min` : ""}</span></li>)}</ol>{!result.recovery_order.length && <p className="text-sm text-muted">Nothing to recover</p>}</Panel>
          </div>
        </>
      )}
    </div>
  );
}
