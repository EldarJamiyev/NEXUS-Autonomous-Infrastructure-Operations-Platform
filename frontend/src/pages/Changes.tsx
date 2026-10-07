import { useState } from "react";
import { CalendarClock, Play } from "lucide-react";
import { api } from "@/api/client";
import { useApi } from "@/hooks/useApi";
import { useAuth } from "@/api/auth";
import { Button, Field, KV, Mono, PageHeader, Panel, Pill, Skeleton, Empty, inputClass } from "@/components/ui";
import { useAction } from "@/components/feedback";
import { DataTable } from "@/components/DataTable";
import { fmtDateTime } from "@/lib/format";

const TYPES: [string, string][] = [["disable_ssh", "Disable SSH on a server"], ["stop_service", "Stop a service"], ["reboot", "Reboot a device"], ["remove_rule", "Remove a firewall rule"],
  ["change_vlan", "Change a device's VLAN"], ["remove_policy", "Remove an access policy"]];

export default function Changes() {
  const { can } = useAuth();
  const { run, busy } = useAction();
  const { data: status } = useApi<any>("/api/status", { refreshOn: ["MAINTENANCE", "SETTING"] });
  const { data: changes } = useApi<any[]>("/api/changes", { refreshOn: ["APPROVAL"] });
  const { data: devices } = useApi<any[]>("/api/devices");
  const { data: deps } = useApi<any>("/api/dependencies");
  const { data: fw } = useApi<any>("/api/firewall");
  const { data: policies } = useApi<any[]>("/api/policies");
  const [form, setForm] = useState({ change_type: "disable_ssh", target: "LINUX01" });
  const [result, setResult] = useState<any>(null);
  const [reason, setReason] = useState("");
  if (!status || !devices) return <Skeleton rows={10} />;
  const targets = form.change_type === "stop_service" ? (deps?.nodes ?? []).map((n: any) => n.id) : form.change_type === "remove_rule" ? (fw?.rules ?? []).map((r: any) => r.id)
    : form.change_type === "remove_policy" ? (policies ?? []).filter((p) => p.kind === "AccessPolicy").map((p) => p.id) : devices.map((d) => d.id);
  const m = status.maintenance;
  return (
    <div className="space-y-4">
      <PageHeader title="Changes" description="Know the blast radius before you change anything. Dangerous changes outside the maintenance window require approval." />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
        <Panel title="Change impact analyzer">
          <div className="flex flex-wrap items-end gap-3">
            <Field label="Change"><select className={inputClass} value={form.change_type} onChange={(e) => setForm({ change_type: e.target.value, target: "" })}>{TYPES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></Field>
            <Field label="Target"><select className={inputClass} value={form.target} onChange={(e) => setForm({ ...form, target: e.target.value })}><option value="">choose</option>{targets.map((t: string) => <option key={t}>{t}</option>)}</select></Field>
            <Button variant="primary" icon={<Play className="h-4 w-4" />} disabled={!form.target} loading={busy === "imp"} onClick={() => run("imp", () => api.post<any>("/api/changes/impact", form)).then((r) => r && setResult(r))}>Analyze impact</Button>
            {result && <Button icon={<CalendarClock className="h-4 w-4" />} disabled={!can("ENGINEER")} loading={busy === "cr"} onClick={() => run("cr", () => api.post<any>("/api/changes", form), (r: any) => `${r.id} ${r.status}`)}>Create change request</Button>}
          </div>
          {result && (
            <div className="mt-4 grid gap-4 lg:grid-cols-2">
              <dl className="grid grid-cols-2 gap-2">
                {([["Impact level", <Pill value={result.impact_level} />], ["Users affected", result.users_affected], ["Active leases", result.active_leases], ["Dependencies", result.dependencies],
                   ["Devices", result.devices_affected], ["Approval", <Pill value={result.approval === "REQUIRED" ? "APPROVAL_REQUIRED" : "NOT_REQUIRED"}>{result.approval}</Pill>]] as [string, any][]).map(([k, v]) => (
                  <div key={k} className="rounded border border-line px-3 py-2"><dt className="text-[11px] text-muted">{k}</dt><dd className="font-cond text-xl font-semibold">{v}</dd></div>
                ))}
              </dl>
              <div className="text-sm"><p className="font-medium">{result.change}</p><p className="text-muted">Approval reason: {result.approval_reason}</p>
                <ol className="mt-2 space-y-0.5 text-xs">{result.details.propagation.slice(0, 10).map((s: any, i: number) => <li key={i}><Mono>{s.entity}</Mono> <span className="text-muted">{s.reason}</span></li>)}</ol></div>
            </div>
          )}
        </Panel>
        <Panel title="Change window">
          <KV cols={1} items={[["Current", <Pill value={m.window} />], ["Detail", m.detail], ["Next", m.next], ["Maintenance mode", m.active ? <Pill tone="warn">ACTIVE · {m.reason}</Pill> : "off"]]} />
          <div className="mt-3 space-y-2 border-t border-line pt-3">
            {!m.active && <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (e.g. CHG-0001 nginx upgrade)" aria-label="Maintenance reason" className={`${inputClass} w-full`} />}
            <Button variant={m.active ? "primary" : "secondary"} disabled={!can("ENGINEER")} loading={busy === "mm"} onClick={() => run("mm", () => api.post<any>("/api/system/maintenance", { active: !m.active, reason }), m.active ? "Maintenance ended - reconciling" : "Maintenance started")}>
              {m.active ? "End maintenance and reconcile" : "Start maintenance mode"}</Button>
            <p className="text-xs text-muted">During maintenance, drift is recorded as EXPECTED and not auto-remediated. When it ends, NEXUS reconciles and any remaining drift becomes an incident.</p>
          </div>
        </Panel>
      </div>
      <Panel title="Change requests" bodyClass="p-3">
        {changes?.length ? <DataTable rows={changes} rowKey={(c) => c.id} columns={[{ key: "id", header: "ID", render: (c) => <Mono>{c.id}</Mono> }, { key: "title", header: "Change" },
          { key: "status", header: "Status", render: (c) => <Pill value={c.status} /> }, { key: "impact", header: "Impact", render: (c) => <Pill value={c.impact.impact_level} /> }, { key: "requested_by", header: "Requested by" },
          { key: "window", header: "Window" }, { key: "created_at", header: "Created", render: (c) => fmtDateTime(c.created_at) }]} /> : <Empty title="No change requests yet" />}
      </Panel>
    </div>
  );
}
