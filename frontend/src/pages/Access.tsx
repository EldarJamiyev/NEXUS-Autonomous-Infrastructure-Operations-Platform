import { useEffect, useState } from "react";
import { KeyRound, Search } from "lucide-react";
import { api, qs } from "@/api/client";
import { useApi } from "@/hooks/useApi";
import { useAuth } from "@/api/auth";
import type { Device, Lease } from "@/types";
import { DataTable } from "@/components/DataTable";
import { Button, Field, Mono, PageHeader, Panel, Pill, Skeleton, inputClass, Empty } from "@/components/ui";
import { ConfirmButton, useAction } from "@/components/feedback";
import { useClockTick } from "@/components/live";

export default function Access() {
  const { principal, can } = useAuth();
  const { run, busy } = useAction();
  useClockTick(1000);
  const { data: leases } = useApi<Lease[]>("/api/leases", { refreshOn: ["LEASE", "FIREWALL", "APPROVAL"] });
  const { data: users } = useApi<any[]>("/api/users");
  const { data: devices } = useApi<Device[]>("/api/devices");
  const [form, setForm] = useState({ user_id: "", device_id: "", destination: "LINUX01", port: 22, reason: "System administration", duration_minutes: 30 });
  const [result, setResult] = useState<any>(null);
  useEffect(() => {
    if (!principal || !users || form.user_id) return;
    const me = users.find((u) => u.id === principal.user_id) ?? users[0];
    setForm((f) => ({ ...f, user_id: me.id, device_id: me.sessions[0]?.device ?? "PC-023" }));
  }, [principal, users, form.user_id]);
  if (!leases || !users || !devices) return <Skeleton rows={10} />;
  const set = (k: string, v: string | number) => setForm((f) => ({ ...f, [k]: v }));
  const explain = () => run("explain", () => api.get<any>(`/api/explain/access?${qs({ user: form.user_id, device: form.device_id, destination: form.destination, port: form.port })}`)).then((r) => r && setResult({ explanation: r, decision: r.decision, explainOnly: true }));
  const request = () => run("req", () => api.post<any>("/api/access/request", form), (r: any) => `Access ${r.decision}`).then((r) => r && setResult(r));
  const ex = result?.explanation;
  return (
    <div className="space-y-4">
      <PageHeader title="Access" description="Short-lived, session-bound access instead of permanent rules. Each lease is evaluated (identity, group, policy, risk, time, firewall state), applied to pfSense, verified and revoked when it expires or risk rises." />
      <div className="grid gap-4 xl:grid-cols-[420px_minmax(0,1fr)]">
        <Panel title="Request or explain access">
          <div className="grid grid-cols-2 gap-3">
            <Field label="User"><select className={inputClass} value={form.user_id} onChange={(e) => set("user_id", e.target.value)}>{users.map((u) => <option key={u.id} value={u.id}>{u.name}</option>)}</select></Field>
            <Field label="From device"><select className={inputClass} value={form.device_id} onChange={(e) => set("device_id", e.target.value)}>{devices.filter((d) => ["workstation", "unknown"].includes(d.kind)).map((d) => <option key={d.id}>{d.id}</option>)}</select></Field>
            <Field label="Destination"><select className={inputClass} value={form.destination} onChange={(e) => set("destination", e.target.value)}>{devices.filter((d) => ["server", "firewall"].includes(d.kind)).map((d) => <option key={d.id}>{d.id}</option>)}</select></Field>
            <Field label="TCP port"><input className={inputClass} type="number" min={1} max={65535} value={form.port} onChange={(e) => set("port", Number(e.target.value))} /></Field>
            <Field label="Reason"><input className={inputClass} value={form.reason} onChange={(e) => set("reason", e.target.value)} /></Field>
            <Field label="Duration (min)"><input className={inputClass} type="number" min={1} max={240} value={form.duration_minutes} onChange={(e) => set("duration_minutes", Number(e.target.value))} /></Field>
          </div>
          <div className="mt-4 flex gap-2">
            <Button icon={<Search className="h-4 w-4" />} loading={busy === "explain"} onClick={explain}>Explain decision</Button>
            <Button variant="auto" icon={<KeyRound className="h-4 w-4" />} loading={busy === "req"} onClick={request}>Request lease</Button>
          </div>
          <p className="mt-3 text-xs text-muted">Users may request access for themselves; engineers may request on behalf of others. Outside business hours, POL-IT-ADMIN requires a second administrator's approval.</p>
        </Panel>
        <Panel title={ex ? ex.title ?? `Access ${result.decision}` : "Decision"} actions={result && <Pill value={result.decision} className="text-[13px]" />}>
          {!ex ? <Empty title="Explain or request access to see the full evaluation" hint="Every check below comes from live state: session, group membership, policy, identity confidence, device and user risk, time window and firewall availability." /> : (
            <div className="space-y-3">
              <p className="text-[15px] leading-6">{ex.narrative}</p>
              <table className="w-full text-left text-sm"><tbody>{ex.checks.map((c: any, i: number) => (
                <tr key={i} className="border-t border-line align-top"><td className="py-1.5 pr-3 font-medium">{c.check}</td><td className="pr-3"><Pill value={c.status} /></td><td className="text-muted">{c.detail}</td></tr>
              ))}</tbody></table>
              <div className="flex flex-wrap gap-2 text-xs text-muted">
                {ex.policy && <Pill tone="auto">{ex.policy}</Pill>}{ex.policy_threshold !== null && ex.policy_threshold !== undefined && <span>risk threshold {ex.policy_threshold}</span>}
                {ex.schedule && <span>· {ex.schedule}</span>}
              </div>
              {result.lease && !result.explainOnly && <p className="rounded border border-line bg-inset p-2 text-sm">Lease <Mono>{result.lease.id}</Mono> · {result.lease.status} · firewall {result.lease.firewall_state} · expires {result.lease.expires_local}</p>}
              {result.approval_id && <p className="rounded border border-warn/40 bg-warn/10 p-2 text-sm">Approval {result.approval_id} created - an engineer other than the requester must approve it on the Approvals page.</p>}
            </div>
          )}
        </Panel>
      </div>
      <Panel title="Leases" bodyClass="p-3">
        <DataTable rows={leases} rowKey={(l) => l.id} placeholder="Filter leases"
          columns={[{ key: "id", header: "Lease", render: (l) => <Mono className="text-info">{l.id}</Mono> }, { key: "user_id", header: "User" },
            { key: "device_id", header: "Source", render: (l) => <span><Mono>{l.device_id}</Mono> <Mono className="text-muted">{l.source_ip}</Mono></span> },
            { key: "destination", header: "Destination", render: (l) => <Mono>{l.destination}:{l.port}/{l.protocol}</Mono> }, { key: "policy_id", header: "Policy", render: (l) => <span className="text-xs">{l.policy_id}</span> },
            { key: "status", header: "Status", render: (l) => <Pill value={l.status} /> }, { key: "firewall_state", header: "Firewall", render: (l) => <Pill value={l.firewall_state} /> },
            { key: "expires_at", header: "Expires", render: (l) => l.status === "ACTIVE" ? <span className="font-mono text-xs">{l.expires_local} · {Math.max(0, Math.round((new Date(l.expires_at).getTime() - Date.now()) / 60000))} min</span> : <span className="text-xs text-muted" title={l.end_reason ?? ""}>{l.end_reason ?? l.expires_local}</span> },
            { key: "actions", header: "", render: (l) => ["ACTIVE", "PENDING", "PENDING_APPROVAL"].includes(l.status) && can("OPERATOR") ? (
              <ConfirmButton size="sm" label="Revoke" confirmTitle={`Revoke ${l.id}?`} confirmText="The firewall rule is removed and its absence verified." onConfirm={() => run("rev", () => api.post(`/api/leases/${l.id}/revoke`), "Lease revoked")} />
            ) : null }]} />
      </Panel>
    </div>
  );
}
