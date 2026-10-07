import { useState } from "react";
import { Play, Stethoscope } from "lucide-react";
import { api } from "@/api/client";
import { useApi } from "@/hooks/useApi";
import { useAuth } from "@/api/auth";
import { Button, Field, Mono, PageHeader, Panel, Pill, Skeleton, cx, inputClass } from "@/components/ui";
import { ConfirmButton, useAction } from "@/components/feedback";

export default function Runbooks() {
  const { can } = useAuth();
  const { run, busy } = useAction();
  const { data } = useApi<any[]>("/api/runbooks");
  const [sel, setSel] = useState<string | null>(null);
  const [target, setTarget] = useState("");
  const [diag, setDiag] = useState<any>(null);
  if (!data) return <Skeleton rows={8} />;
  const rb = data.find((r) => r.id === sel) ?? data[0];
  const tgt = target || (rb.target !== "dynamic" ? rb.target : "");
  return (
    <div className="space-y-4">
      <PageHeader title="Runbooks" description="Executable operator runbooks: trigger, read-only diagnostics, preconditions, actions (through the decision engine), verification, rollback and escalation." />
      <div className="grid gap-4 xl:grid-cols-[260px_minmax(0,1fr)]">
        <Panel title="Runbooks" bodyClass="p-2"><ul>{data.map((r) => (
          <li key={r.id}><button onClick={() => { setSel(r.id); setDiag(null); setTarget(""); }} className={cx("w-full rounded px-2 py-1.5 text-left text-sm", rb.id === r.id ? "bg-accent/10 text-accent" : "hover:bg-inset")}>{r.title}<span className="block font-mono text-[11px] text-muted">{r.id}</span></button></li>
        ))}</ul></Panel>
        <Panel title={rb.title} subtitle={`trigger: ${Object.entries(rb.trigger).map(([k, v]) => `${k} ${v}`).join(", ")}`}>
          <div className="mb-4 flex flex-wrap items-end gap-3">
            <Field label="Target device"><input className={inputClass} value={tgt} onChange={(e) => setTarget(e.target.value.toUpperCase())} placeholder="e.g. UNKNOWN-001" /></Field>
            <Button icon={<Stethoscope className="h-4 w-4" />} disabled={!can("OPERATOR") || !tgt} loading={busy === "diag"} onClick={() => run("diag", () => api.post<any>(`/api/runbooks/${rb.id}/diagnose`, { target: tgt })).then((r) => r && setDiag(r))}>Run diagnostics</Button>
          </div>
          <div className="grid gap-4 lg:grid-cols-2">
            <section><h3 className="mb-1 text-sm font-semibold">Diagnostics (read-only)</h3>
              <ol className="space-y-1 text-sm">{rb.diagnostics.map((d: any, i: number) => {
                const res = diag?.results?.[i];
                return <li key={i} className="flex gap-2">{res ? <Pill value={res.passed ? "PASS" : "FAIL"} /> : <Pill tone="unk">-</Pill>}<span>{d.description}{res && <span className="block text-xs text-muted">{res.detail}</span>}</span></li>;
              })}</ol></section>
            <section><h3 className="mb-1 text-sm font-semibold">Preconditions</h3><ul className="list-disc pl-5 text-sm">{rb.preconditions.map((p: string) => <li key={p}>{p}</li>)}</ul>
              <h3 className="mb-1 mt-3 text-sm font-semibold">Actions</h3>
              <ul className="space-y-2">{rb.actions.map((a: any) => (
                <li key={a.action} className="flex flex-wrap items-center gap-2 text-sm"><Mono>{a.action}</Mono><span className="text-xs text-muted">when {a.when}</span>
                  <ConfirmButton size="sm" label="Execute" icon={<Play className="h-3.5 w-3.5" />} disabled={!can("ENGINEER") || !tgt} confirmTitle={`Execute ${a.action} on ${tgt}?`}
                    confirmText="The request goes through the decision engine: allowlist, preconditions, duplicate and loop guards, approval rules, verification and rollback." onConfirm={() => run("ex", () => api.post<any>(`/api/runbooks/${rb.id}/execute`, { target: tgt, action_id: a.action }), (r: any) => `Decision ${r.outcome}: ${r.reasons?.[0] ?? ""}`)} /></li>
              ))}</ul></section>
            <section><h3 className="mb-1 text-sm font-semibold">Verification</h3><ul className="list-disc pl-5 text-sm">{rb.verification.map((v: string) => <li key={v}>{v}</li>)}</ul></section>
            <section><h3 className="mb-1 text-sm font-semibold">Rollback</h3><p className="text-sm">{rb.rollback}</p><h3 className="mb-1 mt-3 text-sm font-semibold">Escalation</h3><p className="text-sm">{rb.escalation}</p></section>
          </div>
        </Panel>
      </div>
    </div>
  );
}
