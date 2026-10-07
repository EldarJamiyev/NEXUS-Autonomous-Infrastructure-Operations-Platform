import { useEffect, useState } from "react";
import { CheckCircle2, CircleAlert, CircleX, GitPullRequestArrow, Play } from "lucide-react";
import { api } from "@/api/client";
import { useApi } from "@/hooks/useApi";
import { useAuth } from "@/api/auth";
import { Button, Mono, PageHeader, Panel, Pill, Skeleton, Tabs, cx, inputClass, Empty } from "@/components/ui";
import { ConfirmButton, useAction } from "@/components/feedback";
import { DiffView } from "@/components/timeline";
import { fmtDateTime } from "@/lib/format";

function Stages({ report }: { report: any }) {
  return (
    <ol className="space-y-2">{(report.stages ?? []).map((s: any) => (
      <li key={s.name} className="flex gap-2">
        {s.status === "passed" ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-ok" /> : s.status === "warning" ? <CircleAlert className="mt-0.5 h-4 w-4 shrink-0 text-warn" /> : <CircleX className="mt-0.5 h-4 w-4 shrink-0 text-crit" />}
        <div><div className="text-sm font-medium">{s.name}</div><ul className="text-xs text-muted">{s.messages.map((m: string, i: number) => <li key={i}>{m}</li>)}</ul></div>
      </li>
    ))}</ol>
  );
}

export default function Policies() {
  const { can } = useAuth();
  const { run, busy } = useAction();
  const { data: list } = useApi<any[]>("/api/policies", { refreshOn: ["POLICY"] });
  const { data: report } = useApi<any>("/api/policies/compile", { refreshOn: ["POLICY"] });
  const { data: disk } = useApi<any[]>("/api/policies/diff", { refreshOn: ["POLICY"] });
  const [sel, setSel] = useState("POL-IT-ADMIN");
  const { data: pol } = useApi<any>(`/api/policies/${sel}`, { refreshOn: ["POLICY"] });
  const [tab, setTab] = useState<"yaml" | "versions" | "draft">("yaml");
  const [draft, setDraft] = useState("");
  const [diff, setDiff] = useState<string | null>(null);
  const [draftResult, setDraftResult] = useState<any>(null);
  useEffect(() => { if (pol) { setDraft(pol.content); setDiff(null); setDraftResult(null); } }, [pol?.id, pol?.active_version]);
  if (!list || !report) return <Skeleton rows={10} />;
  return (
    <div className="space-y-4">
      <PageHeader title="Policies" description="Policy as code. Git-controlled YAML is validated, normalized, checked for conflicts and shadowed rules, analysed for impact and risk, compiled to firewall rules and verified (including lockout protection)."
        meta={<Pill tone={report.ok ? "ok" : "crit"}>{report.ok ? "Policy set compiles" : "Policy set has blocking errors"}</Pill>}
        actions={<ConfirmButton label="Apply from Git" icon={<GitPullRequestArrow className="h-4 w-4" />} disabled={!can("ADMIN") || !disk?.length} confirmTitle="Apply policy files from Git?"
          confirmText={`${disk?.length ?? 0} file(s) differ from the active versions. Valid files become new active versions; invalid ones are rejected.`} onConfirm={() => run("apply", () => api.post("/api/policies/apply"), "Policies applied")} />} />
      <div className="grid gap-4 xl:grid-cols-[280px_minmax(0,1fr)_380px]">
        <Panel title="Policy set" bodyClass="p-2">
          <ul>{list.map((p) => (
            <li key={p.id}><button onClick={() => setSel(p.id)} className={cx("w-full rounded px-2 py-1.5 text-left", sel === p.id ? "bg-accent/10" : "hover:bg-inset")}>
              <div className="flex items-center justify-between gap-2"><Mono className={sel === p.id ? "text-accent" : ""}>{p.id}</Mono><span className="font-mono text-[11px] text-muted">v{p.active_version ?? "-"}</span></div>
              <div className="flex items-center justify-between gap-2 text-xs text-muted"><span className="truncate">{p.kind}</span>{p.status !== "ACTIVE" && <Pill value={p.status} />}</div>
            </button></li>
          ))}</ul>
        </Panel>
        <Panel title={pol ? pol.name : sel} subtitle={pol ? `${pol.kind} · ${pol.file_path ?? "console draft"} · active v${pol.active_version ?? "-"}` : undefined}
          actions={pol && can("ADMIN") && pol.versions.length > 1 && <ConfirmButton size="sm" label="Roll back" confirmTitle={`Roll back ${pol.id}?`} confirmText="The previous version becomes active again. Git stays the source of truth - revert the commit too." onConfirm={() => run("rb", () => api.post(`/api/policies/${pol.id}/rollback`), "Rolled back")} />}>
          {!pol ? <Skeleton rows={8} /> : (
            <>
              <Tabs value={tab} onChange={setTab} tabs={[{ id: "yaml", label: "Active YAML" }, { id: "versions", label: "Versions", count: pol.versions.length }, { id: "draft", label: "Draft & validate" }]} />
              {tab === "yaml" && <pre className="max-h-[560px] overflow-auto rounded border border-line bg-inset p-3 font-mono text-[12px] leading-5">{pol.content}</pre>}
              {tab === "versions" && (
                <div className="space-y-3">
                  <table className="w-full text-left text-sm"><thead className="text-xs text-muted"><tr>{["Version", "Status", "Author", "Created", "SHA-256", ""].map((h) => <th key={h} className="py-1 font-medium">{h}</th>)}</tr></thead>
                    <tbody>{pol.versions.map((v: any, i: number) => (
                      <tr key={v.version} className="border-t border-line"><td className="py-1.5 font-mono">v{v.version}</td><td><Pill value={v.status} /></td><td>{v.author}</td><td className="text-xs">{fmtDateTime(v.created_at)}</td><td className="font-mono text-[11px]">{v.checksum.slice(0, 12)}</td>
                        <td className="space-x-1 text-right">{i < pol.versions.length - 1 && <Button size="sm" onClick={() => api.get<any>(`/api/policies/${pol.id}/diff?a=${pol.versions[i + 1].version}&b=${v.version}`).then((r) => setDiff(r.diff))}>Diff</Button>}
                          {can("ADMIN") && v.status === "SUPERSEDED" && <Button size="sm" onClick={() => run("act", () => api.post(`/api/policies/${pol.id}/activate`, { version: v.version }), `v${v.version} activated`)}>Activate</Button>}</td></tr>
                    ))}</tbody></table>
                  {diff !== null && <DiffView diff={diff} />}
                </div>
              )}
              {tab === "draft" && (
                <div className="space-y-3">
                  <textarea aria-label="Policy draft" value={draft} onChange={(e) => setDraft(e.target.value)} rows={18} spellCheck={false} className={cx(inputClass, "h-auto w-full py-2 font-mono text-[12px] leading-5")} />
                  <div className="flex gap-2">
                    <Button loading={busy === "val"} disabled={!can("OPERATOR")} onClick={() => run("val", () => api.post<any>("/api/policies/validate", { content: draft })).then((r) => r && setDraftResult({ kind: "validate", ...r }))}>Validate</Button>
                    <Button icon={<Play className="h-4 w-4" />} loading={busy === "sim"} disabled={!can("OPERATOR")} onClick={() => run("sim", () => api.post<any>("/api/policies/simulate", { content: draft })).then((r) => r && setDraftResult({ kind: "simulate", ...r }))}>Simulate impact</Button>
                    <span className="self-center text-xs text-muted">Drafts are never activated from here - commit to Git and apply.</span>
                  </div>
                  {draftResult?.kind === "validate" && <div className="rounded border border-line p-3"><Pill tone={draftResult.ok ? "ok" : "crit"}>{draftResult.ok ? "VALID" : "INVALID"}</Pill><div className="mt-2"><Stages report={draftResult} /></div></div>}
                  {draftResult?.kind === "simulate" && (
                    <div className="space-y-1 rounded border border-line p-3 text-sm">
                      <Pill tone={draftResult.ok ? "ok" : "crit"}>{draftResult.ok ? "Would compile" : "Would be rejected"}</Pill>
                      <p>Users gaining access: {draftResult.users_gaining_access?.join(", ") || "none"}</p><p>Users losing access: {draftResult.users_losing_access?.join(", ") || "none"}</p>
                      {draftResult.new_conflicts?.map((c: any, i: number) => <p key={i} className="text-crit">{c.kind}: {c.detail}</p>)}
                      {draftResult.new_shadowed?.map((s: any, i: number) => <p key={i} className="text-warn">{s.message}</p>)}
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </Panel>
        <div className="space-y-4">
          <Panel title="Compiler report" subtitle={`compiled ${fmtDateTime(report.compiled_at)}`}><Stages report={report} /></Panel>
          <Panel title="Shadowed and conflicting rules">
            {report.shadowed.map((s: any) => <p key={s.rule} className="mb-2 rounded border border-warn/40 bg-warn/5 p-2 text-xs"><Pill tone="warn">{s.kind}</Pill> {s.message}</p>)}
            {report.conflicts.map((c: any, i: number) => <p key={i} className="mb-2 rounded border border-crit/40 bg-crit/5 p-2 text-xs"><Pill tone={c.blocking ? "crit" : "warn"}>{c.kind}</Pill> {c.detail}</p>)}
            {!report.shadowed.length && !report.conflicts.length && <Empty title="No shadowed or conflicting rules" />}
          </Panel>
          {disk && disk.length > 0 && <Panel title="Git vs active">{disk.map((d) => <div key={d.policy} className="mb-2"><Pill tone="warn">{d.status}</Pill> <Mono>{d.policy}</Mono><DiffView diff={d.diff} /></div>)}</Panel>}
        </div>
      </div>
    </div>
  );
}
