import { useState } from "react";
import { Copy } from "lucide-react";
import { useApi } from "@/hooks/useApi";
import { PageHeader, Panel, Pill, Skeleton, cx } from "@/components/ui";
import { useToast } from "@/components/feedback";

export default function Troubleshooting() {
  const toast = useToast();
  const { data } = useApi<any[]>("/api/troubleshooting", { refreshOn: ["SERVICE", "INCIDENT", "REMEDIATION", "DRIFT"] });
  const [sel, setSel] = useState<string | null>(null);
  if (!data) return <Skeleton rows={8} />;
  const g = data.find((x) => x.id === sel) ?? data[0];
  return (
    <div>
      <PageHeader title="Troubleshooting center" description="Field guides for everyday problems, each with live NEXUS checks against the current state. Written for a junior administrator on their first on-call." />
      <div className="grid gap-4 xl:grid-cols-[280px_minmax(0,1fr)]">
        <Panel title="Problems" bodyClass="p-2"><ul>{data.map((x) => {
          const bad = x.live.some((c: any) => !c.ok);
          return <li key={x.id}><button onClick={() => setSel(x.id)} className={cx("flex w-full items-center justify-between rounded px-2 py-1.5 text-left text-sm", g.id === x.id ? "bg-accent/10 text-accent" : "hover:bg-inset")}>
            {x.title}<span className={cx("h-2 w-2 rounded-full", bad ? "bg-crit" : "bg-ok")} title={bad ? "a live check is failing" : "live checks pass"} /></button></li>;
        })}</ul></Panel>
        <Panel title={g.title}>
          <div className="mb-4 flex flex-wrap gap-2">{g.live.map((c: any) => <Pill key={c.check} tone={c.ok ? "ok" : "crit"} title={c.detail}>{c.check}: {c.detail}</Pill>)}</div>
          <div className="grid gap-5 lg:grid-cols-2">
            {([["Symptoms", g.symptoms], ["Evidence to collect", g.evidence], ["Likely causes", g.causes], ["Resolution", g.resolution], ["Verification", g.verification]] as [string, string[]][]).map(([t, items]) => (
              <section key={t}><h3 className="mb-1 text-sm font-semibold">{t}</h3><ul className="list-disc space-y-0.5 pl-5 text-sm">{items.map((x) => <li key={x}>{x}</li>)}</ul></section>
            ))}
            <section><h3 className="mb-1 text-sm font-semibold">Commands</h3>
              <ul className="space-y-1">{g.commands.map((c: string) => (
                <li key={c} className="flex items-center gap-2 rounded border border-line bg-inset px-2 py-1 font-mono text-[12px]"><span className="flex-1 break-all">{c}</span>
                  <button aria-label="Copy command" className="text-muted hover:text-ink" onClick={() => navigator.clipboard?.writeText(c).then(() => toast({ tone: "ok", title: "Copied" }))}><Copy className="h-3.5 w-3.5" /></button></li>
              ))}</ul></section>
          </div>
        </Panel>
      </div>
    </div>
  );
}
