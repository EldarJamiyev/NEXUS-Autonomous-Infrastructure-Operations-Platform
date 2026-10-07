import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { HelpCircle } from "lucide-react";
import { api } from "@/api/client";
import { Dialog } from "./feedback";
import { Pill, Skeleton, ErrorBox, cx } from "./ui";
import { toneOf } from "@/lib/format";

const Ctx = createContext<(path: string) => void>(() => undefined);
export const useExplain = () => useContext(Ctx);

export function ExplainProvider({ children }: { children: ReactNode }) {
  const [path, setPath] = useState<string | null>(null);
  const [data, setData] = useState<Record<string, any> | null>(null);
  const [error, setError] = useState<any>(null);
  const open = useCallback((p: string) => {
    setPath(p);
    setData(null);
    setError(null);
    api.get<Record<string, any>>(p).then(setData).catch(setError);
  }, []);
  return (
    <Ctx.Provider value={open}>
      {children}
      <Dialog drawer open={!!path} onClose={() => setPath(null)} title={data?.title ?? "Explanation"}>
        <ErrorBox error={error} />
        {!data && !error && <Skeleton rows={6} />}
        {data && <Explanation data={data} />}
      </Dialog>
    </Ctx.Provider>
  );
}

function Explanation({ data }: { data: Record<string, any> }) {
  const verdict = data.decision ?? data.outcome ?? data.level ?? data.classification ?? (data.quarantined !== undefined ? (data.quarantined ? "QUARANTINED" : "NOT QUARANTINED") : null);
  return (
    <div className="space-y-4 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        {verdict && <Pill value={String(verdict)} className="text-[13px]" />}
        {data.score !== undefined && <Pill value={`risk ${data.score}`} tone={toneOf(data.level)} />}
        {data.confidence !== undefined && data.confidence !== null && <Pill tone="info">confidence {String(data.confidence)}{typeof data.confidence === "number" ? "%" : ""}</Pill>}
        {data.policy && typeof data.policy === "string" && <Pill tone="auto">{data.policy}</Pill>}
      </div>
      {(data.narrative || data.reason || data.root_cause) && <p className="leading-6">{data.narrative ?? data.reason ?? data.root_cause}</p>}
      {Array.isArray(data.checks) && (
        <table className="w-full text-left text-sm">
          <thead className="text-xs text-muted"><tr><th className="py-1 font-medium">Check</th><th className="font-medium">Result</th><th className="font-medium">Detail</th></tr></thead>
          <tbody>{data.checks.map((c: any, i: number) => (
            <tr key={i} className="border-t border-line align-top"><td className="py-1.5 pr-2">{c.check ?? c.name}</td><td className="pr-2"><Pill value={c.status} /></td><td className="text-muted">{c.detail}</td></tr>
          ))}</tbody>
        </table>
      )}
      {Array.isArray(data.factors) && data.factors.length > 0 && (
        <div>
          <h3 className="mb-1 text-xs font-medium text-muted">Contributing factors</h3>
          <ul className="space-y-1">{data.factors.map((f: any, i: number) => (
            <li key={i} className="flex gap-3 rounded border border-line px-2 py-1.5">
              <span className={cx("w-10 shrink-0 text-right font-mono num", f.points >= 0 ? "text-high" : "text-ok")}>{f.points > 0 ? "+" : ""}{f.points}</span>
              <span><span className="font-medium">{f.label}</span><span className="block text-xs text-muted">{f.evidence}</span></span>
            </li>
          ))}</ul>
        </div>
      )}
      {Array.isArray(data.evidence) && data.evidence.length > 0 && (
        <div><h3 className="mb-1 text-xs font-medium text-muted">Evidence</h3><ul className="list-disc space-y-1 pl-5">{data.evidence.map((e: string, i: number) => <li key={i}>{e}</li>)}</ul></div>
      )}
      {Array.isArray(data.confidence_breakdown) && (
        <div><h3 className="mb-1 text-xs font-medium text-muted">Automation confidence (evidence completeness)</h3>
          <ul className="space-y-0.5 font-mono text-xs">{data.confidence_breakdown.map((b: any, i: number) => <li key={i}>{b.points > 0 ? "+" : ""}{b.points} {b.factor}</li>)}</ul></div>
      )}
      {data.safety?.checks && (
        <div><h3 className="mb-1 text-xs font-medium text-muted">Safety checks</h3>
          <ul className="space-y-1">{data.safety.checks.map((c: any, i: number) => <li key={i} className="flex gap-2"><Pill value={c.status} /><span>{c.name}: <span className="text-muted">{c.detail}</span></span></li>)}</ul></div>
      )}
      {Array.isArray(data.signals_missing) && data.signals_missing.length > 0 && <p className="text-muted">Missing identity signals: {data.signals_missing.join(", ")}</p>}
      {data.diff && <pre className="overflow-x-auto rounded border border-line bg-inset p-2 font-mono text-xs">{data.diff}</pre>}
      {(data.method || data.note) && <p className="border-t border-line pt-3 text-xs text-muted">{data.method ?? data.note}</p>}
    </div>
  );
}

export function WhyButton({ path, label = "Why?" }: { path: string; label?: string }) {
  const explain = useExplain();
  return (
    <button onClick={() => explain(path)} className="inline-flex items-center gap-1 rounded border border-accent/40 px-1.5 py-0.5 text-xs font-medium text-accent hover:bg-accent/10">
      <HelpCircle className="h-3.5 w-3.5" />{label}
    </button>
  );
}
