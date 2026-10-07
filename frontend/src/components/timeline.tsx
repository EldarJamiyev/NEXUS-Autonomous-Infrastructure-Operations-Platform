import { Check, CircleDashed, Loader2, Minus, RotateCcw, X } from "lucide-react";
import type { TxStep } from "@/types";
import { fmtTime } from "@/lib/format";
import { cx } from "./ui";

const ICON: Record<string, JSX.Element> = {
  done: <Check className="h-3.5 w-3.5" />, failed: <X className="h-3.5 w-3.5" />, running: <Loader2 className="h-3.5 w-3.5 animate-spin" />,
  rolled_back: <RotateCcw className="h-3.5 w-3.5" />, skipped: <Minus className="h-3.5 w-3.5" />, pending: <CircleDashed className="h-3.5 w-3.5" />,
  waiting: <CircleDashed className="h-3.5 w-3.5" />,
};
const COLOR: Record<string, string> = {
  done: "bg-ok text-white border-ok", failed: "bg-crit text-white border-crit", running: "bg-accent text-white border-accent step-running",
  rolled_back: "bg-high text-white border-high", skipped: "bg-inset text-muted border-line", pending: "bg-panel text-muted border-line", waiting: "bg-warn/15 text-warn border-warn",
};

/** DETECTED -> TRIAGED -> POLICY CHECK -> SAFETY CHECK -> BACKUP -> EXECUTION -> VERIFICATION -> COMMIT/ROLLBACK -> CHATOPS -> AUDIT */
export function RemediationTimeline({ steps, horizontal }: { steps: TxStep[]; horizontal?: boolean }) {
  if (horizontal) {
    return (
      <ol className="flex flex-wrap items-start gap-y-2">
        {steps.map((s, i) => (
          <li key={s.name} className="flex items-center" title={s.detail}>
            <span className="flex flex-col items-center gap-1">
              <span className={cx("flex h-6 w-6 items-center justify-center rounded-full border", COLOR[s.status] ?? COLOR.pending)}>{ICON[s.status] ?? ICON.pending}</span>
              <span className={cx("font-cond text-[11px] font-semibold", s.status === "pending" ? "text-muted" : "text-ink")}>{s.status === "rolled_back" ? "ROLLBACK" : s.name}</span>
            </span>
            {i < steps.length - 1 && <span className={cx("mx-1 mb-4 h-px w-5", s.status === "done" ? "bg-ok" : "bg-line")} />}
          </li>
        ))}
      </ol>
    );
  }
  return (
    <ol className="relative space-y-0">
      {steps.map((s, i) => (
        <li key={s.name} className="grid grid-cols-[28px_minmax(0,1fr)] gap-x-3">
          <span className="flex flex-col items-center">
            <span className={cx("flex h-6 w-6 items-center justify-center rounded-full border", COLOR[s.status] ?? COLOR.pending)}>{ICON[s.status] ?? ICON.pending}</span>
            {i < steps.length - 1 && <span className={cx("w-px flex-1", s.status === "done" ? "bg-ok/60" : "bg-line")} style={{ minHeight: 14 }} />}
          </span>
          <div className="pb-3">
            <div className="flex items-baseline gap-2">
              <span className="font-cond text-[13px] font-semibold">{s.status === "rolled_back" ? "ROLLBACK" : s.name}</span>
              <span className="font-mono text-[11px] text-muted">{s.ts ? fmtTime(s.ts) : ""}</span>
            </div>
            {s.detail && <p className="break-words text-xs text-muted">{s.detail}</p>}
          </div>
        </li>
      ))}
    </ol>
  );
}

const STAGE_COLOR: Record<string, string> = {
  EVENT: "bg-info", OBSERVATION: "bg-info", CORRELATION: "bg-warn", ROOT_CAUSE: "bg-high", DECISION: "bg-accent", REMEDIATION: "bg-accent",
  VERIFICATION: "bg-ok", RESOLUTION: "bg-ok", NOTE: "bg-unk",
};

export function IncidentTimeline({ items }: { items: { ts: string; stage: string; message: string }[] }) {
  return (
    <ol className="space-y-0">
      {items.map((e, i) => (
        <li key={i} className="grid grid-cols-[70px_14px_minmax(0,1fr)] gap-x-2">
          <span className="pt-0.5 text-right font-mono text-[11.5px] text-muted num">{fmtTime(e.ts)}</span>
          <span className="flex flex-col items-center">
            <span className={cx("mt-1.5 h-2.5 w-2.5 rounded-full", STAGE_COLOR[e.stage] ?? "bg-unk")} />
            {i < items.length - 1 && <span className="w-px flex-1 bg-line" />}
          </span>
          <div className="pb-3">
            <span className="font-cond text-[12px] font-semibold tracking-wide text-muted">{e.stage.replace("_", " ")}</span>
            <p className="text-sm leading-5">{e.message}</p>
          </div>
        </li>
      ))}
    </ol>
  );
}

export function DiffView({ diff }: { diff: string }) {
  if (!diff) return <p className="text-sm text-muted">No differences.</p>;
  return (
    <pre className="overflow-x-auto rounded border border-line bg-inset py-2 font-mono text-[12px] leading-[18px]">
      {diff.split("\n").map((line, i) => (
        <div key={i} className={cx("px-3", line.startsWith("+") && !line.startsWith("+++") ? "bg-ok/10 text-ok" : line.startsWith("-") && !line.startsWith("---") ? "bg-crit/10 text-crit" : line.startsWith("@@") ? "text-info" : "text-muted")}>
          {line || " "}
        </div>
      ))}
    </pre>
  );
}
