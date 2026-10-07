import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useLive } from "@/hooks/live";
import type { LiveEvent } from "@/types";
import { fmtTime, toneOf, TONE_TEXT, type Tone } from "@/lib/format";
import { cx } from "./ui";

export const PHASES = ["OBSERVE", "NORMALIZE", "CORRELATE", "UNDERSTAND", "COMPARE", "POLICY", "RISK", "DECIDE", "PLAN", "EXECUTE", "VERIFY", "AUDIT", "RECONCILE"];
const LABEL: Record<string, string> = { UNDERSTAND: "State", COMPARE: "Intent", POLICY: "Policy", RISK: "Risk", RECONCILE: "Reconcile" };

/** The reconciliation loop, lit by live events: the phase of the latest event glows and fades. */
export function LoopStrip() {
  const { phase, connected } = useLive();
  const [, tick] = useState(0);
  useEffect(() => {
    const id = window.setInterval(() => tick((n) => n + 1), 500);
    return () => window.clearInterval(id);
  }, []);
  const age = phase ? Date.now() - phase.at : Infinity;
  return (
    <ol className="hidden items-center gap-px xl:flex" aria-label="Reconciliation loop">
      {PHASES.map((p, i) => {
        const active = phase?.name === p && age < 4000;
        const name = LABEL[p] ?? p.charAt(0) + p.slice(1).toLowerCase();
        return (
          <li key={p} className="flex items-center">
            <span key={active ? phase?.at : p} title={`${i + 1}. ${p}`}
              className={cx("rounded px-1.5 py-0.5 font-cond text-[11.5px] font-semibold transition-colors", active ? "phase-flash bg-accent/15 text-accent" : connected ? "text-muted/80" : "text-muted/40")}>
              {name}
            </span>
            {i < PHASES.length - 1 && <span className="mx-px text-[10px] text-line" aria-hidden>›</span>}
          </li>
        );
      })}
    </ol>
  );
}

const SEV_TONE: Record<string, Tone> = { critical: "crit", high: "high", warning: "warn", notice: "info", info: "neutral", debug: "unk" };

export function EventLine({ e, compact }: { e: LiveEvent; compact?: boolean }) {
  const tone = SEV_TONE[e.severity] ?? "neutral";
  return (
    <li className="grid grid-cols-[64px_minmax(0,1fr)] gap-x-2 border-b border-line/60 py-1 font-mono text-[12px] leading-[17px] last:border-0">
      <span className="text-muted num">{fmtTime(e.ts)}</span>
      <span className="min-w-0">
        <span className={cx("font-semibold", tone === "neutral" ? "text-ink" : TONE_TEXT[tone])}>{e.type}</span>
        {e.target && <span className="text-muted"> {e.target}</span>}
        {!compact && <span className="block truncate text-muted" title={e.message}>{e.message}</span>}
      </span>
    </li>
  );
}

export function EventStream({ filter, limit = 60, compact, initial = [] }: { filter?: (e: LiveEvent) => boolean; limit?: number; compact?: boolean; initial?: LiveEvent[] }) {
  const { events, connected } = useLive();
  const seen = new Set(events.map((e) => e.id));
  const merged = [...events, ...initial.filter((e) => !seen.has(e.id))].filter((e) => e.type !== "AUTH_FAILURE" && (!filter || filter(e))).slice(0, limit);
  return (
    <div>
      <div className="mb-1 flex items-center gap-2 text-xs text-muted">
        <span className={cx("inline-block h-2 w-2 rounded-full", connected ? "bg-ok" : "bg-unk")} />
        {connected ? "live" : "reconnecting"}
        <Link to="/audit" className="ml-auto hover:text-ink">Audit trail</Link>
      </div>
      {merged.length ? <ol aria-live="off">{merged.map((e) => <EventLine key={e.id} e={e} compact={compact} />)}</ol> : <p className="py-6 text-center text-sm text-muted">Waiting for events</p>}
    </div>
  );
}

export function useClockTick(ms = 1000) {
  const [, setN] = useState(0);
  useEffect(() => {
    const id = window.setInterval(() => setN((n) => n + 1), ms);
    return () => window.clearInterval(id);
  }, [ms]);
}

export const toneText = (v: string) => TONE_TEXT[toneOf(v)];
