export type Tone = "ok" | "info" | "warn" | "high" | "crit" | "auto" | "unk" | "neutral";

const TONES: Record<string, Tone> = {};
const put = (tone: Tone, words: string) => words.split(" ").forEach((w) => (TONES[w] = tone));
put("ok", "HEALTHY RUNNING ACTIVE RESOLVED COMMITTED SUCCESS PASS PASSED ALLOW TRUSTED VERIFIED APPLIED COMPLIANT REMEDIATED APPROVED LOW NORMAL VALID SENT UP OK CONSISTENT COMPLETED");
put("info", "INFO NOTICE INVESTIGATING MITIGATED RECOVERY P4 RECOMMEND RESOLVED_EXTERNALLY ACCEPTED NOT_REQUIRED MANUAL");
put("warn", "WARNING UNCERTAIN MEDIUM PENDING EXPIRING DEGRADED APPROVAL_REQUIRED AWAITING_APPROVAL EXPECTED P3 PENDING_APPROVAL WARN DRAFT HUMAN_REQUIRED OBSERVING SHADOWED");
put("high", "HIGH SUSPICIOUS ROLLED_BACK P2 OPEN");
put("crit", "CRITICAL FAILED FAIL DENY DOWN STOPPED EXPIRED_CERT UNKNOWN_IDENTITY EMERGENCY REJECTED BLOCKED P1 CONFLICT MISMATCH");
put("auto", "AUTOMATE REMEDIATING PLANNED QUARANTINED QUARANTINE RUNNING_TX INJECTING");
put("unk", "UNKNOWN INACTIVE NONE SKIPPED CANCELLED DRY_RUN EXPIRED REVOKED DENIED REMOVED SKIPPED_DUPLICATE OBSERVE_ONLY SUPERSEDED STALE NOT_APPLICABLE");

export function toneOf(value?: string | null): Tone {
  if (!value) return "neutral";
  const v = value.toUpperCase().replace(/[ -]/g, "_");
  return TONES[v] ?? (v.includes("FAIL") ? "crit" : v.includes("MISMATCH") ? "crit" : "neutral");
}
export const riskTone = (score: number): Tone => (score >= 80 ? "crit" : score >= 60 ? "high" : score >= 30 ? "warn" : "ok");
export const confidenceTone = (c: number): Tone => (c >= 95 ? "ok" : c >= 80 ? "ok" : c >= 60 ? "warn" : c >= 40 ? "high" : "crit");

export const TONE_TEXT: Record<Tone, string> = { ok: "text-ok", info: "text-info", warn: "text-warn", high: "text-high", crit: "text-crit", auto: "text-accent", unk: "text-unk", neutral: "text-muted" };
export const TONE_BG: Record<Tone, string> = { ok: "bg-ok", info: "bg-info", warn: "bg-warn", high: "bg-high", crit: "bg-crit", auto: "bg-accent", unk: "bg-unk", neutral: "bg-muted" };
export const TONE_SOFT: Record<Tone, string> = {
  ok: "bg-ok/10 text-ok border-ok/30", info: "bg-info/10 text-info border-info/30", warn: "bg-warn/10 text-warn border-warn/35", high: "bg-high/10 text-high border-high/35",
  crit: "bg-crit/10 text-crit border-crit/35", auto: "bg-accent/10 text-accent border-accent/35", unk: "bg-unk/10 text-unk border-unk/30", neutral: "bg-inset text-muted border-line",
};

const pad = (n: number) => String(n).padStart(2, "0");
export function fmtTime(iso?: string | null): string {
  if (!iso) return "-";
  const d = new Date(iso);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
export function fmtDateTime(iso?: string | null): string {
  if (!iso) return "-";
  const d = new Date(iso);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
export function ago(iso?: string | null): string {
  if (!iso) return "-";
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 0) return `in ${dur(-s)}`;
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}
export function dur(seconds?: number | null): string {
  if (seconds === null || seconds === undefined) return "-";
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)} s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.round((seconds % 3600) / 60)}m`;
}
export const ms = (v?: number | null) => (v === null || v === undefined ? "-" : v < 1000 ? `${v} ms` : `${(v / 1000).toFixed(1)} s`);
export const title = (s: string) => s.replace(/_/g, " ").toLowerCase().replace(/^\w/, (c) => c.toUpperCase());
export const json = (v: unknown) => (typeof v === "string" ? v : JSON.stringify(v));
