import { useId, type ButtonHTMLAttributes, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { TONE_BG, TONE_SOFT, TONE_TEXT, toneOf, riskTone, type Tone } from "@/lib/format";

export function cx(...parts: (string | false | null | undefined)[]) {
  return parts.filter(Boolean).join(" ");
}

export function Panel({ title, subtitle, actions, children, className, bodyClass, id }: {
  title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClass?: string; id?: string;
}) {
  return (
    <section id={id} className={cx("rounded-md border border-line bg-panel min-w-0", className)}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-3 border-b border-line px-4 py-2.5">
          <div className="min-w-0">
            {title && <h2 className="font-cond text-[15px] font-semibold leading-6 tracking-[0.01em]">{title}</h2>}
            {subtitle && <p className="text-xs text-muted">{subtitle}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cx("p-4", bodyClass)}>{children}</div>
    </section>
  );
}

export function PageHeader({ title, description, actions, meta }: { title: string; description?: ReactNode; actions?: ReactNode; meta?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="font-cond text-[26px] font-semibold leading-8">{title}</h1>
        {description && <p className="mt-0.5 max-w-[80ch] text-sm text-muted">{description}</p>}
        {meta && <div className="mt-2 flex flex-wrap items-center gap-2">{meta}</div>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Pill({ children, tone, value, className, title }: { children?: ReactNode; tone?: Tone; value?: string | null; className?: string; title?: string }) {
  const t = tone ?? toneOf(value);
  return (
    <span title={title} className={cx("inline-flex items-center gap-1 whitespace-nowrap rounded border px-1.5 py-px font-cond text-[12px] font-semibold leading-[18px] tracking-wide", TONE_SOFT[t], className)}>
      {children ?? value ?? "-"}
    </span>
  );
}

export function Dot({ tone, pulse }: { tone: Tone; pulse?: boolean }) {
  return <span className={cx("inline-block h-2 w-2 shrink-0 rounded-full", TONE_BG[tone], pulse && "pulse-crit")} aria-hidden />;
}

export function Status({ value }: { value: string }) {
  const t = toneOf(value);
  return (
    <span className={cx("inline-flex items-center gap-1.5 text-sm", TONE_TEXT[t])}>
      <Dot tone={t} />
      <span className="capitalize">{value.replace(/_/g, " ").toLowerCase()}</span>
    </span>
  );
}

export function Risk({ score, level, compact }: { score: number; level?: string; compact?: boolean }) {
  const t = riskTone(score);
  return (
    <span className={cx("inline-flex items-center gap-1.5 font-mono text-sm num", TONE_TEXT[t])} title={`risk ${score}${level ? ` (${level})` : ""}`}>
      <span className="inline-flex h-[10px] w-[44px] overflow-hidden rounded-sm bg-inset ring-1 ring-line">
        <span className={cx("h-full", TONE_BG[t])} style={{ width: `${Math.max(3, score)}%` }} />
      </span>
      {score}
      {!compact && level && <span className="font-cond text-xs font-semibold">{level}</span>}
    </span>
  );
}

/** Segmented meter (RISK ████░░░░░░ 32) */
export function Meter({ label, value, tone, max = 100 }: { label: string; value: number; tone: Tone; max?: number }) {
  const filled = Math.round((value / max) * 10);
  return (
    <div className="flex items-center gap-3">
      <span className="w-20 text-xs text-muted">{label}</span>
      <span className="flex gap-[3px]" aria-hidden>
        {Array.from({ length: 10 }, (_, i) => (
          <span key={i} className={cx("h-3 w-3 rounded-[2px]", i < filled ? TONE_BG[tone] : "bg-inset ring-1 ring-line")} />
        ))}
      </span>
      <span className={cx("font-mono text-sm num", TONE_TEXT[tone])}>{value}</span>
    </div>
  );
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" | "ghost" | "auto"; icon?: ReactNode; loading?: boolean; size?: "sm" | "md" };
export function Button({ variant = "secondary", icon, loading, size = "md", className, children, disabled, ...rest }: ButtonProps) {
  const styles = {
    primary: "bg-ink text-panel hover:bg-ink/85 border-ink",
    secondary: "bg-panel text-ink hover:bg-inset border-line",
    danger: "bg-crit text-white hover:bg-crit/90 border-crit",
    ghost: "bg-transparent text-muted hover:text-ink hover:bg-inset border-transparent",
    auto: "bg-accent text-white hover:bg-accent/90 border-accent",
  }[variant];
  return (
    <button
      type="button"
      disabled={disabled || loading}
      className={cx("inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded border font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        size === "sm" ? "h-7 px-2 text-xs" : "h-8 px-3 text-sm", styles, className)}
      {...rest}
    >
      {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : icon}
      {children}
    </button>
  );
}

export function KV({ items, cols = 2 }: { items: [ReactNode, ReactNode][]; cols?: 1 | 2 | 3 }) {
  return (
    <dl className={cx("grid gap-x-6 gap-y-2", cols === 1 ? "grid-cols-1" : cols === 2 ? "grid-cols-1 sm:grid-cols-2" : "grid-cols-1 sm:grid-cols-3")}>
      {items.map(([k, v], i) => (
        <div key={i} className="min-w-0">
          <dt className="text-xs text-muted">{k}</dt>
          <dd className="truncate text-sm">{v ?? "-"}</dd>
        </div>
      ))}
    </dl>
  );
}

export const Mono = ({ children, className }: { children: ReactNode; className?: string }) => <span className={cx("font-mono text-[12.5px]", className)}>{children}</span>;

export function Empty({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-1 rounded border border-dashed border-line px-4 py-8 text-center">
      <p className="text-sm font-medium">{title}</p>
      {hint && <p className="max-w-[60ch] text-xs text-muted">{hint}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function ErrorBox({ error, retry }: { error: { status?: number; detail?: string; message?: string } | null; retry?: () => void }) {
  if (!error) return null;
  return (
    <div role="alert" className="flex items-center justify-between gap-3 rounded border border-crit/40 bg-crit/10 px-3 py-2 text-sm text-crit">
      <span>{error.status ? `${error.status}: ` : ""}{error.detail ?? error.message}</span>
      {retry && <Button size="sm" onClick={retry}>Retry</Button>}
    </div>
  );
}

export function Skeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-2" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => <div key={i} className="h-5 animate-pulse rounded bg-inset" style={{ width: `${92 - i * 9}%` }} />)}
    </div>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: ReactNode; count?: number }[]; value: T; onChange: (v: T) => void }) {
  const id = useId();
  return (
    <div role="tablist" aria-label="Sections" className="mb-3 flex flex-wrap gap-1 border-b border-line">
      {tabs.map((t) => (
        <button key={t.id} id={`${id}-${t.id}`} role="tab" aria-selected={value === t.id} onClick={() => onChange(t.id)}
          className={cx("-mb-px border-b-2 px-3 py-1.5 text-sm transition-colors", value === t.id ? "border-accent font-medium text-ink" : "border-transparent text-muted hover:text-ink")}>
          {t.label}
          {t.count !== undefined && <span className="ml-1.5 rounded bg-inset px-1 font-mono text-[11px] text-muted">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="flex min-w-0 flex-col gap-1">
      <span className="text-xs font-medium text-muted">{label}</span>
      {children}
      {hint && <span className="text-[11px] text-muted">{hint}</span>}
    </label>
  );
}
export const inputClass = "h-8 rounded border border-line bg-panel px-2 text-sm text-ink placeholder:text-muted focus:border-accent focus:outline-none";

export function EntityLink({ kind, id, children }: { kind: "device" | "incident" | "user" | "tx"; id: string; children?: ReactNode }) {
  const to = kind === "device" ? `/devices/${id}` : kind === "incident" ? `/incidents/${id}` : kind === "user" ? `/identity/${id}` : `/autoheal?tx=${id}`;
  return <Link to={to} className="font-mono text-[12.5px] text-info hover:underline">{children ?? id}</Link>;
}

export function Section({ title, children, aside }: { title: string; children: ReactNode; aside?: ReactNode }) {
  return (
    <div className="mb-4">
      <div className="mb-1.5 flex items-center justify-between gap-2">
        <h3 className="text-sm font-semibold">{title}</h3>
        {aside}
      </div>
      {children}
    </div>
  );
}
