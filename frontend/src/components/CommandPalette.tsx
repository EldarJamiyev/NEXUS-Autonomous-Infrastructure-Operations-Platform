import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { CornerDownLeft } from "lucide-react";
import { api } from "@/api/client";
import { Dialog, useAction } from "./feedback";
import { cx, inputClass } from "./ui";

interface Item { id: string; label: string; detail?: string; group: string; run: () => void }

export function CommandPalette({ open, onClose, onCopilot }: { open: boolean; onClose: () => void; onCopilot: () => void }) {
  const navigate = useNavigate();
  const { run } = useAction();
  const [q, setQ] = useState("");
  const [results, setResults] = useState<{ type: string; id: string; label: string; detail: string; route: string }[]>([]);
  const [idx, setIdx] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => { if (open) { setQ(""); setIdx(0); window.setTimeout(() => input.current?.focus(), 30); } }, [open]);
  useEffect(() => {
    if (q.trim().length < 2) { setResults([]); return; }
    const t = window.setTimeout(() => api.get<typeof results>(`/api/search?q=${encodeURIComponent(q)}`).then(setResults).catch(() => setResults([])), 160);
    return () => window.clearTimeout(t);
  }, [q]);
  const go = (path: string) => () => { navigate(path); onClose(); };
  const commands: Item[] = useMemo(() => [
    { id: "c-demo", group: "Run", label: "Run guided demo", run: () => { run("demo", () => api.post("/api/demo/start"), "Guided demo started"); onClose(); } },
    { id: "c-chaos", group: "Run", label: "Open Chaos Lab", run: go("/chaos") },
    { id: "c-blackout", group: "Run", label: "Run full infrastructure blackout", run: () => { run("b", () => api.post("/api/demo/blackout"), "Blackout drill started"); navigate("/chaos"); onClose(); } },
    { id: "c-snap", group: "Run", label: "Create state snapshot", run: () => { run("s", () => api.post("/api/snapshots", { label: "palette snapshot" }), "Snapshot created"); onClose(); } },
    { id: "c-self", group: "Run", label: "Run self-test", run: go("/system") },
    { id: "c-ask", group: "Run", label: "Ask the operator assistant", run: () => { onClose(); onCopilot(); } },
    { id: "n-topology", group: "Open", label: "Open topology (digital twin)", run: go("/twin") },
    { id: "n-access", group: "Open", label: "Explain access", run: go("/access") },
    { id: "n-time", group: "Open", label: "Open Time Machine", run: go("/timemachine") },
    { id: "n-whatif", group: "Open", label: "What-if simulator", run: go("/whatif") },
    { id: "n-incidents", group: "Open", label: "Open incidents", run: go("/incidents") },
    { id: "n-approvals", group: "Open", label: "Pending approvals", run: go("/approvals") },
    { id: "n-brief", group: "Open", label: "Generate morning brief", run: go("/operations") },
  ], [navigate, onClose, onCopilot, run]);
  const items: Item[] = [
    ...results.map((r) => ({ id: `r-${r.type}-${r.id}`, group: r.type, label: r.label, detail: r.detail, run: go(r.route) })),
    ...commands.filter((c) => !q || c.label.toLowerCase().includes(q.toLowerCase())),
  ];
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setIdx((i) => Math.min(i + 1, items.length - 1)); }
    if (e.key === "ArrowUp") { e.preventDefault(); setIdx((i) => Math.max(i - 1, 0)); }
    if (e.key === "Enter" && items[idx]) items[idx].run();
  };
  return (
    <Dialog open={open} onClose={onClose} title="Search and commands" wide>
      <input ref={input} value={q} onChange={(e) => { setQ(e.target.value); setIdx(0); }} onKeyDown={onKey}
        placeholder="PC-023, Eldar, INC-0010, LEASE-99182, 10.30.30.42 or a command" aria-label="Search" className={cx(inputClass, "mb-3 h-10 w-full text-base")} />
      <ul role="listbox" className="max-h-[50vh] overflow-y-auto">
        {items.map((it, i) => (
          <li key={it.id} role="option" aria-selected={i === idx}>
            <button onMouseEnter={() => setIdx(i)} onClick={it.run} className={cx("flex w-full items-center gap-3 rounded px-2 py-1.5 text-left", i === idx ? "bg-accent/10" : "")}>
              <span className="w-20 shrink-0 font-cond text-[11px] font-semibold uppercase text-muted">{it.group}</span>
              <span className="min-w-0 flex-1"><span className="text-sm">{it.label}</span>{it.detail && <span className="block truncate text-xs text-muted">{it.detail}</span>}</span>
              {i === idx && <CornerDownLeft className="h-3.5 w-3.5 text-muted" />}
            </button>
          </li>
        ))}
        {!items.length && <li className="px-2 py-6 text-center text-sm text-muted">No matches</li>}
      </ul>
    </Dialog>
  );
}
