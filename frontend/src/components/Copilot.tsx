import { useState } from "react";
import { Send } from "lucide-react";
import { api } from "@/api/client";
import { Dialog } from "./feedback";
import { Button, cx, inputClass } from "./ui";

const EXAMPLES = ["Why is LINUX01 unhealthy?", "What changed on LINUX01 today?", "Which users would be affected if VLAN 30 goes down?",
  "Why can't Aysel access port 22?", "What caused the latest P1 incident?", "Which devices currently have elevated risk?", "Why is UNKNOWN-001 quarantined?"];

export function Copilot({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [log, setLog] = useState<{ question: string; answer: string; interpreted_as: string }[]>([]);
  const ask = async (question: string) => {
    if (!question.trim()) return;
    setBusy(true);
    try {
      const r = await api.post<{ question: string; answer: string; interpreted_as: string }>("/api/copilot/ask", { question });
      setLog((l) => [r, ...l]);
      setQ("");
    } finally { setBusy(false); }
  };
  return (
    <Dialog drawer open={open} onClose={onClose} title="NEXUS operator assistant">
      <p className="mb-3 text-xs text-muted">Answers come only from NEXUS state through read-only queries. Deterministic intent matching — no language model, and it cannot change anything.</p>
      <form onSubmit={(e) => { e.preventDefault(); ask(q); }} className="mb-3 flex gap-2">
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Ask about state, changes, access, risk…" aria-label="Question" className={cx(inputClass, "flex-1")} />
        <Button variant="primary" loading={busy} icon={<Send className="h-3.5 w-3.5" />} onClick={() => ask(q)}>Ask</Button>
      </form>
      <div className="mb-4 flex flex-wrap gap-1.5">
        {EXAMPLES.map((x) => <button key={x} onClick={() => ask(x)} className="rounded border border-line px-2 py-0.5 text-xs text-muted hover:border-accent hover:text-accent">{x}</button>)}
      </div>
      <ul className="space-y-3">
        {log.map((r, i) => (
          <li key={i} className="rounded border border-line p-3">
            <p className="text-sm font-medium">{r.question}</p>
            <p className="mt-1 whitespace-pre-line text-sm leading-6">{r.answer}</p>
            <p className="mt-2 font-mono text-[11px] text-muted">interpreted as {r.interpreted_as}</p>
          </li>
        ))}
      </ul>
    </Dialog>
  );
}
