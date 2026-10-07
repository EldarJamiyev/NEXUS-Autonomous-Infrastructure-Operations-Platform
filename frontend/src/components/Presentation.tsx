import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Pause, Play, RotateCcw, SkipForward, X } from "lucide-react";
import { api } from "@/api/client";
import { useDemo } from "@/hooks/live";
import { useAction } from "./feedback";
import { Button, cx } from "./ui";

/** Presentation mode for the guided demo: eight steps, current scene narrative, NEXT / PAUSE / RESET. */
export function Presentation() {
  const demo = useDemo();
  const navigate = useNavigate();
  const { run, busy } = useAction();
  const [follow, setFollow] = useState(true);
  const [hidden, setHidden] = useState(false);
  const lastScene = useRef(0);
  useEffect(() => {
    if (!demo?.current || !follow) return;
    if (demo.current.number !== lastScene.current) {
      lastScene.current = demo.current.number;
      navigate(demo.current.page);
    }
  }, [demo?.current?.number, follow, navigate]);
  useEffect(() => { if (demo?.status === "running") setHidden(false); }, [demo?.status]);
  if (!demo || demo.status === "idle" || hidden) return null;
  const cur = demo.current;
  return (
    <aside aria-label="Guided demo" className="fixed bottom-4 left-4 z-50 w-[min(430px,calc(100vw-2rem))] rounded-md border border-accent/50 bg-panel shadow-2xl lg:left-[230px]">
      <header className="flex items-center gap-2 border-b border-line px-3 py-2">
        <span className="font-cond text-sm font-semibold tracking-wide text-accent">GUIDED DEMO</span>
        <span className="font-mono text-xs text-muted">scene {demo.scene}/{demo.total} · {demo.elapsed.toFixed(0)} s</span>
        <button className="ml-auto rounded p-1 text-muted hover:bg-inset" aria-label="Hide demo panel" onClick={() => setHidden(true)}><X className="h-4 w-4" /></button>
      </header>
      <ol className="grid grid-cols-8 gap-1 px-3 pt-3" aria-label="Steps">
        {demo.steps.map((s, i) => {
          const n = i + 1;
          const state = cur ? (n < cur.step ? "done" : n === cur.step ? "now" : "next") : demo.status === "finished" ? "done" : "next";
          return (
            <li key={s} title={s} className="flex flex-col gap-1">
              <span className={cx("h-1.5 rounded-full", state === "done" ? "bg-ok" : state === "now" ? "bg-accent" : "bg-line")} />
              <span className={cx("font-mono text-[10px]", state === "now" ? "text-accent" : "text-muted")}>{String(n).padStart(2, "0")}</span>
            </li>
          );
        })}
      </ol>
      <div className="px-3 py-2">
        {cur ? (
          <>
            <p className="font-cond text-[12px] font-semibold tracking-wide text-muted">STEP {String(cur.step).padStart(2, "0")} · {cur.step_title.toUpperCase()}</p>
            <p className="font-cond text-lg font-semibold leading-6">{cur.title}</p>
            <p className="mt-1 text-sm leading-5 text-ink/85">{cur.narrative}</p>
          </>
        ) : <p className="text-sm">Demo {demo.status}.</p>}
        {demo.status === "finished" && demo.report_id && (
          <p className="mt-2 text-sm">Final report: <Link className="text-info hover:underline" to={`/reports?id=${demo.report_id}`}>{demo.report_id}</Link></p>
        )}
      </div>
      <footer className="flex flex-wrap items-center gap-2 border-t border-line px-3 py-2">
        <Button size="sm" variant="auto" icon={<SkipForward className="h-3.5 w-3.5" />} disabled={demo.status !== "running" && demo.status !== "paused"} onClick={() => api.post("/api/demo/next")}>Next</Button>
        {demo.status === "paused"
          ? <Button size="sm" icon={<Play className="h-3.5 w-3.5" />} onClick={() => api.post("/api/demo/resume")}>Resume</Button>
          : <Button size="sm" icon={<Pause className="h-3.5 w-3.5" />} disabled={demo.status !== "running"} onClick={() => api.post("/api/demo/pause")}>Pause</Button>}
        <Button size="sm" icon={<RotateCcw className="h-3.5 w-3.5" />} loading={busy === "reset"} onClick={() => run("reset", async () => { await api.post("/api/demo/stop"); return api.post("/api/demo/reset"); }, "Demo environment reset")}>Reset</Button>
        <label className="ml-auto flex items-center gap-1.5 text-xs text-muted"><input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} />Follow pages</label>
      </footer>
    </aside>
  );
}
