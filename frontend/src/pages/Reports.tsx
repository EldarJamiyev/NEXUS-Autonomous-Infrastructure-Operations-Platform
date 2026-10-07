import { useSearchParams } from "react-router-dom";
import { Download, FileText } from "lucide-react";
import { useApi } from "@/hooks/useApi";
import { Button, Mono, PageHeader, Panel, Pill, Skeleton, Empty, cx } from "@/components/ui";
import { Markdown } from "@/components/Markdown";
import { openAuthed } from "@/lib/download";
import { fmtDateTime } from "@/lib/format";

export default function Reports() {
  const [params, setParams] = useSearchParams();
  const { data: list } = useApi<any[]>("/api/reports", { refreshOn: ["INCIDENT_UPDATED", "DEMO_SCENE"] });
  const id = params.get("id") ?? list?.[0]?.id ?? null;
  const { data: rep } = useApi<any>(id ? `/api/reports/${id}` : null);
  if (!list) return <Skeleton rows={8} />;
  return (
    <div>
      <PageHeader title="Reports" description="Final incident reports from the guided demo and blackout drills, plus saved shift handovers. Per-incident reports are on each incident page." />
      <div className="grid gap-4 xl:grid-cols-[300px_minmax(0,1fr)]">
        <Panel title="Generated reports" bodyClass="p-2">
          {!list.length && <Empty title="No reports yet" hint="Run the guided demo or the blackout drill." />}
          <ul>{list.map((r) => (
            <li key={r.id}><button onClick={() => setParams({ id: r.id })} className={cx("w-full rounded px-2 py-1.5 text-left", id === r.id ? "bg-accent/10" : "hover:bg-inset")}>
              <div className="flex items-center justify-between"><Mono>{r.id}</Mono><Pill tone="neutral">{r.kind}</Pill></div><div className="truncate text-sm">{r.title}</div><div className="text-xs text-muted">{fmtDateTime(r.created_at)}</div>
            </button></li>
          ))}</ul>
        </Panel>
        <Panel title={rep?.title ?? "Report"} actions={rep && <><Button size="sm" icon={<FileText className="h-3.5 w-3.5" />} onClick={() => openAuthed(`/api/reports/${rep.id}?format=html`)}>HTML</Button><Button size="sm" icon={<Download className="h-3.5 w-3.5" />} onClick={() => openAuthed(`/api/reports/${rep.id}?format=md`, `${rep.id}.md`)}>Markdown</Button></>}>
          {rep ? <Markdown text={rep.markdown} /> : <Empty title="Select a report" />}
        </Panel>
      </div>
    </div>
  );
}
