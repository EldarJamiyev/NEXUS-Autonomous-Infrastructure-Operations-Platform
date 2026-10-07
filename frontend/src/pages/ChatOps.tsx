import { Send } from "lucide-react";
import { api } from "@/api/client";
import { useApi } from "@/hooks/useApi";
import { useAuth } from "@/api/auth";
import { Button, PageHeader, Panel, Pill, Skeleton, Empty } from "@/components/ui";
import { useAction } from "@/components/feedback";
import { fmtDateTime } from "@/lib/format";

export default function ChatOps() {
  const { can } = useAuth();
  const { run, busy } = useAction();
  const { data } = useApi<any>("/api/chatops", { refreshOn: ["CHATOPS"] });
  if (!data) return <Skeleton rows={8} />;
  const s = data.stats;
  return (
    <div className="space-y-4">
      <PageHeader title="ChatOps" description="Discord or Slack notifications for every AutoHeal outcome, escalation and approval request."
        meta={data.configured ? <Pill tone="ok">{data.provider.toUpperCase()} webhook configured</Pill> : <Pill tone="unk">DRY RUN - set CHATOPS_PROVIDER and CHATOPS_WEBHOOK_URL to deliver</Pill>}
        actions={<Button variant="primary" icon={<Send className="h-4 w-4" />} disabled={!can("OPERATOR")} loading={busy === "t"} onClick={() => run("t", () => api.post<any>("/api/chatops/test"), (r: any) => `Test notification ${r.delivery_status}`)}>Send test notification</Button>} />
      <div className="grid grid-cols-2 divide-x divide-line overflow-hidden rounded-md border border-line bg-panel sm:grid-cols-5">
        {([["Messages", s.messages], ["Successful remediations", s.successful_remediations], ["Failed remediations", s.failed_remediations], ["Human escalations", s.human_escalations], ["Approval requests", s.approvals]] as [string, number][]).map(([k, v]) => (
          <div key={k} className="px-3 py-2"><div className="text-[11.5px] text-muted">{k}</div><div className="font-cond text-2xl font-semibold num">{v}</div></div>
        ))}
      </div>
      <Panel title="Recent notifications">
        {!data.messages.length && <Empty title="No notifications yet" />}
        <ul className="grid gap-3 lg:grid-cols-2">{data.messages.map((m: any) => (
          <li key={m.id} className="rounded border border-line">
            <div className="flex items-center gap-2 border-b border-line px-3 py-1.5 text-xs"><Pill tone={m.kind === "AUTOHEAL_EVENT" ? "ok" : m.kind === "AUTOHEAL_FAILED" ? "crit" : m.kind === "APPROVAL" ? "warn" : "info"}>{m.kind}</Pill>
              <span className="text-muted">{fmtDateTime(m.ts)}</span><span className="ml-auto"><Pill value={m.delivery_status} /></span></div>
            <pre className="overflow-x-auto px-3 py-2 font-mono text-[12px] leading-5">{m.body}</pre>
            {m.error && m.delivery_status !== "DRY_RUN" && <p className="px-3 pb-2 text-xs text-crit">{m.error}</p>}
          </li>
        ))}</ul>
      </Panel>
    </div>
  );
}
