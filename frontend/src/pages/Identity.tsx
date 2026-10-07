import { Link, useNavigate } from "react-router-dom";
import { ChevronRight } from "lucide-react";
import { useApi } from "@/hooks/useApi";
import { DataTable } from "@/components/DataTable";
import { Mono, PageHeader, Panel, Pill, Risk, Skeleton, cx } from "@/components/ui";
import { confidenceTone, TONE_BG } from "@/lib/format";

export default function Identity() {
  const navigate = useNavigate();
  const { data: users } = useApi<any[]>("/api/users", { refreshOn: ["USER_", "RISK", "LEASE", "AUTH"] });
  const { data: idn } = useApi<any>("/api/identity", { refreshOn: ["IDENTITY", "USER_", "DEVICE_DISCOVERED", "QUARANTINE", "LEASE"] });
  if (!users || !idn) return <Skeleton rows={10} />;
  return (
    <div className="space-y-4">
      <PageHeader title="Users and identity" description="Who is on which device, how sure NEXUS is about it, and what that identity is allowed to reach." />
      <Panel title="Identity chains" subtitle="AD user → group → workstation → IP → MAC → VLAN → switch port → access lease">
        <div className="space-y-2">{idn.chains.map((c: any) => (
          <div key={`${c.user}-${c.device}`} className="flex flex-wrap items-center gap-1 rounded border border-line bg-inset px-2 py-1.5 text-sm">
            {[<Link key="u" to={`/identity/${c.user}`} className="font-medium text-info">{c.user}</Link>, <span key="g" className="text-xs">{c.groups.join(", ")}</span>,
              <Link key="d" to={`/devices/${c.device}`} className="font-mono text-xs text-info">{c.device}</Link>, <Mono key="ip">{c.ip}</Mono>, <Mono key="mac">{c.mac}</Mono>,
              <span key="v">VLAN {c.vlan}</span>, <Mono key="sw">{c.switchport}</Mono>, c.leases.length ? <Pill key="l" tone="ok">{c.leases.join(", ")}</Pill> : <span key="l" className="text-xs text-muted">no lease</span>]
              .map((el, i, arr) => <span key={i} className="flex items-center gap-1">{el}{i < arr.length - 1 && <ChevronRight className="h-3.5 w-3.5 text-muted" />}</span>)}
            <span className="ml-auto"><Pill tone={confidenceTone(c.confidence)}>identity {c.confidence}%</Pill></span>
          </div>
        ))}</div>
      </Panel>
      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Users" bodyClass="p-3">
          <DataTable rows={users} rowKey={(u) => u.id} onRowClick={(u) => navigate(`/identity/${u.id}`)} searchable={false}
            columns={[{ key: "name", header: "User", render: (u) => <div><div className="font-medium">{u.name}</div><div className="text-xs text-muted">{u.title}</div></div> },
              { key: "groups", header: "Groups", render: (u) => <div className="flex flex-wrap gap-1">{u.groups.map((g: string) => <Pill key={g} tone={g.endsWith("ADMIN") ? "auto" : "neutral"}>{g}</Pill>)}</div> },
              { key: "sessions", header: "Session", render: (u) => u.sessions.length ? <Mono>{u.sessions.map((s: any) => s.device).join(", ")}</Mono> : <span className="text-xs text-muted">none</span> },
              { key: "active_leases", header: "Leases" }, { key: "risk", header: "Risk", sort: (u) => u.risk, render: (u) => <Risk score={u.risk} compact /> },
              { key: "console_role", header: "Console role", render: (u) => <Pill tone="neutral">{u.console_role}</Pill> }]} />
        </Panel>
        <Panel title="Device identity confidence" subtitle={idn.note} bodyClass="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-inset text-xs text-muted"><tr><th className="px-3 py-2 font-medium">Device</th><th className="font-medium">Confidence</th>
                {Object.entries(idn.weights).map(([k, w]) => <th key={k} className="px-1 text-center font-medium" title={k}>{k.split("_").map((s) => s[0]).join("").toUpperCase()}<span className="block font-mono text-[10px]">{String(w)}</span></th>)}</tr></thead>
              <tbody>{idn.devices.map((d: any) => (
                <tr key={d.id} className="border-t border-line">
                  <td className="px-3 py-1.5"><Link to={`/devices/${d.id}`} className="font-mono text-xs text-info">{d.id}</Link>{d.quarantined && <Pill tone="auto" className="ml-1">Q</Pill>}</td>
                  <td className="whitespace-nowrap pr-2"><span className="font-mono text-xs">{d.confidence}%</span> <Pill value={d.level} /></td>
                  {d.signals.map((s: any) => <td key={s.key} className="text-center" title={`${s.label}: ${s.detail}`}><span className={cx("inline-block h-2.5 w-2.5 rounded-sm", s.status === null ? "bg-line" : s.status ? TONE_BG.ok : TONE_BG.crit)} /></td>)}
                </tr>
              ))}</tbody>
            </table>
          </div>
          <p className="px-3 py-2 text-[11px] text-muted">Columns: AD computer, AD session, DHCP hostname, DNS, known MAC, expected VLAN, monitoring. Grey = not applicable to that device kind. Levels: {idn.levels.map((l: any) => `${l.level} ≥${l.min}`).join(" · ")}</p>
        </Panel>
      </div>
    </div>
  );
}
