import { useState } from "react";
import { Link } from "react-router-dom";
import { useApi } from "@/hooks/useApi";
import { DataTable } from "@/components/DataTable";
import { Mono, PageHeader, Panel, Pill, Skeleton, Tabs, Empty, cx } from "@/components/ui";

type Tab = "vlans" | "ips" | "macs" | "ports" | "firewall" | "consistency" | "health";

export default function NetworkPage() {
  const [tab, setTab] = useState<Tab>("vlans");
  const { data: inv } = useApi<any>("/api/network/inventory", { refreshOn: ["DHCP", "ARP", "DEVICE_DISCOVERED", "QUARANTINE", "CONFIG"] });
  const { data: fw } = useApi<any>("/api/firewall", { refreshOn: ["FIREWALL", "LEASE", "REMEDIATION"] });
  const { data: health } = useApi<any>("/api/network/health", { interval: 5000 });
  if (!inv) return <Skeleton rows={10} />;
  return (
    <div>
      <PageHeader title="Network" description="IP, MAC, VLAN, switch port and service inventory, firewall rule state with shadow analysis, DHCP conflicts and DNS consistency. Discovery is passive (DHCP, ARP, syslog) - NEXUS never scans aggressively." />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "vlans", label: "VLANs", count: inv.vlans.length }, { id: "ips", label: "IP inventory", count: inv.ips.length }, { id: "macs", label: "MAC inventory", count: inv.macs.length },
        { id: "ports", label: "Switch ports", count: inv.switchports.length }, { id: "firewall", label: "Firewall rules", count: fw?.rules?.length },
        { id: "consistency", label: "Conflicts & DNS", count: inv.dhcp_conflicts.length + inv.port_anomalies.length || undefined }, { id: "health", label: "Health" }]} />
      {tab === "vlans" && (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">{inv.vlans.map((v: any) => (
          <Panel key={v.id} title={`VLAN ${v.id} · ${v.name}`} subtitle={v.purpose} actions={<Pill value={v.status.toUpperCase()} />}>
            <p className="font-mono text-sm">{v.subnet} <span className="text-muted">gw {v.gateway}</span></p>
            <p className="mt-2 text-sm">{v.devices.length ? v.devices.map((d: string) => <Link key={d} to={`/devices/${d}`} className="mr-2 font-mono text-xs text-info">{d}</Link>) : <span className="text-muted">no devices</span>}</p>
            {v.dhcp && (
              <div className="mt-3">
                <div className="flex justify-between text-xs text-muted"><span>DHCP pool</span><span className="font-mono">{v.dhcp.in_use}/{v.dhcp.size} · {v.dhcp.stale} stale</span></div>
                <div className="mt-1 h-2 overflow-hidden rounded-sm bg-inset ring-1 ring-line"><div className={cx("h-full", v.dhcp.utilization >= 95 ? "bg-crit" : v.dhcp.utilization >= 80 ? "bg-warn" : "bg-ok")} style={{ width: `${v.dhcp.utilization}%` }} /></div>
              </div>
            )}
          </Panel>
        ))}</div>
      )}
      {tab === "ips" && <DataTable rows={inv.ips} rowKey={(r: any) => r.address} columns={[{ key: "address", header: "Address", render: (r: any) => <Mono>{r.address}</Mono> }, { key: "device", header: "Device", render: (r: any) => r.device ? <Link className="font-mono text-xs text-info" to={`/devices/${r.device}`}>{r.device}</Link> : "-" },
        { key: "mac", header: "MAC", render: (r: any) => <Mono>{r.mac}</Mono> }, { key: "vlan", header: "VLAN" }, { key: "assignment", header: "Assignment", render: (r: any) => <Pill tone={r.assignment === "apipa" ? "crit" : "neutral"}>{r.assignment}</Pill> },
        { key: "dhcp_hostname", header: "DHCP hostname", render: (r: any) => r.dhcp_hostname ?? "-" }, { key: "conflict", header: "Conflict", render: (r: any) => r.conflict ? <Pill tone="crit">CONFLICT</Pill> : "" }]} />}
      {tab === "macs" && <DataTable rows={inv.macs} rowKey={(r: any) => r.address} columns={[{ key: "address", header: "MAC", render: (r: any) => <Mono>{r.address}</Mono> }, { key: "device", header: "Device", render: (r: any) => <Mono>{r.device}</Mono> },
        { key: "vendor", header: "Vendor" }, { key: "known", header: "Inventory", render: (r: any) => <Pill tone={r.known ? "ok" : "crit"}>{r.known ? "KNOWN" : "UNKNOWN"}</Pill> }, { key: "interface", header: "Port", render: (r: any) => <Mono>{r.interface ?? "-"}</Mono> }]} />}
      {tab === "ports" && <DataTable rows={inv.switchports} rowKey={(r: any) => r.id} columns={[{ key: "name", header: "Port", render: (r: any) => <Mono>{r.switch} {r.name}</Mono> }, { key: "mode", header: "Mode" }, { key: "vlan", header: "VLAN", render: (r: any) => r.vlan ?? "trunk" },
        { key: "device", header: "Device", render: (r: any) => r.device ? <Link className="font-mono text-xs text-info" to={`/devices/${r.device}`}>{r.device}</Link> : <span className="text-muted">-</span> }, { key: "status", header: "Status", render: (r: any) => <Pill value={r.status.toUpperCase()} /> }]} />}
      {tab === "firewall" && (!fw ? <Skeleton /> : !fw.available ? <Panel title="Firewall unreachable"><p className="text-sm text-crit">{fw.error}</p><p className="mt-1 text-sm text-muted">NEXUS preserves the last known safe state and queues changes as PENDING until the API returns.</p></Panel> : (
        <div className="space-y-3">
          {fw.shadowed.map((s: any) => <p key={s.rule} className="rounded border border-warn/40 bg-warn/5 p-2 text-sm"><Pill tone="warn">{s.kind}</Pill> {s.message}</p>)}
          <p className="text-xs text-muted">{fw.state.adapter} ({fw.state.mode}) · {fw.state.rule_count} rules · checksum <Mono>{String(fw.state.checksum).slice(0, 12)}</Mono> · first match wins</p>
          <DataTable rows={fw.rules} rowKey={(r: any) => r.id} pageSize={40} columns={[{ key: "position", header: "#", sort: (r: any) => r.position, render: (r: any) => <Mono>{r.position}</Mono> }, { key: "id", header: "Rule", render: (r: any) => <Mono>{r.id}</Mono> },
            { key: "action", header: "Action", render: (r: any) => <Pill value={r.action} /> }, { key: "source", header: "Source", render: (r: any) => <Mono>{r.source}</Mono> }, { key: "destination", header: "Destination", render: (r: any) => <Mono>{r.destination}</Mono> },
            { key: "port", header: "Port", render: (r: any) => <Mono>{r.port}/{r.protocol}</Mono> }, { key: "origin", header: "Origin", render: (r: any) => <Pill tone={r.origin === "manual" ? "crit" : r.origin === "lease" ? "ok" : r.origin.startsWith("nexus") ? "auto" : "neutral"}>{r.origin}</Pill> },
            { key: "description", header: "Description", render: (r: any) => <span className="text-xs text-muted">{r.description}</span> }]} />
        </div>
      ))}
      {tab === "consistency" && (
        <div className="grid gap-4 xl:grid-cols-2">
          <Panel title="DHCP conflicts">{inv.dhcp_conflicts.length ? inv.dhcp_conflicts.map((c: any) => <p key={c.ip} className="text-sm"><Pill tone="crit">CONFLICT</Pill> <Mono>{c.ip}</Mono> owner {c.owner} ({c.owner_mac}) vs {c.conflicting_macs.join(", ")}</p>) : <Empty title="No address conflicts" />}</Panel>
          <Panel title="Port and service anomalies">{inv.port_anomalies.length ? inv.port_anomalies.map((a: any, i: number) => <p key={i} className="text-sm"><Pill value={a.status.includes("UNEXPECTED") ? "UNEXPECTED" : "WARNING"} tone={a.status.includes("UNEXPECTED") ? "crit" : "warn"} /> {a.device} TCP/{a.port} - {a.status.toLowerCase()}</p>) : <Empty title="Listening ports match baselines" />}</Panel>
          <Panel title="DNS consistency" subtitle="DHCP hostname vs DNS name vs AD computer vs inventory" className="xl:col-span-2" bodyClass="p-3">
            <DataTable rows={inv.dns_consistency} rowKey={(r: any) => r.device} searchable={false} columns={[{ key: "device", header: "Device", render: (r: any) => <Mono>{r.device}</Mono> }, { key: "ip", header: "IP", render: (r: any) => <Mono>{r.ip}</Mono> },
              { key: "dhcp_hostname", header: "DHCP", render: (r: any) => r.dhcp_hostname ?? "-" }, { key: "dns_name", header: "DNS", render: (r: any) => <Mono>{r.dns_name ?? "-"}</Mono> }, { key: "ad_computer", header: "AD", render: (r: any) => r.ad_computer ?? "-" },
              { key: "status", header: "Status", render: (r: any) => <Pill tone={r.status === "CONSISTENT" ? "ok" : r.status.startsWith("UNVERIFIABLE") ? "warn" : "crit"}>{r.status}</Pill> }]} />
          </Panel>
        </div>
      )}
      {tab === "health" && (!health ? <Skeleton /> : (
        <Panel title="Network health" subtitle={health.simulated ? "Simulated, deterministic values" : undefined} bodyClass="p-0">
          <table className="w-full text-left text-sm"><thead className="bg-inset text-xs text-muted"><tr>{["VLAN", "Devices", "Availability", "Latency", "Packet loss"].map((h) => <th key={h} className="px-4 py-2 font-medium">{h}</th>)}</tr></thead>
            <tbody>{health.vlans.map((v: any) => <tr key={v.vlan} className="border-t border-line"><td className="px-4 py-2">VLAN {v.vlan} {v.name}</td><td className="px-4">{v.devices}</td>
              <td className={cx("px-4 font-mono", v.availability !== null && v.availability < 100 ? "text-crit" : "")}>{v.availability ?? "-"}{v.availability !== null ? "%" : ""}</td><td className="px-4 font-mono">{v.latency_ms ?? "-"} ms</td><td className="px-4 font-mono">{v.packet_loss ?? "-"}%</td></tr>)}</tbody></table>
          <p className="px-4 py-2 text-xs text-muted">{health.devices_reachable}/{health.devices_total} devices reachable · {health.services_up}/{health.services_total} services up</p>
        </Panel>
      ))}
    </div>
  );
}
