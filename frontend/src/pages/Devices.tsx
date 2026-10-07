import { useNavigate } from "react-router-dom";
import { useApi } from "@/hooks/useApi";
import { useMetrics } from "@/hooks/live";
import type { Device } from "@/types";
import { DataTable } from "@/components/DataTable";
import { PageHeader, Pill, Risk, Skeleton, Status, Mono, ErrorBox } from "@/components/ui";
import { Spark } from "@/charts/MetricChart";

export default function Devices() {
  const navigate = useNavigate();
  const { history } = useMetrics();
  const { data, error, reload } = useApi<Device[]>("/api/devices", { refreshOn: ["RISK", "QUARANTINE", "DEVICE_DISCOVERED", "INCIDENT", "REMEDIATION", "IDENTITY"] });
  if (error) return <ErrorBox error={error} retry={reload} />;
  if (!data) return <Skeleton rows={10} />;
  return (
    <div>
      <PageHeader title="Devices" description="Every managed and discovered device, with live health, identity confidence and risk." />
      <DataTable rows={data} rowKey={(d) => d.id} onRowClick={(d) => navigate(`/devices/${d.id}`)} placeholder="Filter devices, IPs, roles"
        columns={[
          { key: "id", header: "Device", render: (d) => <div><Mono className="text-info">{d.id}</Mono><div className="max-w-[240px] truncate text-xs text-muted">{d.role}</div></div>, search: (d) => `${d.id} ${d.role} ${d.ip}` },
          { key: "kind", header: "Kind", render: (d) => <span className="capitalize">{d.kind}</span> },
          { key: "ip", header: "IP", render: (d) => <Mono>{d.ip ?? "-"}</Mono> },
          { key: "vlan", header: "VLAN", sort: (d) => d.vlan ?? 0 },
          { key: "status", header: "Status", render: (d) => <span className="flex items-center gap-1"><Status value={d.status} />{d.quarantined && <Pill tone="auto">VLAN 99</Pill>}</span> },
          { key: "risk", header: "Risk", sort: (d) => d.risk, render: (d) => <Risk score={d.risk} level={d.risk_level} /> },
          { key: "identity_confidence", header: "Identity", sort: (d) => d.identity_confidence, render: (d) => <span className="flex items-center gap-2"><span className="font-mono text-xs num">{d.identity_confidence}%</span><Pill value={d.identity_level} /></span> },
          { key: "services", header: "Services", sort: (d) => d.services.filter((s) => s.status !== "running").length, render: (d) => {
            const down = d.services.filter((s) => s.status !== "running");
            return d.services.length ? <span className={down.length ? "text-crit" : "text-muted"}>{d.services.length - down.length}/{d.services.length} running</span> : <span className="text-muted">-</span>;
          } },
          { key: "open_incidents", header: "Incidents", render: (d) => d.open_incidents ? <Pill tone="crit">{d.open_incidents}</Pill> : <span className="text-muted">0</span> },
          { key: "cpu", header: "CPU", sort: (d) => Number(d.metrics?.cpu ?? 0), render: (d) => <span className="flex items-center gap-2"><Spark points={history[d.id] ?? []} field="cpu" /><span className="w-10 font-mono text-xs num">{d.metrics?.cpu ?? "-"}</span></span> },
        ]} />
    </div>
  );
}
