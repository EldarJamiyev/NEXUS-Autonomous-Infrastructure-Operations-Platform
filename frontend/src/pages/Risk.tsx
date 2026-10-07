import { Link } from "react-router-dom";
import { useApi } from "@/hooks/useApi";
import { Meter, PageHeader, Panel, Pill, Risk as RiskBar, Skeleton } from "@/components/ui";
import { WhyButton } from "@/components/explain";
import { confidenceTone, riskTone } from "@/lib/format";

export default function RiskPage() {
  const { data } = useApi<any>("/api/risk", { refreshOn: ["RISK", "IDENTITY", "QUARANTINE", "DRIFT", "INCIDENT"] });
  if (!data) return <Skeleton rows={10} />;
  return (
    <div className="space-y-4">
      <PageHeader title="Risk" description={data.note} meta={<Pill tone={riskTone(data.global_risk)}>Global risk {data.global_risk}</Pill>} />
      <Panel title="Devices" bodyClass="p-0">
        <ul>{data.devices.map((d: any) => (
          <li key={d.id} className="grid gap-3 border-t border-line px-4 py-3 first:border-0 lg:grid-cols-[150px_310px_minmax(0,1fr)_auto]">
            <div><Link to={`/devices/${d.id}`} className="font-mono text-sm text-info">{d.id}</Link><div className="text-xs capitalize text-muted">{d.kind}{d.quarantined ? " · quarantined" : ""}</div></div>
            <div className="space-y-1">
              <Meter label="Risk" value={d.score} tone={riskTone(d.score)} />
              <Meter label="Trust" value={d.trust} tone={d.trust >= 80 ? "ok" : d.trust >= 50 ? "warn" : "crit"} />
              <Meter label="Identity" value={d.identity} tone={confidenceTone(d.identity)} />
            </div>
            <ul className="space-y-0.5 text-xs">{[...d.factors].sort((a: any, b: any) => b.points - a.points).slice(0, 4).map((f: any) => (
              <li key={f.key}><span className="inline-block w-8 text-right font-mono text-high">{f.points > 0 ? "+" : ""}{f.points}</span> {f.label} <span className="text-muted">· {f.evidence}</span></li>
            ))}</ul>
            <div className="flex items-start gap-2"><Pill value={d.level} /><WhyButton path={`/api/explain/risk/device/${d.id}`} /></div>
          </li>
        ))}</ul>
      </Panel>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Users" bodyClass="p-0">
          <table className="w-full text-left text-sm"><tbody>{data.users.map((u: any) => (
            <tr key={u.id} className="border-t border-line first:border-0"><td className="px-4 py-2"><Link to={`/identity/${u.id}`} className="text-info">{u.name}</Link></td><td><RiskBar score={u.score} level={u.level} /></td>
              <td className="text-xs text-muted">{u.factors.map((f: any) => f.label).join(", ") || "no factors"}</td><td className="px-3"><WhyButton path={`/api/explain/risk/user/${u.id}`} /></td></tr>
          ))}</tbody></table>
        </Panel>
        <Panel title="Rules (prototype, configurable)">
          <ul className="space-y-1 text-sm">{data.levels.map((l: any) => <li key={l.level} className="flex justify-between"><Pill value={l.level} /><span className="font-mono">≥ {l.min}</span></li>)}</ul>
          <h3 className="mt-4 text-xs font-medium text-muted">Trust decay</h3>
          <ul className="mt-1 grid grid-cols-2 gap-1 font-mono text-xs">{Object.entries(data.trust_rules).map(([k, v]) => <li key={k}>{k}: {String(v)}</li>)}</ul>
        </Panel>
      </div>
    </div>
  );
}
