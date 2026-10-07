"""nexusctl - command-line client for the NEXUS OMNIS API.

Environment: NEXUS_URL (default http://localhost:8000), NEXUS_API_TOKEN (API key or console token),
NEXUS_USER (demo login user when no token is set; default eldar).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any

import httpx
from rich.console import Console
from rich.table import Table

console = Console()
COLORS = {"CRITICAL": "red", "HIGH": "dark_orange", "MEDIUM": "yellow", "LOW": "green", "P1": "red", "P2": "dark_orange", "P3": "yellow", "P4": "blue",
          "healthy": "green", "warning": "yellow", "critical": "red", "quarantined": "magenta", "ACTIVE": "green", "RESOLVED": "green", "COMMITTED": "green",
          "OPEN": "red", "FAILED": "red", "ROLLED_BACK": "dark_orange", "ALLOW": "green", "DENY": "red", "APPROVAL_REQUIRED": "yellow"}


def c(value: Any) -> str:
    text = str(value)
    color = COLORS.get(text)
    return f"[{color}]{text}[/]" if color else text


class Client:
    def __init__(self) -> None:
        self.base = os.environ.get("NEXUS_URL", "http://localhost:8000").rstrip("/")
        self.http = httpx.Client(base_url=self.base, timeout=30)
        token = os.environ.get("NEXUS_API_TOKEN")
        if not token:
            try:
                r = self.http.post("/api/auth/demo-login", json={"user_id": os.environ.get("NEXUS_USER", "eldar")})
            except httpx.ConnectError:
                console.print(f"[red]Cannot reach NEXUS at {self.base}[/]. Start it with `docker compose up` or `make dev`.")
                sys.exit(2)
            if r.status_code != 200:
                console.print("[red]Demo login is disabled; set NEXUS_API_TOKEN.[/]")
                sys.exit(2)
            token = r.json()["token"]
        self.http.headers["Authorization"] = f"Bearer {token}"

    def call(self, method: str, path: str, **kw: Any) -> Any:
        r = self.http.request(method, path, **kw)
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail")
            except ValueError:
                detail = r.text
            console.print(f"[red]{r.status_code}[/] {detail}")
            sys.exit(1)
        ctype = r.headers.get("content-type", "")
        return r.json() if "json" in ctype else r.text

    def get(self, path: str, **kw: Any) -> Any:
        return self.call("GET", path, **kw)

    def post(self, path: str, **kw: Any) -> Any:
        return self.call("POST", path, **kw)


def table(title: str, columns: list[str], rows: list[list[Any]]) -> None:
    t = Table(title=title, title_justify="left", header_style="bold")
    for col in columns:
        t.add_column(col)
    for row in rows:
        t.add_row(*[c(v) if isinstance(v, str) else str(v) for v in row])
    console.print(t)


def cmd_status(cli: Client, a: argparse.Namespace) -> None:
    s = cli.get("/api/status")
    m = s["mode"]
    console.print(f"[bold]NEXUS OMNIS v{s['version']}[/]  ENVIRONMENT: [cyan]{s['environment']}[/]  SYSTEM MODE: {c(m['mode'])}  "
                  f"AUTONOMY: {s['autonomy']['level']} ({s['autonomy']['name']})")
    for reason in m.get("reasons", []):
        console.print(f"  reason: {reason}")
    k = s["counts"]
    table("State", ["Health", "Global risk", "Devices", "Users", "Sessions", "Leases", "Open incidents", "Drift", "Quarantined", "AutoHeal 24h"],
          [[f"{s['health']['health_percent']}%", s["global_risk"], k["devices"], k["users"], k["active_sessions"], k["active_leases"], k["open_incidents"],
            k["drift_events"], k["quarantined"], k["automated_remediations"]]])


def cmd_devices(cli: Client, a: argparse.Namespace) -> None:
    rows = cli.get("/api/devices")
    table("Devices", ["Device", "Kind", "IP", "VLAN", "Status", "Risk", "Identity"],
          [[d["id"], d["kind"], d["ip"] or "-", d["vlan"], d["status"], f"{d['risk']} {d['risk_level']}", f"{d['identity_confidence']}% {d['identity_level']}"] for d in rows])


def cmd_users(cli: Client, a: argparse.Namespace) -> None:
    rows = cli.get("/api/users")
    table("Users", ["User", "Name", "Groups", "Sessions", "Leases", "Risk"],
          [[u["id"], u["name"], ", ".join(u["groups"]), ", ".join(s["device"] for s in u["sessions"]) or "-", u["active_leases"], u["risk"]] for u in rows])


def cmd_leases(cli: Client, a: argparse.Namespace) -> None:
    rows = cli.get("/api/leases")
    table("Leases", ["Lease", "User", "Source", "Destination", "Status", "Firewall", "Expires"],
          [[x["id"], x["user_id"], f"{x['device_id']} {x['source_ip']}", f"{x['destination']}:{x['port']}", x["status"], x["firewall_state"], x["expires_local"]] for x in rows])


def cmd_risk(cli: Client, a: argparse.Namespace) -> None:
    kind = "user" if a.entity.islower() else "device"
    r = cli.get(f"/api/explain/risk/{kind}/{a.entity}")
    console.print(f"[bold]{a.entity}[/] RISK {c(r['level'])} {r['score']}  TRUST {r['trust']}")
    table("Factors", ["Factor", "Points", "Evidence"], [[f["label"], f["points"], f["evidence"]] for f in r["factors"]])


def cmd_explain(cli: Client, a: argparse.Namespace) -> None:
    r = cli.get("/api/explain/access", params={"user": a.user, "device": a.device, "destination": a.destination, "port": a.port})
    console.print(f"[bold]{r['title']}[/]")
    table("Evaluation", ["Check", "Result", "Detail"], [[x["check"], x["status"], x["detail"]] for x in r["checks"]])
    console.print(f"Decision: {c(r['decision'])}\n{r['narrative']}")


def cmd_drift(cli: Client, a: argparse.Namespace) -> None:
    if a.action == "scan":
        r = cli.post("/api/drift/scan")
        console.print(f"new drift: {r['new'] or 'none'}; cleared: {r['cleared'] or 'none'}; planned remediation: {r['planned'] or 'none'}")
    elif a.action == "remediate":
        r = cli.post(f"/api/drift/{a.id}/remediate")
        console.print(f"decision {r['decision_id']}: {c(r['outcome'])} ({r['confidence']}%) transaction {r.get('transaction_id') or '-'}; " + "; ".join(r["reasons"]))
    rows = cli.get("/api/drift")
    table("Drift", ["ID", "Device", "Key", "Desired", "Actual", "Class", "Status"],
          [[d["id"], d["device_id"], f"{d['component']}.{d['key']}", json.dumps(d["desired"])[:30], json.dumps(d["actual"])[:30], d["classification"], d["status"]] for d in rows[:25]])


def cmd_incidents(cli: Client, a: argparse.Namespace) -> None:
    if a.action == "show":
        console.print(cli.get(f"/api/incidents/{a.id}/report"))
        return
    rows = cli.get("/api/incidents")
    table("Incidents", ["ID", "Priority", "Status", "Title", "Root cause"], [[i["id"], i["priority"], i["status"], i["title"][:48], (i["root_cause"] or "-")[:60]] for i in rows[:30]])


def cmd_policy(cli: Client, a: argparse.Namespace) -> None:
    if a.action == "validate":
        if a.file:
            from pathlib import Path

            r = cli.post("/api/policies/validate", json={"content": Path(a.file).read_text(encoding="utf-8")})
        else:
            r = cli.get("/api/policies/compile")
        for st in r.get("stages", []):
            console.print(f"{c('LOW') if st['status'] == 'passed' else c('MEDIUM') if st['status'] == 'warning' else c('CRITICAL')} {st['name']}: {'; '.join(st['messages'])[:200]}")
        console.print(f"Result: {'[green]VALID[/]' if r.get('ok') else '[red]INVALID[/]'}")
    elif a.action == "diff":
        diffs = cli.get("/api/policies/diff")
        console.print("\n".join(d["diff"] for d in diffs) or "Active policies match the files on disk.")
    elif a.action == "apply":
        console.print(cli.post("/api/policies/apply"))
    elif a.action == "rollback":
        console.print(cli.post(f"/api/policies/{a.file}/rollback"))


def cmd_network(cli: Client, a: argparse.Namespace) -> None:
    r = cli.post("/api/snapshots", json={"label": a.label})
    console.print(f"Snapshot {r['id']} at {r['ts']} sha256 {r['checksum'][:16]}")


def cmd_whatif(cli: Client, a: argparse.Namespace) -> None:
    if not a.scenario:
        table("What-if scenarios", ["Scenario", "Question", "Params"], [[s["id"], s["question"], ", ".join(s["params"])] for s in cli.get("/api/whatif/scenarios")])
        return
    params = dict(p.split("=", 1) for p in a.params)
    r = cli.post("/api/whatif", json={"scenario": a.scenario, "params": params})
    imp = r["impact"]
    console.print(f"[bold]{r['question']}[/] - {r['change']} (read-only simulation)")
    console.print(f"Devices {imp['counts']['devices']}, services {imp['counts']['services']}, users {imp['counts']['users']} ({', '.join(imp['user_names'])}), "
                  f"leases {imp['counts']['leases']}; expected priority {c(r['expected']['priority'])}, mode {r['expected']['system_mode']}")
    for step in r["propagation"][:15]:
        console.print(f"  -> {step['entity']}: {step['reason']}")
    if r["recovery_order"]:
        table("Suggested recovery order", ["#", "Service", "Why"], [[x["order"], x["service"], x["reason"]] for x in r["recovery_order"]])


def cmd_chaos(cli: Client, a: argparse.Namespace) -> None:
    if a.action == "list":
        table("Chaos scenarios", ["Scenario", "Title", "Category"], [[s["id"], s["title"], s["category"]] for s in cli.get("/api/chaos/scenarios")])
        return
    run = cli.post(f"/api/chaos/{a.scenario}")["run"]
    console.print(f"Injected [bold]{a.scenario}[/] as {run}; watching NEXUS...")
    seen: set[str] = set()
    for _ in range(120):
        v = cli.get(f"/api/chaos/runs/{run}")
        for name, st in v["stages"].items():
            if st["done"] and name not in seen:
                seen.add(name)
                console.print(f"  [green]OK[/] {name.upper():<13} {st['detail'][:110]}")
        if v["status"] in ("COMPLETED", "HUMAN_REQUIRED"):
            console.print(f"Final: {c(v['status'])}" + (f" (detected in {v['detection_seconds']} s)" if v["detection_seconds"] is not None else ""))
            return
        time.sleep(1)


def cmd_demo(cli: Client, a: argparse.Namespace) -> None:
    if a.action == "reset":
        console.print(cli.post("/api/demo/reset"))
        return
    if a.action == "blackout":
        run = cli.post("/api/demo/blackout")["run"]
        console.print(f"[bold red]FULL INFRASTRUCTURE BLACKOUT[/] drill {run} started")
        for _ in range(240):
            v = cli.get(f"/api/chaos/runs/{run}")
            if v["status"] == "COMPLETED" and v.get("report_id"):
                console.print(cli.get(f"/api/reports/{v['report_id']}?format=md"))
                return
            time.sleep(1)
        console.print("[yellow]Blackout still settling; check the Chaos Lab page.[/]")
        return
    state = cli.post("/api/demo/start")
    last = 0
    console.print("[bold]NEXUS GUIDED DEMO[/] - 20 scenes")
    for _ in range(400):
        state = cli.get("/api/demo/state")
        cur = state.get("current")
        if cur and cur["number"] != last:
            last = cur["number"]
            console.print(f"[magenta]STEP {cur['step']:02d}[/] {cur['step_title'].upper():<24} Scene {cur['number']:02d}: [bold]{cur['title']}[/]\n            {cur['narrative']}")
        if state["status"] in ("finished", "failed", "idle"):
            break
        time.sleep(0.5)
    console.print(f"Demo {state['status']} in {state['elapsed']} s" + (f" - report {state['report_id']}" if state.get("report_id") else ""))


def cmd_selftest(cli: Client, a: argparse.Namespace) -> None:
    r = cli.get("/api/system/selftest")
    table(f"NEXUS SELF TEST - {r['summary']}", ["Component", "Status", "Detail"], [[x["component"], x["status"], x["detail"]] for x in r["checks"]])


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="nexusctl", description="NEXUS OMNIS command-line client")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    sub.add_parser("selftest")
    for name in ("devices", "users", "leases"):
        sp = sub.add_parser(name)
        sp.add_argument("action", nargs="?", default="list", choices=["list"])
    sp = sub.add_parser("risk")
    sp.add_argument("entity")
    sp = sub.add_parser("explain")
    sp.add_argument("what", choices=["access"])
    sp.add_argument("user")
    sp.add_argument("device")
    sp.add_argument("destination")
    sp.add_argument("port", type=int)
    sp = sub.add_parser("drift")
    sp.add_argument("action", choices=["scan", "remediate", "list"], nargs="?", default="list")
    sp.add_argument("id", nargs="?")
    sp = sub.add_parser("incidents")
    sp.add_argument("action", choices=["list", "show"], nargs="?", default="list")
    sp.add_argument("id", nargs="?")
    sp = sub.add_parser("policy")
    sp.add_argument("action", choices=["validate", "diff", "apply", "rollback"])
    sp.add_argument("file", nargs="?", help="policy file (validate) or policy id (rollback)")
    sp = sub.add_parser("network")
    sp.add_argument("action", choices=["snapshot"])
    sp.add_argument("--label", default="nexusctl snapshot")
    sp = sub.add_parser("whatif")
    sp.add_argument("scenario", nargs="?")
    sp.add_argument("params", nargs="*", help="key=value, e.g. vlan=30")
    sp = sub.add_parser("chaos")
    sp.add_argument("action", choices=["list", "run"])
    sp.add_argument("scenario", nargs="?")
    sp = sub.add_parser("demo")
    sp.add_argument("action", nargs="?", default="start", choices=["start", "blackout", "reset"])
    a = p.parse_args(argv)
    handlers = {"status": cmd_status, "devices": cmd_devices, "users": cmd_users, "leases": cmd_leases, "risk": cmd_risk, "explain": cmd_explain,
                "drift": cmd_drift, "incidents": cmd_incidents, "policy": cmd_policy, "network": cmd_network, "whatif": cmd_whatif, "chaos": cmd_chaos,
                "demo": cmd_demo, "selftest": cmd_selftest}
    handlers[a.cmd](Client(), a)


if __name__ == "__main__":
    main()
