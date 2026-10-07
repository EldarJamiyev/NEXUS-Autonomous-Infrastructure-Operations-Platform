"""Behavioural tests for the NEXUS engines. Each test asserts an observable outcome."""

from __future__ import annotations

from datetime import timedelta

import pytest
from conftest import chaos, process
from sqlalchemy import select

from nexus.models import (
    Alert,
    ConfigItem,
    Device,
    DriftEvent,
    FirewallRule,
    Incident,
    Lease,
    RemediationTransaction,
    RiskScore,
    Service,
    StateSnapshot,
)


def test_policy_set_compiles_and_reports_shadowed_hr_rule(ctx):
    from nexus.policy.compiler import compile_policy_set

    with ctx.session() as db:
        r = compile_policy_set(ctx, db)
    assert r["ok"] is True
    assert {s["rule"] for s in r["shadowed"]} == {"FW-POL-HR-D1"}
    assert r["shadowed"][0]["shadowed_by"] == "FW-130"
    assert any("lockout protection" in m for st in r["stages"] for m in st["messages"])


def test_policy_conflict_blocks_unsafe_draft(ctx):
    from nexus.chaos.scenarios import POLICY_CONFLICT_YAML
    from nexus.policy.compiler import compile_policy_set

    with ctx.session() as db:
        r = compile_policy_set(ctx, db, overrides={"POL-HR-EMERGENCY": POLICY_CONFLICT_YAML})
    assert r["ok"] is False
    assert any(c["kind"] == "BASELINE_CONSTRAINT" and c["blocking"] for c in r["conflicts"])


def test_policy_schema_rejects_typos():
    from nexus.policy.schema import PolicyValidationError, parse_policy

    bad = "apiVersion: nexus.omnis/v1\nkind: AccessPolicy\nmetadata: {id: POL-X, name: x}\nspec:\n  subjects: {groups: [GG-IT]}\n  grnts: []\n"
    with pytest.raises(PolicyValidationError) as exc:
        parse_policy(bad)
    assert "grnts" in str(exc.value)


def test_admin_access_allowed_and_explained(ctx):
    from nexus.policy.evaluator import evaluate_access

    with ctx.session() as db:
        r = evaluate_access(ctx, db, "eldar", "PC-023", "LINUX01", 22)
    assert r["decision"] == "ALLOW"
    assert r["policy"] == "POL-IT-ADMIN"
    assert "Eldar Jamiyev can access LINUX01:22" in r["narrative"]


def test_finance_explicit_deny(ctx):
    from nexus.policy.evaluator import evaluate_access

    with ctx.session() as db:
        r = evaluate_access(ctx, db, "aysel", "PC-024", "LINUX01", 22)
    assert r["decision"] == "DENY"
    assert any(c["check"] == "Explicit deny" for c in r["checks"])


def test_access_requires_authenticated_session(ctx):
    from nexus.policy.evaluator import evaluate_access

    with ctx.session() as db:
        r = evaluate_access(ctx, db, "murad", "PC-023", "LINUX01", 22)
    assert r["decision"] == "DENY" and "not authenticated" in r["summary"]


def test_temporal_policy_requires_approval_after_hours(ctx):
    from nexus.policy.evaluator import evaluate_access

    site = ctx.clock.site_now()
    days_to_monday = (7 - site.weekday()) % 7
    ctx.clock.set_time((site + timedelta(days=days_to_monday)).replace(hour=21, minute=0))
    with ctx.session() as db:
        r = evaluate_access(ctx, db, "eldar", "PC-023", "APP01", 22)
    ctx.clock.reset()
    assert r["decision"] == "APPROVAL_REQUIRED"
    assert "outside" in r["schedule"]


def test_identity_confidence_known_vs_unknown(ctx):
    with ctx.session() as db:
        assert db.get(Device, "PC-023").identity_level == "TRUSTED"
        assert db.get(Device, "PFSENSE").identity_confidence == 100  # AD object not applicable to appliances
        ctx.world.attach_endpoint(db, "02:00:00:00:00:01", "Gi1/0/16", None, "ROGUE", vendor="test")
    with ctx.session() as db:
        dev = db.scalar(select(Device).where(Device.kind == "unknown"))
        assert dev.identity_confidence < 40 and dev.identity_level == "UNKNOWN"


def test_risk_is_a_deterministic_sum_of_explained_factors(ctx):
    from nexus.risk.engine import _score_row, device_factors, recompute_device

    with ctx.session() as db:
        dev = db.get(Device, "LINUX01")
        row = recompute_device(ctx, db, dev, "test", evaluate_policy=False)
        factors = device_factors(ctx, db, dev, _score_row(ctx, db, "device", dev.id))
        assert factors == device_factors(ctx, db, dev, row)
        assert row.score == max(0, min(100, sum(f["points"] for f in factors)))
        assert all(f["evidence"] for f in factors)


def test_lease_creates_verified_firewall_rule(ctx):
    from nexus.leases.engine import request_access

    with ctx.session() as db:
        out = request_access(ctx, db, user_id="eldar", device_id="PC-023", destination="MON01", port=22, requested_by="eldar")
        if out["decision"] == "APPROVAL_REQUIRED":
            pytest.skip("outside business hours at test time")
        lease = db.get(Lease, out["lease"]["id"])
        assert lease.status == "ACTIVE" and lease.firewall_state == "APPLIED"
        assert db.get(FirewallRule, lease.firewall_rule_id) is not None


def test_lease_expiry_removes_firewall_rule(ctx):
    from nexus.leases.engine import expire_leases

    with ctx.session() as db:
        lease = db.scalar(select(Lease).where(Lease.status == "ACTIVE"))
        rule_id = lease.firewall_rule_id
    ctx.clock.shift(timedelta(hours=3))
    with ctx.session() as db:
        expired = expire_leases(ctx, db)
    ctx.clock.reset()
    with ctx.session() as db:
        assert lease.id in expired
        assert db.get(Lease, lease.id).status == "EXPIRED"
        assert db.get(FirewallRule, rule_id) is None


def test_lease_revoked_when_session_ends(ctx):
    with ctx.session() as db:
        ctx.world.logoff(db, "eldar", "PC-023")
    with ctx.session() as db:
        assert db.get(Lease, "LEASE-99182").status == "REVOKED"
        assert "session" in db.get(Lease, "LEASE-99182").end_reason


def test_firewall_outage_reports_pending_never_success(ctx):
    from nexus.leases.engine import request_access

    ctx.runtime.firewall_available = False
    with ctx.session() as db:
        out = request_access(ctx, db, user_id="murad", device_id="PC-025", destination="LINUX01", port=22, requested_by="murad")
    ctx.runtime.firewall_available = True
    assert out["decision"] == "BLOCKED"
    assert out["lease"] is None


def test_unknown_device_is_quarantined_and_isolated(ctx):
    chaos(ctx, "unknown-device")
    process(ctx)
    with ctx.session() as db:
        dev = db.scalar(select(Device).where(Device.kind == "unknown"))
        assert dev.quarantined and dev.vlan_id == 99
        tx = db.scalar(select(RemediationTransaction).where(RemediationTransaction.target == dev.id))
        assert tx.action_id == "REM-NET-QUARANTINE" and tx.status == "COMMITTED"
        assert any(v["probe"] == "policy test" and "DENY" in v["detail"] for v in tx.verification)
        inc = db.scalar(select(Incident).where(Incident.target == dev.id))
        assert inc.title == "Identityless device attempted administrative access" and inc.status == "MITIGATED"


def test_dhcp_conflict_claimant_is_quarantined(ctx):
    chaos(ctx, "dhcp-conflict")
    process(ctx)
    with ctx.session() as db:
        claimant = db.scalar(select(Device).where(Device.kind == "unknown"))
        assert claimant.quarantined
        assert db.get(Device, "PC-024").quarantined is False


def test_ssh_drift_detected_with_checksums_and_diff(ctx):
    from nexus.drift.engine import scan

    chaos(ctx, "break-ssh-config")
    with ctx.session() as db:
        result = scan(ctx, db, {"LINUX01"})
        drift = db.scalar(select(DriftEvent).where(DriftEvent.id.in_(result["new"]), DriftEvent.key == "permit_root_login"))
        assert drift.classification == "SECURITY"
        assert drift.desired_checksum != drift.actual_checksum
        assert "+PermitRootLogin no" in drift.diff and "-PermitRootLogin yes" in drift.diff


def test_ssh_drift_remediated_and_verified(ctx):
    from nexus.drift.engine import config_matches

    chaos(ctx, "break-ssh-config")
    process(ctx)
    with ctx.session() as db:
        assert config_matches(ctx, db, "LINUX01", "ssh")[0]
        tx = db.scalars(select(RemediationTransaction).where(RemediationTransaction.action_id == "REM-CFG-RESTORE-SSH")
                        .order_by(RemediationTransaction.created_at.desc())).first()
        assert tx.status == "COMMITTED" and tx.rollback_available


def test_failed_verification_triggers_rollback_despite_exit_zero(ctx):
    chaos(ctx, "fail-remediation")
    process(ctx)
    with ctx.session() as db:
        txs = db.scalars(select(RemediationTransaction).where(RemediationTransaction.action_id == "REM-CFG-RESTORE-NGINX")
                         .order_by(RemediationTransaction.created_at.desc())).all()
        tx = next(t for t in txs if t.status == "ROLLED_BACK")
        assert all(c["exit_code"] == 0 for c in tx.commands if not c.get("rollback"))
        assert tx.rollback_status == "COMPLETED" and tx.human_action == "REQUIRED"
        retry = txs[0]  # after a failure, confidence drops below the threshold: the next attempt waits for a human
        assert retry.status == "AWAITING_APPROVAL" and retry.automation_confidence < 80
        item = db.get(ConfigItem, "LINUX01:nginx")
        assert item.checksum == tx.backup["config"]["checksum"]
        assert db.get(Incident, tx.incident_id).human_required


def test_dns_alert_storm_becomes_one_incident_with_dns_root_cause(ctx):
    chaos(ctx, "break-dns")
    from nexus.monitoring.detector import scan

    with ctx.session() as db:
        scan(ctx, db)
        ctx.world.tick(db)
        ctx.world.tick(db)
        ctx.world.tick(db)
    with ctx.session() as db:
        scan(ctx, db)
        incs = db.scalars(select(Incident).where(Incident.status.in_(("OPEN", "INVESTIGATING")), Incident.root_cause_entity == "dns@DC01")).all()
        assert len(incs) == 1
        names = {a.name for a in db.scalars(select(Alert).where(Alert.incident_id == incs[0].id))}
        assert {"DNSServiceDown", "PortalHealthCheckFailed"} <= names
        assert incs[0].root_cause_confidence == "HIGH" and incs[0].priority == "P1"


def test_root_cause_identifies_config_change(ctx):
    chaos(ctx, "fail-remediation")
    from nexus.monitoring.detector import scan

    with ctx.session() as db:
        scan(ctx, db)
        inc = db.scalars(select(Incident).where(Incident.target == "LINUX01").order_by(Incident.created_at.desc())).first()
        assert inc.root_cause_kind == "config_change"
        assert any("configuration changed by deploy-bot" in e for e in inc.evidence)


def test_recurring_failure_is_flagged_without_claiming_a_root_cause(ctx):
    chaos(ctx, "kill-nginx")
    process(ctx)
    with ctx.session() as db:
        inc = db.scalars(select(Incident).where(Incident.title.like("Nginx%")).order_by(Incident.created_at.desc())).first()
        assert inc.recurring["occurrences"] >= 4
        assert "not a root cause" in inc.recurring["note"]


def test_whatif_vlan30_is_read_only(ctx):
    from nexus.timemachine.snapshots import capture
    from nexus.whatif.engine import simulate

    with ctx.session() as db:
        before = capture(ctx, db)
        r = simulate(ctx, db, "vlan_down", {"vlan": 30})
        after = capture(ctx, db)
    assert r["impact"]["counts"]["devices"] == 3 and r["impact"]["counts"]["users"] == 3 and r["impact"]["counts"]["leases"] == 2
    assert before == after and r["read_only"]


def test_recovery_order_respects_dependencies(ctx):
    from nexus.dependencies.graph import recovery_order

    with ctx.session() as db:
        order = [x["service"] for x in recovery_order(db, ["portal@APP01", "ad-ds@DC01", "dns@DC01", "postgresql@APP01", "docker@APP01"])]
    assert order.index("dns@DC01") < order.index("ad-ds@DC01") < order.index("portal@APP01")
    assert order.index("docker@APP01") < order.index("postgresql@APP01") < order.index("portal@APP01")


def test_command_allowlist_rejects_injection_and_unapproved_paths(ctx):
    from nexus.remediation.executor import CommandRejected, render

    with ctx.session() as db:
        linux = db.get(Device, "LINUX01")
        assert render("service_restart", linux, {"service": "nginx"}) == ["systemctl", "restart", "nginx"]
        for params in ({"service": "nginx; rm -rf /"}, {"service": "sshd"}):
            with pytest.raises(CommandRejected):
                render("service_restart", linux, params)
        with pytest.raises(CommandRejected):
            render("clean_tmp", linux, {"path": "/etc", "days": 7})
        with pytest.raises(CommandRejected):
            render("bash", linux, {})


def test_duplicate_remediation_is_skipped(ctx):
    from nexus.core.decision import plan_action

    with ctx.session() as db:
        ctx.world.stop_service(db, "nginx@LINUX01", "test")
        first = plan_action(ctx, db, action_id="REM-SVC-RESTART-NGINX", target="LINUX01", trigger="test 1")
        second = plan_action(ctx, db, action_id="REM-SVC-RESTART-NGINX", target="LINUX01", trigger="test 2")
    assert first["outcome"] == "AUTOMATE"
    assert second["outcome"] == "SKIPPED_DUPLICATE"


def test_restart_of_healthy_service_is_blocked(ctx):
    from nexus.core.decision import plan_action

    with ctx.session() as db:
        r = plan_action(ctx, db, action_id="REM-SVC-RESTART-NGINX", target="LINUX01", trigger="test")
    assert r["outcome"] == "BLOCKED" and any("nothing to restart" in x for x in r["reasons"])


def test_event_bus_dispatches_only_after_commit(ctx):
    q = ctx.bus.subscribe(10)
    try:
        with pytest.raises(RuntimeError), ctx.session() as db:
            ctx.bus.emit(db, "TEST_EVENT", "rolled back")
            raise RuntimeError("abort")
        assert q.empty()
        with ctx.session() as db:
            ctx.bus.emit(db, "TEST_EVENT", "committed")
        assert q.get_nowait()["event"]["message"] == "committed"
    finally:
        ctx.bus.unsubscribe(q)


def test_event_bus_queue_is_bounded(ctx):
    q = ctx.bus.subscribe(3)
    try:
        for i in range(6):
            ctx.bus.broadcast({"kind": "metrics", "n": i})
        assert q.qsize() == 3 and q.get_nowait()["n"] == 3
    finally:
        ctx.bus.unsubscribe(q)


def test_time_machine_reconstructs_earlier_state(ctx):
    from nexus.timemachine.snapshots import capture, compare, state_at

    with ctx.session() as db:
        first = db.scalar(select(StateSnapshot).order_by(StateSnapshot.ts))
        past = state_at(db, first.ts + timedelta(seconds=1))
        diff = compare(past["state"], capture(ctx, db))
    assert past["snapshot"]["id"] == first.id
    assert diff["totals"]["leases"] > 0


def test_unauthorized_firewall_rule_rolled_back_with_lockout_protection(ctx):
    chaos(ctx, "add-firewall-rule")
    process(ctx)
    with ctx.session() as db:
        assert not db.scalars(select(FirewallRule).where(FirewallRule.origin == "manual")).all()
        tx = db.scalars(select(RemediationTransaction).where(RemediationTransaction.action_id == "REM-CFG-RESTORE-FIREWALL")
                        .order_by(RemediationTransaction.created_at.desc())).first()
        assert tx.status == "COMMITTED"
        assert any(v["probe"] == "management path" and v["passed"] for v in tx.verification)


def test_maintenance_mode_expected_drift_then_reopened(ctx):
    from nexus.core.store import set_setting
    from nexus.drift.engine import end_maintenance_review, scan

    with ctx.session() as db:
        set_setting(db, "maintenance", {"active": True, "reason": "test"}, ctx.clock.now())
        ctx.world.set_config(db, "APP01", "ssh", {"MaxAuthTries": 6}, actor="admin")
    with ctx.session() as db:
        new = scan(ctx, db, {"APP01"})["new"]
        assert db.get(DriftEvent, new[0]).status == "EXPECTED"
    with ctx.session() as db:
        set_setting(db, "maintenance", {"active": False}, ctx.clock.now())
        assert new[0] in end_maintenance_review(ctx, db)


def test_high_impact_action_requires_approval(ctx):
    with ctx.session() as db:
        tx = db.scalar(select(RemediationTransaction).where(RemediationTransaction.action_id == "REM-CFG-RESTORE-DOCKER"))
        assert tx.status == "AWAITING_APPROVAL" and tx.approval_id


def test_blackout_injections_are_handled(ctx):
    from nexus.chaos.scenarios import BLACKOUT_SEQUENCE

    for scenario in BLACKOUT_SEQUENCE:
        chaos(ctx, scenario)
    process(ctx, rounds=3)
    with ctx.session() as db:
        committed = {t.action_id for t in db.scalars(select(RemediationTransaction).where(RemediationTransaction.status == "COMMITTED"))}
        assert {"REM-SVC-RESTART-DNS", "REM-CFG-RESTORE-FIREWALL", "REM-NET-QUARANTINE", "REM-NET-BLOCK-PORT", "REM-SVC-RESTART-NGINX"} <= committed
        assert db.get(Service, "dns@DC01").status == "running"
        assert all(d.quarantined for d in db.scalars(select(Device).where(Device.kind == "unknown")))


def test_selftest_checks_twelve_components(ctx):
    from nexus.monitoring.selftest import run

    r = run(ctx, route_count=100)
    assert r["total"] == 12
    assert r["healthy"] == 12, [c for c in r["checks"] if c["status"] != "HEALTHY"]


def test_chatops_is_dry_run_without_webhook(ctx):
    from nexus.models import ChatOpsEvent

    with ctx.session() as db:
        msgs = db.scalars(select(ChatOpsEvent)).all()
    assert msgs and all(m.delivery_status == "DRY_RUN" for m in msgs)


def test_risk_scores_exist_for_every_device(ctx):
    with ctx.session() as db:
        ids = {d.id for d in db.scalars(select(Device))}
        scored = {r.entity_id for r in db.scalars(select(RiskScore).where(RiskScore.entity_type == "device"))}
    assert ids <= scored
