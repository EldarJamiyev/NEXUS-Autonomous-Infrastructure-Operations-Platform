"""API tests: authentication, server-side RBAC, validation, rate limiting and webhook safety."""

from __future__ import annotations

from conftest import token


def test_health_and_version(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["database"] == "healthy" and body["version"] == "0.1.0" and body["environment"] == "SIMULATION"


def test_api_requires_authentication(client):
    assert client.get("/api/status").status_code == 401


def test_status_overview_and_inventory(client):
    h = token(client)
    status = client.get("/api/status", headers=h).json()
    assert status["counts"]["devices"] == 9 and status["environment"] == "SIMULATION"
    for path in ("/api/overview", "/api/devices/LINUX01", "/api/network", "/api/identity", "/api/risk", "/api/incidents", "/api/drift",
                 "/api/remediations", "/api/policies", "/api/timemachine/timeline", "/api/chaos/scenarios", "/api/operations/morning-brief"):
        assert client.get(path, headers=h).status_code == 200, path


def test_rbac_is_enforced_by_the_backend(client):
    viewer = token(client, "aysel")
    assert client.post("/api/chaos/kill-nginx", headers=viewer).status_code == 403
    assert client.put("/api/system/autonomy", headers=viewer, json={"level": 5}).status_code == 403
    engineer = token(client, "murad")
    assert client.put("/api/system/autonomy", headers=engineer, json={"level": 5}).status_code == 403
    assert client.put("/api/system/autonomy", headers=token(client), json={"level": 3}).status_code == 200


def test_input_validation(client):
    h = token(client)
    r = client.post("/api/access/request", headers=h, json={"user_id": "eldar", "device_id": "PC-023", "destination": "LINUX01", "port": 70000})
    assert r.status_code == 422
    assert client.get("/api/incidents/INC-9999", headers=h).status_code == 404


def test_users_cannot_request_access_for_others(client):
    viewer = token(client, "aysel")
    r = client.post("/api/access/request", headers=viewer, json={"user_id": "eldar", "device_id": "PC-023", "destination": "LINUX01", "port": 22})
    assert r.status_code == 403


def test_alertmanager_alert_is_validated_against_state(client):
    payload = {"version": "4", "status": "firing", "alerts": [{"status": "firing", "labels": {"alertname": "NginxDown", "device": "LINUX01",
                                                                                               "service": "nginx", "severity": "critical"},
                                                                "annotations": {"summary": "rm -rf / ; nginx down"}}]}
    r = client.post("/api/alerts/alertmanager", json=payload)
    assert r.status_code == 200
    accepted = r.json()["accepted"][0]
    assert accepted["status"] == "STALE" and accepted["validated"] is False and accepted["incident"] is None


def test_rate_limit_on_sensitive_endpoints(client, ctx):
    from nexus.api.deps import RateLimiter

    ctx.limiter = RateLimiter(2)
    h = token(client)
    codes = [client.post("/api/drift/scan", headers=h).status_code for _ in range(3)]
    assert codes[:2] == [200, 200] and codes[2] == 429


def test_explain_access_endpoint(client):
    h = token(client)
    r = client.get("/api/explain/access", headers=h, params={"user": "eldar", "device": "PC-023", "destination": "LINUX01", "port": 22}).json()
    assert r["decision"] == "ALLOW" and r["policy"] == "POL-IT-ADMIN" and r["lease"]["id"] == "LEASE-99182"


def test_incident_report_markdown_and_html(client):
    h = token(client)
    inc = client.get("/api/incidents", headers=h).json()[-1]["id"]
    md = client.get(f"/api/incidents/{inc}/report", headers=h)
    assert md.status_code == 200 and md.text.startswith(f"# {inc}") and "## Root cause" in md.text
    html = client.get(f"/api/incidents/{inc}/report?format=html", headers=h)
    assert "<h2>Timeline</h2>" in html.text


def test_policy_validate_endpoint_reports_errors(client):
    h = token(client)
    r = client.post("/api/policies/validate", headers=h, json={"content": "kind: AccessPolicy\nmetadata: {id: X}\n"}).json()
    assert r["ok"] is False and r["errors"]


def test_copilot_is_read_only_and_deterministic(client):
    h = token(client)
    r = client.post("/api/copilot/ask", headers=h, json={"question": "Why can't Aysel access port 22?"}).json()
    assert r["read_only"] is True and "POL-FINANCE" in r["answer"] and "no LLM" in r["engine"]
