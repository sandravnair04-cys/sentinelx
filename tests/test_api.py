"""API endpoint, collection, simulation and report tests."""

from app.collectors import read_sample


def test_health_and_docs(client):
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/openapi.json").status_code == 200


def test_dashboard_statistics(client, auth_headers):
    stats = client.get("/api/dashboard/stats", headers=auth_headers).json()
    assert stats["total_events"] > 0
    assert stats["total_alerts"] > 0
    assert stats["simulated_data"] is True
    activity = client.get("/api/dashboard/activity", headers=auth_headers).json()
    assert "series" in activity and activity["series"]


def test_event_collection_endpoints(client, auth_headers):
    sample = read_sample("windows_security_sample.log")
    result = client.post(
        "/api/collect/windows/text", headers=auth_headers,
        json={"text": sample[:2000], "source_name": "test-windows"}
    )
    assert result.status_code == 200
    assert result.json()["received"] > 0
    linux = client.post(
        "/api/collect/linux/text", headers=auth_headers,
        json={"text": "Nov 19 08:41:03 host sshd[1]: Failed password for invalid user admin from 198.51.100.23 port 1 ssh2"}
    )
    assert linux.json()["inserted"] == 1
    assert client.get("/api/events?limit=5", headers=auth_headers).status_code == 200


def test_simulation_endpoint(client, auth_headers):
    result = client.post(
        "/api/simulation/run", headers=auth_headers,
        json={"scenario": "correlated_attack", "count": 10, "source_ip": "203.0.113.211"}
    )
    assert result.status_code == 200, result.text
    assert result.json()["simulated"] is True
    assert result.json()["events"]["inserted"] > 0


def test_threat_intel_lookup_without_keys(client, auth_headers):
    result = client.post("/api/threat-intel/lookup", headers=auth_headers, json={"indicator": "192.0.2.10"})
    assert result.status_code == 200
    assert result.json()["verdict"] == "unknown"
    assert "not mean clean" in result.json()["details"]["note"]


def test_report_generation_and_download(client, auth_headers):
    incident_id = client.get("/api/incidents", headers=auth_headers).json()["items"][0]["incident_id"]
    generated = client.post(f"/api/reports/generate/{incident_id}", headers=auth_headers)
    assert generated.status_code == 200, generated.text
    assert generated.json()["file_name"].endswith(".pdf")
    download = client.get(f"/api/reports/{incident_id}/download", headers=auth_headers)
    assert download.status_code == 200
    assert download.content[:4] == b"%PDF"


def test_static_ui(client):
    # The built React SPA is the primary dashboard when frontend/dist exists.
    response = client.get("/")
    assert response.status_code == 200
    assert "SENTINELX" in response.text
    assert "/assets/" in response.text
    # The original zero-build dashboard is still available as a fallback.
    legacy = client.get("/static/index.html")
    assert legacy.status_code == 200
    assert "chart.umd.min.js" in legacy.text
