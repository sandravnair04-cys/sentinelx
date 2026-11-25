"""Risk scoring tests."""

from app.risk.scoring import score_risk


def test_low_risk():
    result = score_risk(alerts=[], events=[{"username": "alice", "host": "WS1"}])
    assert result["score"] >= 0
    assert result["severity"] == "LOW"
    assert result["model_version"] == "deterministic-v1"


def test_critical_risk_with_factors():
    alerts = [
        {"severity": "CRITICAL", "confidence": 0.95, "title": "Success after failures",
         "mitre": ["T1110", "T1078", "T1098"]}
    ]
    events = [
        {"username": "administrator", "host": "SRV1", "source_ip": "203.0.113.77"}
        for _ in range(20)
    ] + [{"username": "administrator", "host": "SRV2", "source_ip": "203.0.113.77"}]
    result = score_risk(
        alerts=alerts, events=events,
        intel=[{"indicator": "203.0.113.77", "verdict": "malicious"}],
        context={"username": "administrator", "success_after_failures": True},
    )
    assert result["score"] == 100
    assert result["severity"] == "CRITICAL"
    factor_names = {f["factor"] for f in result["factors"]}
    assert "Privileged account involved" in factor_names
    assert "Threat intelligence match" in factor_names
    assert "Multiple affected systems" in factor_names
    assert len(result["recommendations"]) >= 3


def test_score_is_reproducible():
    context = {"alerts": [{"severity": "HIGH", "confidence": 0.8}],
               "events": [{"username": "bob"}] * 5}
    a = score_risk(**context)
    b = score_risk(**context)
    assert a["score"] == b["score"]
    assert a["factors"] == b["factors"]
