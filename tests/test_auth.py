"""Authentication and RBAC tests."""

from app.security import hash_password, verify_password


def test_password_hashing():
    hashed = hash_password("CorrectHorse9!")
    assert hashed != "CorrectHorse9!"
    assert verify_password("CorrectHorse9!", hashed)
    assert not verify_password("wrong", hashed)


def test_login_success_and_failure(client):
    ok = client.post("/api/auth/login", json={"username": "analyst", "password": "Analyst@123!"})
    assert ok.status_code == 200
    assert ok.json()["role"] == "analyst"
    bad = client.post("/api/auth/login", json={"username": "analyst", "password": "wrong-password"})
    assert bad.status_code == 401


def test_protected_endpoints_require_token(client):
    assert client.get("/api/dashboard/stats").status_code == 401
    assert client.get("/api/events").status_code == 401


def test_analyst_cannot_access_admin_endpoints(client, analyst_headers):
    assert client.get("/api/users", headers=analyst_headers).status_code == 403
    assert client.get("/api/audit", headers=analyst_headers).status_code == 403


def test_registration_requires_admin(client, analyst_headers, auth_headers):
    payload = {
        "email": "new.analyst@sentinelx.io", "username": "new.analyst",
        "full_name": "New Analyst", "password": "Str0ngPass!", "role": "analyst"
    }
    assert client.post("/api/auth/register", json=payload, headers=analyst_headers).status_code == 403
    created = client.post("/api/auth/register", json=payload, headers=auth_headers)
    assert created.status_code == 201
    assert created.json()["role"] == "analyst"


def test_me_endpoint(client, auth_headers):
    response = client.get("/api/auth/me", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["username"] == "admin"
