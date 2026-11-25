"""Shared test fixtures.

The environment is configured before importing the application so all tests
use an isolated temporary SQLite database and never touch real log sources.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

TMP_DIR = Path(tempfile.gettempdir()) / "sentinelx-tests"
TMP_DIR.mkdir(parents=True, exist_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{TMP_DIR / 'test.db'}"
os.environ["SEED_DEMO_DATA"] = "false"
os.environ["LLM_API_KEY"] = ""
os.environ["SIMULATION_MODE"] = "true"
os.environ["SECRET_KEY"] = "test-only-secret-key-not-for-production"
os.environ["LOGIN_RATE_LIMIT"] = "100"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Base  # noqa: E402
from app.services.seed import seed_database  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_schema():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def db(fresh_schema):
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def seeded_db(db):
    seed_database(db, demo=True)
    return db


@pytest.fixture
def client(fresh_schema):
    session = SessionLocal()
    try:
        seed_database(session, demo=True)
    finally:
        session.close()
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth_headers(client):
    response = client.post(
        "/api/auth/login", json={"username": "admin", "password": "Admin@123!"}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}


@pytest.fixture
def analyst_headers(client):
    response = client.post(
        "/api/auth/login", json={"username": "analyst", "password": "Analyst@123!"}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}
