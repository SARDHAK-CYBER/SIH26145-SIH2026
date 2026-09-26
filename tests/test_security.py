"""API-key middleware: closed without a key, open /health + preflight, header/bearer/query accepted, constant-time compare."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src import security

KEY = "k" * 32


def _app(key):
    app = FastAPI()

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.get("/secret")
    def secret():
        return {"secret": 1}

    app.add_middleware(security.ApiKeyMiddleware, key=key)
    return TestClient(app)


def test_no_key_configured_leaves_api_open():
    assert _app(None).get("/secret").status_code == 200


def test_missing_and_wrong_key_rejected():
    c = _app(KEY)
    assert c.get("/secret").status_code == 401
    assert c.get("/secret", headers={"X-API-Key": "x" * 32}).status_code == 401
    assert c.get("/secret?api_key=nope").status_code == 401
    assert c.get("/secret", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_key_accepted_via_header_bearer_and_query():
    c = _app(KEY)
    assert c.get("/secret", headers={"X-API-Key": KEY}).status_code == 200
    assert c.get("/secret", headers={"Authorization": f"Bearer {KEY}"}).status_code == 200
    assert c.get(f"/secret?api_key={KEY}").status_code == 200


def test_health_and_preflight_stay_open():
    c = _app(KEY)
    assert c.get("/health").status_code == 200
    assert c.options("/secret").status_code != 401


def test_bind_guard(monkeypatch):
    monkeypatch.delenv("STEALTHTAP_API_KEY", raising=False)
    security.require_key_for_bind("127.0.0.1")
    security.require_key_for_bind("::1")
    with pytest.raises(SystemExit):
        security.require_key_for_bind("0.0.0.0")
    monkeypatch.setenv("STEALTHTAP_API_KEY", "short")
    with pytest.raises(SystemExit):
        security.require_key_for_bind("127.0.0.1")
    monkeypatch.setenv("STEALTHTAP_API_KEY", KEY)
    security.require_key_for_bind("0.0.0.0")


def test_real_apps_are_protected(monkeypatch):
    monkeypatch.setenv("STEALTHTAP_API_KEY", KEY)
    from src.api.live_capture import build_app
    c = TestClient(build_app())
    assert c.get("/capture/status").status_code == 401
    assert c.get("/health").status_code == 200
    assert c.get("/capture/status", headers={"X-API-Key": KEY}).status_code == 200
    # a 401 must still carry CORS headers so the browser dashboard can read it and prompt for the key
    r = c.get("/capture/status", headers={"Origin": "http://localhost:4173"})
    assert r.status_code == 401 and r.headers.get("access-control-allow-origin")
