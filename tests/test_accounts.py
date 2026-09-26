"""Users, login tokens, roles, throttling, audit log, per-tenant limits -- through the real ASGI middleware."""
import json
import logging
import os
import time

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src import accounts, security
from src.api.auth import router as auth_router

KEY = "k" * 32
SECRET = "s" * 40


def build_app():
    app = FastAPI()
    app.include_router(auth_router)

    @app.get("/health")
    def h():
        return {"ok": 1}

    @app.get("/alerts")
    def alerts(request: Request):
        return {"tenant": request.state.tenant, "role": request.state.role}

    @app.post("/analyze/pcap")
    def analyze():
        return {"analysed": 1}

    @app.post("/alerts/ingest")
    def ingest():
        return {"stored": 1}

    @app.post("/capture/start")
    def start():
        return {"started": 1}

    app.add_middleware(security.ApiKeyMiddleware)
    return app


@pytest.fixture()
def env(tmp_path, monkeypatch):
    users_file = tmp_path / "users.json"
    users_file.write_text(json.dumps({"users": [
        {"name": "vera", "role": "viewer", "tenant": "acme", "password_hash": accounts.hash_password("viewer-password-1")},
        {"name": "ann", "role": "analyst", "tenant": "acme", "password_hash": accounts.hash_password("analyst-password-1")},
        {"name": "root", "role": "admin", "tenant": "acme", "password_hash": accounts.hash_password("admin-password-123")}]}))
    monkeypatch.setenv("STEALTHTAP_USERS", str(users_file))
    monkeypatch.setenv("STEALTHTAP_TOKEN_SECRET", SECRET)
    monkeypatch.setenv("STEALTHTAP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("STEALTHTAP_API_KEY", KEY)
    monkeypatch.setenv("STEALTHTAP_TENANT_KEYS", f"plant7/sensor={'p' * 20},globex/viewer={'g' * 20}")
    monkeypatch.setattr(accounts, "_users", None)
    monkeypatch.setattr(accounts, "_secret", None)
    monkeypatch.setattr(accounts, "_audit_logger", None)
    monkeypatch.setattr(accounts, "throttle", accounts.LoginThrottle())
    logging.getLogger("stealthtap.audit").handlers.clear()
    return TestClient(build_app()), tmp_path


def login(c, u, p):
    return c.post("/auth/login", json={"username": u, "password": p})


def test_password_hash_is_salted_and_verifies():
    a, b = accounts.hash_password("correct horse battery"), accounts.hash_password("correct horse battery")
    assert a != b and a.startswith("scrypt$")
    assert accounts.verify_password("correct horse battery", a) and not accounts.verify_password("wrong", a)
    assert not accounts.verify_password("anything", None)                      # unknown user never verifies


def test_login_token_roles_and_tenant(env):
    c, _ = env
    assert c.get("/alerts").status_code == 401
    tok = login(c, "vera", "viewer-password-1").json()
    assert tok["role"] == "viewer" and tok["tenant"] == "acme"
    H = {"X-API-Key": tok["token"]}
    assert c.get("/alerts", headers=H).json() == {"tenant": "acme", "role": "viewer"}
    assert c.post("/analyze/pcap", headers=H).status_code == 403                # viewer cannot upload
    ann = {"X-API-Key": login(c, "ann", "analyst-password-1").json()["token"]}
    assert c.post("/analyze/pcap", headers=ann).status_code == 200
    assert c.post("/capture/start", headers=ann).status_code == 403             # analyst cannot control capture
    adm = {"Authorization": "Bearer " + login(c, "root", "admin-password-123").json()["token"]}
    assert c.post("/capture/start", headers=adm).status_code == 200
    assert c.get("/auth/me", headers=adm).json()["user"] == "root"


def test_api_keys_carry_roles(env):
    c, _ = env
    assert c.get("/alerts", headers={"X-API-Key": KEY}).json()["role"] == "admin"
    sensor = {"X-API-Key": "p" * 20}
    assert c.post("/alerts/ingest", headers=sensor).status_code == 200
    assert c.get("/alerts", headers=sensor).status_code == 403                  # a sensor key cannot read alerts
    assert c.post("/capture/start", headers=sensor).status_code == 403
    v = {"X-API-Key": "g" * 20}
    assert c.get("/alerts", headers=v).json() == {"tenant": "globex", "role": "viewer"}
    assert c.post("/alerts/ingest", headers=v).status_code == 403


def test_wrong_password_unknown_user_and_lockout(env):
    c, _ = env
    assert login(c, "vera", "nope").status_code == 401
    assert login(c, "ghost", "nope").status_code == 401
    for _ in range(4):
        login(c, "vera", "nope")
    assert login(c, "vera", "viewer-password-1").status_code == 429            # locked even with the right password
    assert login(c, "ann", "analyst-password-1").status_code == 200            # other accounts unaffected


def test_tokens_expire_tamper_and_revocation(env):
    c, tmp = env
    t = login(c, "ann", "analyst-password-1").json()["token"]

    def ok(tok):
        return c.get("/alerts", headers={"X-API-Key": tok}).status_code
    assert ok(t) == 200
    assert ok(t[:-3] + ("AAA" if not t.endswith("AAA") else "BBB")) == 401     # tampered signature
    forged = "st1." + accounts._b64(json.dumps({"u": "ann", "r": "admin", "t": "acme", "e": 9999999999}).encode()) + "." + t.split(".")[2]
    assert ok(forged) == 401                                                    # role escalation reusing the old signature
    expired, _ = accounts.sign_token("ann", "analyst", "acme", ttl=-5)
    assert ok(expired) == 401
    # removing the user (or changing the role) revokes existing tokens at once
    f = tmp / "users.json"
    d = json.loads(f.read_text())
    d["users"] = [u for u in d["users"] if u["name"] != "ann"]
    f.write_text(json.dumps(d))
    os.utime(f, (time.time() + 10, time.time() + 10))
    accounts.users()._checked = 0
    assert ok(t) == 401


def test_audit_log_records_who_did_what_without_secrets(env):
    c, tmp = env
    tok = login(c, "vera", "viewer-password-1").json()["token"]
    c.get("/alerts?api_key=SHOULDNOTAPPEAR&x=1", headers={"X-API-Key": tok})
    c.post("/analyze/pcap", headers={"X-API-Key": tok})                          # 403
    login(c, "vera", "wrong-password-xyz")
    for h in logging.getLogger("stealthtap.audit").handlers:
        h.flush()
    text = (tmp / "audit.jsonl").read_text()
    lines = [json.loads(x) for x in text.splitlines()]
    assert "SHOULDNOTAPPEAR" not in text and tok not in text
    assert "viewer-password-1" not in text and "wrong-password-xyz" not in text
    assert {(x["user"], x["method"], x["path"], x["status"]) for x in lines} >= {
        ("vera", "LOGIN", "/auth/login", 200), ("vera", "GET", "/alerts", 200),
        ("vera", "POST", "/analyze/pcap", 403), ("vera", "LOGIN", "/auth/login", 401)}


def test_per_tenant_rate_limit_isolates_tenants(env, monkeypatch):
    monkeypatch.setenv("STEALTHTAP_RATE_LIMIT_PER_MIN", "60")
    c = TestClient(build_app())                                                  # rebuilt so the limiter reads the new setting
    noisy = {"X-API-Key": KEY}                                                   # tenant default
    quiet = {"X-API-Key": "g" * 20}                                              # tenant globex
    codes = [c.get("/alerts", headers=noisy).status_code for _ in range(60)]
    assert 429 in codes and codes[0] == 200
    assert c.get("/alerts", headers=quiet).status_code == 200                    # the other tenant is unaffected
    r = c.get("/alerts", headers=noisy)
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1


def test_per_tenant_analysis_slots(monkeypatch):
    from fastapi import HTTPException
    import src.api.pcap_analysis as pa
    monkeypatch.setattr(pa, "TENANT_MAX_ANALYSES", 2)
    monkeypatch.setattr(pa, "_inflight", 0)
    monkeypatch.setattr(pa, "_tenant_inflight", {})
    pa._admit("acme")
    pa._admit("acme")
    with pytest.raises(HTTPException) as e:
        pa._admit("acme")
    assert e.value.status_code == 429
    pa._admit("globex")                                                          # another tenant still gets a slot
    pa._release("acme")
    pa._admit("acme")


def test_client_ip_trusts_forwarded_for_only_from_the_proxy():
    assert accounts.client_ip("172.18.0.14", "203.0.113.7, 172.18.0.14") == "203.0.113.7"     # behind the local proxy
    assert accounts.client_ip("198.51.100.9", "203.0.113.7") == "198.51.100.9"                 # a remote peer cannot spoof it
    assert accounts.client_ip("172.18.0.14", "not-an-ip") == "172.18.0.14"
    assert accounts.client_ip("127.0.0.1", "") == "127.0.0.1"
