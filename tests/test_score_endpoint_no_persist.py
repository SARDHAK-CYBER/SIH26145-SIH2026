"""
POST /score/{family} is a diagnostic/preview endpoint -- the dashboard's
"test a domain against the model" playground and system_check.py's latency
benchmark both call it. It must never write to the production alerts table
unless the caller explicitly opts in with persist=true: previously it stored
every fired score unconditionally, so each system_check.py run (40 calls,
same synthetic test domain) silently injected 40 fake DGA_DOMAIN alerts into
the real alerts table -- discovered via a 442-row flood of identical
0.0.0.0-sourced "DGA_DOMAIN" alerts spanning weeks of routine benchmark runs.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from src.api import main


class _FakeModelServer:
    def score_flow(self, flow: dict, family: str):
        return {"threat_score": 0.999, "model_scores": {"xgboost": 0.999}, "detection_mode": "xgboost"}


def _request():
    return SimpleNamespace(state=SimpleNamespace(tenant="default"))


def _run(monkeypatch, persist: bool):
    stored = []

    async def fake_store(alert, tenant="default"):
        stored.append(alert)
        return True

    monkeypatch.setattr(main, "model_server", _FakeModelServer())
    monkeypatch.setattr(main, "_store_alert", fake_store)

    req = main.FlowScoreRequest(flow={"dns_query": "xkqzjvbnwmpl.com"}, persist=persist)
    result = asyncio.run(main.score_flow("dns", req, _request()))
    return result, stored


def test_score_endpoint_does_not_persist_by_default(monkeypatch):
    result, stored = _run(monkeypatch, persist=False)
    assert result["fired"] is True
    assert result["persisted"] is False
    assert stored == [], "a plain /score call must not write to the alerts table"


def test_score_endpoint_persists_when_explicitly_requested(monkeypatch):
    result, stored = _run(monkeypatch, persist=True)
    assert result["fired"] is True
    assert result["persisted"] is True
    assert len(stored) == 1, "persist=true must still record exactly one alert"
