"""Regression test for a real path-traversal gap: GitHub CodeQL flagged
`analysis_id` (a raw URL path segment, no format constraint from FastAPI's
routing) reaching the filesystem in three places. _get_index() already
validated it as a UUID before touching disk; _check_owner() -- called FIRST
on every inspector request (GET /analyze/{analysis_id}/packets, /packet/{n},
/export.pcap) -- did not, so a crafted id could make _owner_file() read a
file outside CAPTURE_STORE before the id was ever checked. Fixed by a single
_validate_analysis_id() every path-touching function calls first."""
from __future__ import annotations

import pytest

from fastapi import HTTPException

from src.api import pcap_analysis as pa


def test_validate_analysis_id_rejects_non_uuid_strings():
    for bad in ("../../etc/passwd", "..\\..\\Windows\\win.ini", "not-a-uuid", "", "a" * 40):
        with pytest.raises(HTTPException) as exc:
            pa._validate_analysis_id(bad)
        assert exc.value.status_code == 400


def test_validate_analysis_id_accepts_a_real_uuid():
    import uuid
    pa._validate_analysis_id(str(uuid.uuid4()))  # must not raise


def test_check_owner_validates_before_touching_the_filesystem(monkeypatch, tmp_path):
    """The bug: _check_owner used to build a path from analysis_id and read
    it BEFORE any format check. Confirm it now rejects a traversal-shaped id
    with 400, not by silently reading (or failing to read) some other file."""
    monkeypatch.setattr(pa, "CAPTURE_STORE", tmp_path)
    from types import SimpleNamespace
    request = SimpleNamespace(state=SimpleNamespace(tenant="default"))
    with pytest.raises(HTTPException) as exc:
        pa._check_owner("../../../../etc/passwd", request)
    assert exc.value.status_code == 400
