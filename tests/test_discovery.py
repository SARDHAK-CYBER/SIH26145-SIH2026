"""Active discovery scope rules -- never sweep anything but a private range inside an attached subnet."""
import ipaddress

import pytest

pytest.importorskip("psutil")
fastapi = pytest.importorskip("fastapi")

from src.api import discovery as d  # noqa: E402


def _fake(monkeypatch, subnets):
    monkeypatch.setattr(d, "local_subnets", lambda: [(n, ipaddress.IPv4Network(c, strict=False), ipaddress.IPv4Address(ip)) for n, c, ip in subnets])


def test_default_target_is_the_slash24_around_this_host(monkeypatch):
    _fake(monkeypatch, [("Wi-Fi", "10.20.120.0/21", "10.20.123.212")])
    iface, net = d.resolve_target(None, None)
    assert str(net) == "10.20.123.0/24" and iface == "Wi-Fi"


@pytest.mark.parametrize("cidr,code", [("8.8.8.0/24", 403), ("10.99.0.0/24", 403), ("10.20.120.0/21", 422), ("garbage", 422)])
def test_out_of_scope_targets_are_refused(monkeypatch, cidr, code):
    _fake(monkeypatch, [("Wi-Fi", "10.20.120.0/21", "10.20.123.212")])
    with pytest.raises(fastapi.HTTPException) as e:
        d.resolve_target("Wi-Fi", cidr)
    assert e.value.status_code == code


def test_public_attached_subnet_is_never_swept(monkeypatch):
    _fake(monkeypatch, [("eth0", "203.0.113.0/24", "203.0.113.5")])
    with pytest.raises(fastapi.HTTPException) as e:
        d.resolve_target("eth0", "203.0.113.0/28")
    assert e.value.status_code == 403
