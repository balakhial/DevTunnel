"""Tests for VPN Gate official-HTTPS profile retrieval."""

import base64
from urllib.error import URLError

import pytest

from devtunnel.providers import vpngate
from devtunnel.providers.vpngate import (
    VPN_GATE_API_URL,
    VPN_GATE_MIRROR_API_URL,
    VpnGateError,
    VpnGateProvider,
)


PROFILE = """client
dev tun
proto tcp-client
remote 8.8.8.8 443
nobind
persist-key
persist-tun
remote-cert-tls server
auth-user-pass
<ca>
-----BEGIN CERTIFICATE-----
ZmFrZQ==
-----END CERTIFICATE-----
</ca>
"""


def make_csv(config: str | None, ip_address: str = "8.8.8.8") -> bytes:
    encoded = (
        base64.b64encode(config.encode("utf-8")).decode("ascii")
        if config is not None
        else ""
    )
    return (
        "*vpn_servers\n"
        "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
        f"relay-one,{ip_address},1000,20,10000000,Japan,JP,2,3600,20,100,2weeks,Test,hello,{encoded}\n"
    ).encode("utf-8")


class FakeResponse:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _limit: int) -> bytes:
        return self.payload


def test_profile_is_retrieved_only_from_official_https_api(monkeypatch):
    requests = []

    def fake_urlopen(request, timeout):
        requests.append(request.full_url)
        assert timeout > 0
        return FakeResponse(make_csv(PROFILE))

    monkeypatch.setattr(vpngate, "urlopen", fake_urlopen)

    provider = VpnGateProvider()
    profile = provider.fetch_server_profile("8.8.8.8")

    assert "remote 8.8.8.8 443" in profile
    assert "<ca>" in profile
    assert requests == [VPN_GATE_API_URL]
    assert provider.last_source == VPN_GATE_API_URL


def test_profile_fetch_never_falls_back_to_http_mirror(monkeypatch):
    requests = []

    def fake_urlopen(request, timeout):
        requests.append(request.full_url)
        raise URLError("official HTTPS blocked")

    monkeypatch.setattr(vpngate, "urlopen", fake_urlopen)

    with pytest.raises(VpnGateError, match="HTTP mirror is intentionally not used"):
        VpnGateProvider().fetch_server_profile("8.8.8.8")

    assert requests == [VPN_GATE_API_URL]
    assert VPN_GATE_MIRROR_API_URL not in requests


def test_profile_fetch_rejects_server_not_in_official_list(monkeypatch):
    monkeypatch.setattr(
        vpngate,
        "urlopen",
        lambda *_args, **_kwargs: FakeResponse(make_csv(PROFILE, "1.1.1.1")),
    )

    with pytest.raises(VpnGateError, match="no longer present"):
        VpnGateProvider().fetch_server_profile("8.8.8.8")


def test_profile_fetch_rejects_servers_without_openvpn(monkeypatch):
    monkeypatch.setattr(
        vpngate,
        "urlopen",
        lambda *_args, **_kwargs: FakeResponse(make_csv(None)),
    )

    with pytest.raises(VpnGateError, match="does not publish an OpenVPN profile"):
        VpnGateProvider().fetch_server_profile("8.8.8.8")


def test_profile_fetch_rejects_invalid_base64(monkeypatch):
    payload = (
        "*vpn_servers\n"
        "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
        "relay-one,8.8.8.8,1000,20,10000000,Japan,JP,2,3600,20,100,2weeks,Test,hello,%%%\n"
    ).encode("utf-8")
    monkeypatch.setattr(
        vpngate,
        "urlopen",
        lambda *_args, **_kwargs: FakeResponse(payload),
    )

    with pytest.raises(VpnGateError, match="invalid OpenVPN profile"):
        VpnGateProvider().fetch_server_profile("8.8.8.8")
