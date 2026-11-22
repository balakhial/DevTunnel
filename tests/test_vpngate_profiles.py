"""Tests for VPN Gate official-HTTPS profile retrieval."""

import base64
import hashlib
import json
from datetime import datetime, timezone
from urllib.error import URLError

import pytest

from devtunnel.providers import vpngate
from devtunnel.providers.vpngate import (
    VPN_GATE_API_URL,
    VPN_GATE_MIRROR_API_URL,
    COMMUNITY_MIRROR_INDEX_URL,
    COMMUNITY_MIRROR_REPOSITORY,
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
    def __init__(self, payload: bytes, url: str = VPN_GATE_API_URL):
        self.payload = payload
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _limit: int) -> bytes:
        return self.payload

    def geturl(self) -> str:
        return self.url


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


def test_profile_fetch_never_falls_back_to_unauthenticated_http_mirror(monkeypatch):
    requests = []

    def fake_urlopen(request, timeout):
        requests.append(request.full_url)
        raise URLError("endpoint unavailable")

    monkeypatch.setattr(vpngate, "urlopen", fake_urlopen)

    with pytest.raises(
        VpnGateError,
        match="verified community HTTPS snapshot was also unavailable",
    ):
        VpnGateProvider().fetch_server_profile("8.8.8.8")

    assert requests == [VPN_GATE_API_URL, COMMUNITY_MIRROR_INDEX_URL]
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



def test_profile_fetch_rejects_downgraded_or_untrusted_redirect(monkeypatch):
    class RedirectedResponse(FakeResponse):
        def geturl(self):
            return "http://www.vpngate.net/api/iphone/"

    monkeypatch.setattr(
        vpngate,
        "urlopen",
        lambda *_args, **_kwargs: RedirectedResponse(make_csv(PROFILE)),
    )

    with pytest.raises(VpnGateError, match="redirected to an untrusted URL"):
        VpnGateProvider().fetch_server_profile("8.8.8.8")



def make_mirror_csv() -> bytes:
    encoded = base64.b64encode(PROFILE.encode("utf-8")).decode("ascii")
    return (
        "*vpn_servers\n"
        "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
        f"relay-one,8.8.8.8,1000,20,10000000,Japan,JP,2,3600,20,100,2weeks,Test,hello,{encoded}\n"
        "*\n"
    ).encode("utf-8")


def make_mirror_index(csv_bytes: bytes) -> bytes:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    timestamp = now.isoformat(timespec="seconds").replace("+00:00", ".000Z")
    index = {
        "schema_version": 1,
        "source_url": VPN_GATE_API_URL,
        "fetched_at": timestamp,
        "generated_at": timestamp,
        "index_generated_at": timestamp,
        "data_commit": "a" * 40,
        "source_record_count": 1,
        "server_count": 1,
        "country_count": 1,
        "files": {
            "data/vpngate.csv": {
                "bytes": len(csv_bytes),
                "sha256": hashlib.sha256(csv_bytes).hexdigest(),
                "server_count": 1,
            }
        },
        "workflow_run_url": "https://github.com/example/repo/actions/runs/123",
    }
    return json.dumps(index).encode("utf-8")


def test_profile_uses_verified_community_https_snapshot_when_official_api_is_blocked(
    monkeypatch,
):
    requests = []
    csv_bytes = make_mirror_csv()
    index_bytes = make_mirror_index(csv_bytes)
    expected_csv_url = (
        "https://cdn.jsdelivr.net/gh/"
        f"{COMMUNITY_MIRROR_REPOSITORY}@{'a' * 40}/data/vpngate.csv"
    )

    def fake_urlopen(request, timeout):
        url = request.full_url
        requests.append(url)
        if url == VPN_GATE_API_URL:
            raise URLError("official hostname blocked")
        if url == COMMUNITY_MIRROR_INDEX_URL:
            return FakeResponse(index_bytes, url)
        if url == expected_csv_url:
            return FakeResponse(csv_bytes, url)
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(vpngate, "urlopen", fake_urlopen)

    provider = VpnGateProvider()
    result = provider.fetch_server_profile("8.8.8.8")

    assert "remote 8.8.8.8 443" in result
    assert requests == [
        VPN_GATE_API_URL,
        COMMUNITY_MIRROR_INDEX_URL,
        expected_csv_url,
    ]
    assert provider.last_profile_source.startswith("Community HTTPS snapshot")
    assert provider.last_profile_fetched_at is not None


def test_community_snapshot_retries_same_pinned_commit_on_raw_github(
    monkeypatch,
):
    requests = []
    csv_bytes = make_mirror_csv()
    index_bytes = make_mirror_index(csv_bytes)
    cdn_url = (
        "https://cdn.jsdelivr.net/gh/"
        f"{COMMUNITY_MIRROR_REPOSITORY}@{'a' * 40}/data/vpngate.csv"
    )
    raw_url = (
        "https://raw.githubusercontent.com/"
        f"{COMMUNITY_MIRROR_REPOSITORY}/{'a' * 40}/data/vpngate.csv"
    )

    def fake_urlopen(request, timeout):
        url = request.full_url
        requests.append(url)
        if url == VPN_GATE_API_URL:
            raise URLError("official hostname blocked")
        if url == COMMUNITY_MIRROR_INDEX_URL:
            return FakeResponse(index_bytes, url)
        if url == cdn_url:
            return FakeResponse(b"bad cached bytes", url)
        if url == raw_url:
            return FakeResponse(csv_bytes, url)
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(vpngate, "urlopen", fake_urlopen)

    provider = VpnGateProvider()
    assert "remote 8.8.8.8 443" in provider.fetch_server_profile("8.8.8.8")
    assert requests[-2:] == [cdn_url, raw_url]


def test_community_snapshot_rejects_stale_index(monkeypatch):
    csv_bytes = make_mirror_csv()
    index = json.loads(make_mirror_index(csv_bytes))
    index["fetched_at"] = "2020-01-01T00:00:00.000Z"
    index["generated_at"] = "2020-01-01T00:00:00.000Z"
    index["index_generated_at"] = "2020-01-01T00:00:00.000Z"
    index_bytes = json.dumps(index).encode("utf-8")

    def fake_urlopen(request, timeout):
        if request.full_url == VPN_GATE_API_URL:
            raise URLError("official hostname blocked")
        return FakeResponse(index_bytes, request.full_url)

    monkeypatch.setattr(vpngate, "urlopen", fake_urlopen)

    with pytest.raises(VpnGateError, match="older than 24 hours"):
        VpnGateProvider().fetch_server_profile("8.8.8.8")


def test_community_snapshot_rejects_untrusted_index_source(monkeypatch):
    csv_bytes = make_mirror_csv()
    index = json.loads(make_mirror_index(csv_bytes))
    index["source_url"] = "http://attacker.example/api"
    index_bytes = json.dumps(index).encode("utf-8")

    def fake_urlopen(request, timeout):
        if request.full_url == VPN_GATE_API_URL:
            raise URLError("official hostname blocked")
        return FakeResponse(index_bytes, request.full_url)

    monkeypatch.setattr(vpngate, "urlopen", fake_urlopen)

    with pytest.raises(VpnGateError, match="does not identify the official VPN Gate API"):
        VpnGateProvider().fetch_server_profile("8.8.8.8")


def test_community_snapshot_rejects_hash_mismatch(monkeypatch):
    csv_bytes = make_mirror_csv()
    index_bytes = make_mirror_index(csv_bytes)

    def fake_urlopen(request, timeout):
        url = request.full_url
        if url == VPN_GATE_API_URL:
            raise URLError("official hostname blocked")
        if url == COMMUNITY_MIRROR_INDEX_URL:
            return FakeResponse(index_bytes, url)
        return FakeResponse(b"altered data", url)

    monkeypatch.setattr(vpngate, "urlopen", fake_urlopen)

    with pytest.raises(VpnGateError, match="failed verification"):
        VpnGateProvider().fetch_server_profile("8.8.8.8")
