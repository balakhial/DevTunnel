import pytest
from urllib.error import URLError

from devtunnel.providers import vpngate
from devtunnel.providers.vpngate import (
    VPN_GATE_API_URL,
    VPN_GATE_MIRROR_API_URL,
    VpnGateError,
    VpnGateProvider,
    parse_vpngate_csv,
)


SAMPLE_CSV = """*vpn_servers
#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64
relay-one,203.0.113.10,1000,25,50000000,Japan,JP,12,3600,100,2048,2weeks,Test operator,hello,Y29uZmln
relay-two,not-an-ip,900,30,40000000,Test,TS,4,1800,50,1024,2weeks,Operator,,
relay-three,203.0.113.11,800,,30000000,Germany,DE,2,900,25,512,2weeks,Operator,,
relay-duplicate,203.0.113.10,700,40,20000000,Japan,JP,1,100,10,100,2weeks,Operator,,
"""


def test_parse_vpngate_csv_skips_invalid_and_duplicate_ips():
    servers = parse_vpngate_csv(SAMPLE_CSV)

    assert len(servers) == 2
    assert servers[0].host_name == "relay-one"
    assert servers[0].ip_address == "203.0.113.10"
    assert servers[0].ping_ms == 25
    assert servers[0].supports_openvpn is True
    assert servers[0].speed_mbps == 50
    assert servers[1].ping_ms is None
    assert servers[1].supports_openvpn is False


def test_parser_rejects_unknown_format():
    with pytest.raises(VpnGateError):
        parse_vpngate_csv("not a VPN Gate response")


class FakeResponse:
    def __init__(self, content: bytes):
        self.content = content

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _limit: int) -> bytes:
        return self.content


def test_provider_falls_back_to_mirror_when_primary_fails(monkeypatch):
    requested_urls = []

    def fake_urlopen(request, timeout):
        requested_urls.append(request.full_url)
        assert timeout > 0
        if request.full_url == VPN_GATE_API_URL:
            raise URLError("primary unavailable")
        return FakeResponse(SAMPLE_CSV.encode("utf-8"))

    monkeypatch.setattr(vpngate, "urlopen", fake_urlopen)
    provider = VpnGateProvider()

    servers = provider.fetch_servers()

    assert len(servers) == 2
    assert requested_urls == [VPN_GATE_API_URL, VPN_GATE_MIRROR_API_URL]
    assert provider.last_source == VPN_GATE_MIRROR_API_URL


def test_provider_uses_primary_without_requesting_mirror(monkeypatch):
    requested_urls = []

    def fake_urlopen(request, timeout):
        requested_urls.append(request.full_url)
        return FakeResponse(SAMPLE_CSV.encode("utf-8"))

    monkeypatch.setattr(vpngate, "urlopen", fake_urlopen)
    provider = VpnGateProvider()

    provider.fetch_servers()

    assert requested_urls == [VPN_GATE_API_URL]
    assert provider.last_source == VPN_GATE_API_URL
