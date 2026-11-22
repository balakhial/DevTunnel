"""Tests for server table sorting."""

import pytest

from devtunnel.core.diagnostics import ReachabilityResult
from devtunnel.core.models import VpnServer
from devtunnel.core.sorting import sort_servers


def make_server(
    *,
    country: str = "Japan",
    ip_address: str = "10.0.0.1",
    ping_ms: int | None = 20,
    speed_bps: int = 50_000_000,
    sessions: int = 10,
    has_openvpn: bool = True,
) -> VpnServer:
    return VpnServer(
        host_name=f"relay-{ip_address}",
        ip_address=ip_address,
        score=100,
        ping_ms=ping_ms,
        speed_bps=speed_bps,
        country=country,
        country_code="XX",
        sessions=sessions,
        uptime_seconds=1000,
        total_users=100,
        total_traffic_bytes=1000,
        log_policy="unknown",
        operator="test",
        openvpn_config_base64="Y29uZmln" if has_openvpn else None,
    )


def test_sort_country_alphabetically():
    servers = [make_server(country="Japan"), make_server(country="Canada")]

    result = sort_servers(servers, column=0)

    assert [server.country for server in result] == ["Canada", "Japan"]


def test_sort_ip_numerically_not_lexicographically():
    servers = [
        make_server(ip_address="10.0.0.10"),
        make_server(ip_address="10.0.0.2"),
    ]

    result = sort_servers(servers, column=1)

    assert [server.ip_address for server in result] == [
        "10.0.0.2",
        "10.0.0.10",
    ]


@pytest.mark.parametrize("descending", [False, True])
def test_servers_without_ping_stay_at_the_end(descending):
    servers = [
        make_server(ip_address="10.0.0.1", ping_ms=None),
        make_server(ip_address="10.0.0.2", ping_ms=80),
        make_server(ip_address="10.0.0.3", ping_ms=20),
    ]

    result = sort_servers(servers, column=2, descending=descending)

    assert [server.ip_address for server in result[-1:]] == ["10.0.0.1"]
    expected = ["10.0.0.3", "10.0.0.2"] if not descending else [
        "10.0.0.2",
        "10.0.0.3",
    ]
    assert [server.ip_address for server in result[:2]] == expected


def test_sort_speed_numerically():
    servers = [
        make_server(ip_address="10.0.0.1", speed_bps=100_000_000),
        make_server(ip_address="10.0.0.2", speed_bps=20_000_000),
    ]

    result = sort_servers(servers, column=3)

    assert [server.speed_bps for server in result] == [
        20_000_000,
        100_000_000,
    ]


def test_sort_sessions_numerically():
    servers = [
        make_server(ip_address="10.0.0.1", sessions=100),
        make_server(ip_address="10.0.0.2", sessions=9),
    ]

    result = sort_servers(servers, column=4)

    assert [server.sessions for server in result] == [9, 100]


def test_sort_openvpn_support():
    servers = [
        make_server(ip_address="10.0.0.1", has_openvpn=True),
        make_server(ip_address="10.0.0.2", has_openvpn=False),
    ]

    result = sort_servers(servers, column=5)

    assert [server.supports_openvpn for server in result] == [False, True]


def test_sort_reachability_with_unknown_results_last():
    servers = [
        make_server(ip_address="10.0.0.1"),
        make_server(ip_address="10.0.0.2"),
        make_server(ip_address="10.0.0.3"),
    ]
    results = {
        "10.0.0.1": ReachabilityResult("10.0.0.1", False),
        "10.0.0.2": ReachabilityResult("10.0.0.2", True),
    }

    ascending = sort_servers(
        servers, column=6, reachability=results
    )
    descending = sort_servers(
        servers, column=6, descending=True, reachability=results
    )

    assert [server.ip_address for server in ascending] == [
        "10.0.0.2",
        "10.0.0.1",
        "10.0.0.3",
    ]
    assert [server.ip_address for server in descending] == [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
    ]


def test_sort_local_latency_numerically_with_missing_last():
    servers = [
        make_server(ip_address="10.0.0.1"),
        make_server(ip_address="10.0.0.2"),
        make_server(ip_address="10.0.0.3"),
    ]
    results = {
        "10.0.0.1": ReachabilityResult("10.0.0.1", True, 45.0),
        "10.0.0.2": ReachabilityResult("10.0.0.2", True, 8.5),
        "10.0.0.3": ReachabilityResult("10.0.0.3", True, None),
    }

    result = sort_servers(
        servers, column=7, descending=False, reachability=results
    )

    assert [server.ip_address for server in result] == [
        "10.0.0.2",
        "10.0.0.1",
        "10.0.0.3",
    ]


def test_invalid_column_raises_value_error():
    with pytest.raises(ValueError):
        sort_servers([make_server()], column=8)
