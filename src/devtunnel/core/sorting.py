"""Stable, provider-independent sorting for VPN server rows."""

from collections.abc import Iterable, Mapping
import ipaddress

from devtunnel.core.diagnostics import ReachabilityResult
from devtunnel.core.models import VpnServer


def sort_servers(
    servers: Iterable[VpnServer],
    column: int,
    descending: bool = False,
    reachability: Mapping[str, ReachabilityResult] | None = None,
) -> list[VpnServer]:
    """Sort servers according to the eight visible table columns.

    Columns: country, IP address, provider ping, speed, sessions, OpenVPN,
    reachability and locally measured ICMP latency. Missing measurements
    always remain at the end, regardless of sort direction.
    """
    items = list(servers)
    results = reachability or {}

    if column == 0:
        return sorted(
            items,
            key=lambda server: server.country.casefold(),
            reverse=descending,
        )

    if column == 1:
        return sorted(
            items,
            key=lambda server: (
                ipaddress.ip_address(server.ip_address).version,
                int(ipaddress.ip_address(server.ip_address)),
            ),
            reverse=descending,
        )

    if column == 2:
        available = [server for server in items if server.ping_ms is not None]
        unavailable = [server for server in items if server.ping_ms is None]
        available.sort(key=lambda server: server.ping_ms, reverse=descending)
        return available + unavailable

    if column == 3:
        return sorted(
            items,
            key=lambda server: server.speed_bps,
            reverse=descending,
        )

    if column == 4:
        return sorted(
            items,
            key=lambda server: server.sessions,
            reverse=descending,
        )

    if column == 5:
        return sorted(
            items,
            key=lambda server: server.supports_openvpn,
            reverse=descending,
        )

    if column == 6:
        available = [
            server
            for server in items
            if (
                server.ip_address in results
                and results[server.ip_address].reachable is not None
            )
        ]
        unavailable = [server for server in items if server not in available]
        available.sort(
            key=lambda server: not results[server.ip_address].reachable,
            reverse=descending,
        )
        return available + unavailable

    if column == 7:
        available = [
            server
            for server in items
            if (
                server.ip_address in results
                and results[server.ip_address].latency_ms is not None
            )
        ]
        unavailable = [server for server in items if server not in available]
        available.sort(
            key=lambda server: results[server.ip_address].latency_ms,
            reverse=descending,
        )
        return available + unavailable

    raise ValueError(f"Unsupported server table column: {column}")
