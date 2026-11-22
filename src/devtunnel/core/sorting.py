"""Stable, provider-independent sorting for VPN server rows."""

from collections.abc import Iterable
import ipaddress

from devtunnel.core.models import VpnServer


def sort_servers(
    servers: Iterable[VpnServer],
    column: int,
    descending: bool = False,
) -> list[VpnServer]:
    """Sort servers using the table column semantics.

    Columns: country, IP address, ping, speed, sessions, OpenVPN support.
    Servers without a ping are always kept at the end.
    """
    items = list(servers)

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

    raise ValueError(f"Unsupported server table column: {column}")
