"""Safe CSV export for the currently displayed VPN server list."""

from __future__ import annotations

import csv
import os
from pathlib import Path
import tempfile
from collections.abc import Iterable, Mapping

from devtunnel.core.diagnostics import ReachabilityResult
from devtunnel.core.models import VpnServer


_HEADERS = [
    "کشور",
    "آدرس IP",
    "Ping منبع (ms)",
    "سرعت (Mbps)",
    "کاربران هم‌زمان",
    "OpenVPN",
    "دسترس‌پذیری",
    "تأخیر محلی (ms)",
]


def _spreadsheet_safe(value: object) -> str:
    """Prevent untrusted text cells from being interpreted as formulas."""
    text = str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


def _reachability_values(
    result: ReachabilityResult | None,
) -> tuple[str, str]:
    if result is None:
        return "بررسی‌نشده", "—"

    if result.reachable is True:
        latency = (
            f"{result.latency_ms:.1f}"
            if result.latency_ms is not None
            else "نامشخص"
        )
        return "در دسترس", latency

    if result.reachable is False:
        return "بدون پاسخ", "—"

    return "قابل بررسی نیست", "—"


def export_servers_to_csv(
    servers: Iterable[VpnServer],
    destination: str | Path,
    *,
    reachability: Mapping[str, ReachabilityResult] | None = None,
) -> int:
    """Atomically export server metadata and optional diagnostics as UTF-8 CSV.

    OpenVPN profiles, certificates and other credential-like material are
    deliberately excluded. The returned integer is the number of rows written.
    """
    output_path = Path(destination).expanduser()
    if not output_path.parent.exists():
        raise FileNotFoundError(output_path.parent)

    server_list = list(servers)
    results = reachability or {}
    temporary_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8-sig",
            newline="",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            writer = csv.writer(temporary_file, lineterminator="\n")
            writer.writerow(_HEADERS)

            for server in server_list:
                availability, local_latency = _reachability_values(
                    results.get(server.ip_address)
                )
                row = [
                    server.country,
                    server.ip_address,
                    server.ping_ms if server.ping_ms is not None else "—",
                    f"{server.speed_mbps:.2f}",
                    server.sessions,
                    "بله" if server.supports_openvpn else "خیر",
                    availability,
                    local_latency,
                ]
                writer.writerow(_spreadsheet_safe(value) for value in row)

        os.replace(temporary_path, output_path)
        temporary_path = None
        return len(server_list)
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
