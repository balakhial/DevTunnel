"""VPN Gate public CSV provider.

The endpoint and CSV format are published by VPN Gate:
https://www.vpngate.net/api/iphone/
"""

import csv
import io
import ipaddress
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from devtunnel.core.models import VpnServer

VPN_GATE_API_URL = "https://www.vpngate.net/api/iphone/"
_USER_AGENT = "DevTunnel/0.1.0 (+https://github.com/balakhial/DevTunnel)"
_TIMEOUT_SECONDS = 20
_MAX_RESPONSE_BYTES = 15 * 1024 * 1024


class VpnGateError(RuntimeError):
    """Raised when VPN Gate data cannot be downloaded or parsed."""


def _to_int(value: str | None, *, default: int = 0) -> int:
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def _optional_int(value: str | None) -> int | None:
    parsed = _to_int(value, default=-1)
    return parsed if parsed >= 0 else None


def parse_vpngate_csv(payload: str) -> list[VpnServer]:
    """Parse VPN Gate's CSV response, ignoring its preamble and invalid rows."""
    lines = payload.lstrip("\ufeff").splitlines()
    header_index = next(
        (index for index, line in enumerate(lines) if line.startswith("#HostName,")),
        None,
    )
    if header_index is None:
        raise VpnGateError("VPN Gate response did not contain the expected CSV header.")

    reader = csv.DictReader(io.StringIO("\n".join(lines[header_index:])))
    servers: list[VpnServer] = []
    seen_ips: set[str] = set()

    for row in reader:
        host_name = (row.get("#HostName") or "").strip()
        ip_text = (row.get("IP") or "").strip()
        country = (row.get("CountryLong") or "").strip()
        if not host_name or not ip_text:
            continue

        try:
            ip_address = str(ipaddress.ip_address(ip_text))
        except ValueError:
            continue

        if ip_address in seen_ips:
            continue
        seen_ips.add(ip_address)

        config = (row.get("OpenVPN_ConfigData_Base64") or "").strip() or None
        servers.append(
            VpnServer(
                host_name=host_name,
                ip_address=ip_address,
                score=_to_int(row.get("Score")),
                ping_ms=_optional_int(row.get("Ping")),
                speed_bps=_to_int(row.get("Speed")),
                country=country or "Unknown",
                country_code=(row.get("CountryShort") or "").strip(),
                sessions=_to_int(row.get("NumVpnSessions")),
                uptime_seconds=_to_int(row.get("Uptime")),
                total_users=_to_int(row.get("TotalUsers")),
                total_traffic_bytes=_to_int(row.get("TotalTraffic")),
                log_policy=(row.get("LogType") or "").strip(),
                operator=(row.get("Operator") or "").strip(),
                openvpn_config_base64=config,
            )
        )

    return servers


class VpnGateProvider:
    """Fetch the current public relay list from the official VPN Gate API."""

    @property
    def name(self) -> str:
        return "VPN Gate"

    def fetch_servers(self) -> list[VpnServer]:
        request = Request(
            VPN_GATE_API_URL,
            headers={"User-Agent": _USER_AGENT, "Accept": "text/csv,*/*"},
        )
        try:
            with urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
                payload_bytes = response.read(_MAX_RESPONSE_BYTES + 1)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise VpnGateError(f"Could not download the VPN Gate server list: {exc}") from exc

        if len(payload_bytes) > _MAX_RESPONSE_BYTES:
            raise VpnGateError("VPN Gate response exceeded the 15 MB safety limit.")

        try:
            payload = payload_bytes.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise VpnGateError("VPN Gate response was not valid UTF-8.") from exc

        return parse_vpngate_csv(payload)
