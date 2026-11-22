"""VPN Gate public CSV provider with an explicitly identified mirror fallback.

The primary endpoint and CSV format are published by VPN Gate:
https://www.vpngate.net/api/iphone/

The fallback is the HTTP mirror tested for this installation. HTTP does not
authenticate the response; data received from it must remain untrusted.
"""

import base64
import binascii
import csv
import io
import ipaddress
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from devtunnel.core.models import VpnServer
from devtunnel.core.profiles import OpenVPNProfileError, validate_vpngate_profile

VPN_GATE_API_URL = "https://www.vpngate.net/api/iphone/"
# Tested reachable by the user when the primary hostname was inaccessible.
# Plain HTTP is intentional here but provides no transport authenticity.
VPN_GATE_MIRROR_API_URL = "http://150.40.105.20:16086/api/iphone/"
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
    """Fetch VPN Gate relays, trying the official endpoint before its mirror."""

    def __init__(self) -> None:
        self.last_source: str | None = None

    @property
    def name(self) -> str:
        return "VPN Gate"

    def fetch_servers(self) -> list[VpnServer]:
        errors: list[str] = []
        endpoints = (VPN_GATE_API_URL, VPN_GATE_MIRROR_API_URL)

        for endpoint in endpoints:
            request = Request(
                endpoint,
                headers={"User-Agent": _USER_AGENT, "Accept": "text/csv,*/*"},
            )
            try:
                with urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
                    payload_bytes = response.read(_MAX_RESPONSE_BYTES + 1)

                if len(payload_bytes) > _MAX_RESPONSE_BYTES:
                    raise VpnGateError("Response exceeded the 15 MB safety limit.")

                payload = payload_bytes.decode("utf-8-sig")
                servers = parse_vpngate_csv(payload)
                if not servers:
                    raise VpnGateError("The response contained no usable VPN servers.")

                self.last_source = endpoint
                return servers
            except (HTTPError, URLError, TimeoutError, OSError, UnicodeDecodeError, VpnGateError) as exc:
                errors.append(f"{endpoint}: {exc}")

        self.last_source = None
        raise VpnGateError(
            "Could not download the VPN Gate server list from the primary endpoint "
            "or its configured mirror. " + " | ".join(errors)
        )

    def fetch_server_profile(self, ip_address: str) -> str:
        """Fetch one server's OpenVPN profile from the official HTTPS API only.

        This deliberately does not fall back to the HTTP mirror. The CSV list
        and profile must be re-fetched over authenticated HTTPS at connection
        time; a stale or mirror-provided profile must never be launched.
        """
        try:
            selected_ip = str(ipaddress.ip_address(ip_address))
        except ValueError as exc:
            raise VpnGateError("The selected server IP address is invalid.") from exc

        if not ipaddress.ip_address(selected_ip).is_global:
            raise VpnGateError("The selected server IP address is not public.")

        request = Request(
            VPN_GATE_API_URL,
            headers={"User-Agent": _USER_AGENT, "Accept": "text/csv,*/*"},
        )
        try:
            with urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
                final_url = urlsplit(response.geturl())
                if (
                    final_url.scheme.lower() != "https"
                    or final_url.hostname not in {"www.vpngate.net", "vpngate.net"}
                ):
                    raise VpnGateError(
                        "The official API redirected to an untrusted URL; "
                        "the profile will not be used."
                    )
                payload_bytes = response.read(_MAX_RESPONSE_BYTES + 1)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise VpnGateError(
                "A connection profile can only be obtained from VPN Gate's "
                "authenticated HTTPS API. The official API could not be reached; "
                "the HTTP mirror is intentionally not used for VPN connections. "
                f"Details: {exc}"
            ) from exc

        if len(payload_bytes) > _MAX_RESPONSE_BYTES:
            raise VpnGateError("The official VPN Gate response exceeded the 15 MB limit.")

        try:
            payload = payload_bytes.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise VpnGateError("The official VPN Gate response was not valid UTF-8.") from exc

        servers = parse_vpngate_csv(payload)
        server = next(
            (item for item in servers if item.ip_address == selected_ip),
            None,
        )
        if server is None:
            raise VpnGateError(
                "The selected server is no longer present in the official HTTPS list. "
                "Refresh the server list and choose another relay."
            )
        if not server.supports_openvpn or not server.openvpn_config_base64:
            raise VpnGateError("The selected server does not publish an OpenVPN profile.")

        try:
            encoded = b"".join(server.openvpn_config_base64.encode("ascii").split())
            profile_bytes = base64.b64decode(encoded, validate=True)
            if not profile_bytes or len(profile_bytes) > 1024 * 1024:
                raise VpnGateError("The decoded OpenVPN profile is empty or too large.")
            profile_text = profile_bytes.decode("utf-8-sig")
        except (UnicodeEncodeError, binascii.Error, UnicodeDecodeError) as exc:
            raise VpnGateError("The server published an invalid OpenVPN profile.") from exc

        try:
            safe_profile = validate_vpngate_profile(
                profile_text,
                expected_ip=selected_ip,
            )
        except OpenVPNProfileError as exc:
            raise VpnGateError(
                f"The official OpenVPN profile failed safety validation: {exc}"
            ) from exc

        self.last_source = VPN_GATE_API_URL
        return safe_profile
