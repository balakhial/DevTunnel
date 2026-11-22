"""VPN Gate server discovery and guarded OpenVPN profile retrieval.

Server discovery tries the official VPN Gate API and may use a clearly
identified HTTP mirror for display-only metadata. Connection profiles are
fetched from the official HTTPS API, with a separate SHA-256-pinned community
HTTPS snapshot as a fallback. The unauthenticated HTTP mirror is never used
for VPN connection profiles.
"""

import base64
import binascii
import csv
import hashlib
import json
import io
import ipaddress
import re
from datetime import datetime, timedelta, timezone
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

# Independently maintained HTTPS snapshot mirror. It republishes the official
# VPN Gate CSV and provides a pinned Git commit plus exact byte lengths/hashes.
# It is not operated or authenticated by VPN Gate.
COMMUNITY_MIRROR_REPOSITORY = "GeorgeXie2333/vpngate-list-mirror"
COMMUNITY_MIRROR_INDEX_URL = (
    "https://raw.githubusercontent.com/"
    f"{COMMUNITY_MIRROR_REPOSITORY}/main/latest.json"
)
_COMMUNITY_INDEX_MAX_BYTES = 64 * 1024
_COMMUNITY_MAX_AGE = timedelta(hours=24)
_COMMUNITY_STALE_WARNING_AGE = timedelta(hours=3)


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
        self.last_profile_source: str | None = None
        self.last_profile_fetched_at: str | None = None

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

    @staticmethod
    def _decode_and_validate_profile(
        server: VpnServer,
        selected_ip: str,
    ) -> str:
        if not server.supports_openvpn or not server.openvpn_config_base64:
            raise VpnGateError(
                "The selected server does not publish an OpenVPN profile."
            )

        try:
            encoded = b"".join(server.openvpn_config_base64.encode("ascii").split())
            profile_bytes = base64.b64decode(encoded, validate=True)
            if not profile_bytes or len(profile_bytes) > 1024 * 1024:
                raise VpnGateError(
                    "The decoded OpenVPN profile is empty or too large."
                )
            profile_text = profile_bytes.decode("utf-8-sig")
        except (UnicodeEncodeError, binascii.Error, UnicodeDecodeError) as exc:
            raise VpnGateError(
                "The server published an invalid OpenVPN profile."
            ) from exc

        try:
            return validate_vpngate_profile(
                profile_text,
                expected_ip=selected_ip,
            )
        except OpenVPNProfileError as exc:
            raise VpnGateError(
                f"The OpenVPN profile failed safety validation: {exc}"
            ) from exc

    @staticmethod
    def _read_https(
        url: str,
        *,
        max_bytes: int,
        allowed_hosts: set[str],
    ) -> bytes:
        request = Request(
            url,
            headers={
                "User-Agent": _USER_AGENT,
                "Accept": "*/*",
                "Accept-Encoding": "identity",
            },
        )
        with urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
            final_url = urlsplit(response.geturl())
            if (
                final_url.scheme.lower() != "https"
                or final_url.hostname not in allowed_hosts
            ):
                raise VpnGateError(
                    "An HTTPS snapshot request redirected to an untrusted URL."
                )
            body = response.read(max_bytes + 1)

        if len(body) > max_bytes:
            raise VpnGateError(
                f"HTTPS response exceeded its {max_bytes}-byte safety limit."
            )
        return body

    def _fetch_community_mirror_profile(self, selected_ip: str) -> tuple[str, str]:
        """Fetch a fresh, SHA-256-pinned community snapshot over HTTPS.

        The manifest and its files share one publisher, so hashes protect
        snapshot integrity and consistency, not the identity of the publisher.
        The calling UI must disclose that this is not an official VPN Gate
        endpoint before a connection attempt is authorized.
        """
        try:
            index_bytes = self._read_https(
                COMMUNITY_MIRROR_INDEX_URL,
                max_bytes=_COMMUNITY_INDEX_MAX_BYTES,
                allowed_hosts={"raw.githubusercontent.com"},
            )
            index = json.loads(index_bytes.decode("utf-8"))

            if not isinstance(index, dict) or index.get("schema_version") != 1:
                raise VpnGateError(
                    "The community mirror uses an unsupported snapshot schema."
                )
            if index.get("source_url") != VPN_GATE_API_URL:
                raise VpnGateError(
                    "The community mirror manifest does not identify the official VPN Gate API."
                )

            commit = index.get("data_commit")
            if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
                raise VpnGateError(
                    "The community mirror returned an invalid pinned data commit."
                )

            fetched_at = index.get("fetched_at")
            if not isinstance(fetched_at, str) or not fetched_at.endswith("Z"):
                raise VpnGateError(
                    "The community mirror snapshot has no valid UTC fetch time."
                )
            try:
                fetched_time = datetime.fromisoformat(
                    fetched_at.replace("Z", "+00:00")
                )
            except ValueError as exc:
                raise VpnGateError(
                    "The community mirror snapshot has an invalid fetch time."
                ) from exc

            now = datetime.now(timezone.utc)
            if fetched_time > now + timedelta(minutes=5):
                raise VpnGateError(
                    "The community mirror snapshot timestamp is unexpectedly in the future."
                )
            age = now - fetched_time
            if age > _COMMUNITY_MAX_AGE:
                raise VpnGateError(
                    "The community mirror snapshot is older than 24 hours; "
                    "refreshing the server list later may help."
                )

            server_count = index.get("server_count")
            if type(server_count) is not int or not 1 <= server_count <= 500:
                raise VpnGateError(
                    "The community mirror server count is invalid or exceeds the safety limit."
                )

            manifest = index.get("files")
            descriptor = (
                manifest.get("data/vpngate.csv")
                if isinstance(manifest, dict)
                else None
            )
            if not isinstance(descriptor, dict):
                raise VpnGateError(
                    "The community mirror manifest is missing its CSV descriptor."
                )

            expected_bytes = descriptor.get("bytes")
            expected_hash = descriptor.get("sha256")
            if (
                type(expected_bytes) is not int
                or not 1 <= expected_bytes <= _MAX_RESPONSE_BYTES
                or not isinstance(expected_hash, str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
                or descriptor.get("server_count") != server_count
            ):
                raise VpnGateError(
                    "The community mirror CSV descriptor is invalid."
                )

            data_urls = (
                "https://cdn.jsdelivr.net/gh/"
                f"{COMMUNITY_MIRROR_REPOSITORY}@{commit}/data/vpngate.csv",
                "https://raw.githubusercontent.com/"
                f"{COMMUNITY_MIRROR_REPOSITORY}/{commit}/data/vpngate.csv",
            )
            csv_bytes: bytes | None = None
            download_errors: list[str] = []

            for url in data_urls:
                host = urlsplit(url).hostname
                try:
                    candidate = self._read_https(
                        url,
                        max_bytes=_MAX_RESPONSE_BYTES,
                        allowed_hosts={host} if host else set(),
                    )
                    if (
                        len(candidate) != expected_bytes
                        or hashlib.sha256(candidate).hexdigest() != expected_hash
                    ):
                        raise VpnGateError(
                            "The community mirror CSV failed its pinned SHA-256/length check."
                        )
                    csv_bytes = candidate
                    break
                except (HTTPError, URLError, TimeoutError, OSError, VpnGateError) as exc:
                    download_errors.append(f"{host}: {exc}")

            if csv_bytes is None:
                raise VpnGateError(
                    "Both HTTPS snapshot file endpoints failed verification. "
                    + " | ".join(download_errors)
                )

            csv_text = csv_bytes.decode("utf-8-sig")
            csv_lines = csv_text.splitlines()
            if (
                not csv_lines
                or csv_lines[0].strip() != "*vpn_servers"
                or csv_lines[-1].strip() != "*"
            ):
                raise VpnGateError(
                    "The community mirror CSV is missing its expected start/end markers."
                )

            servers = parse_vpngate_csv(csv_text)
            if len(servers) != server_count:
                raise VpnGateError(
                    "The community mirror CSV server count does not match its manifest."
                )

            server = next(
                (item for item in servers if item.ip_address == selected_ip),
                None,
            )
            if server is None:
                raise VpnGateError(
                    "The selected server is absent from the latest verified community snapshot."
                )

            safe_profile = self._decode_and_validate_profile(server, selected_ip)
            source = (
                "Community HTTPS snapshot "
                f"({COMMUNITY_MIRROR_REPOSITORY}, fetched {fetched_at})"
            )
            return safe_profile, source

        except VpnGateError:
            raise
        except (
            HTTPError,
            URLError,
            TimeoutError,
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise VpnGateError(
                f"Could not download or verify the community HTTPS snapshot: {exc}"
            ) from exc

    def fetch_server_profile(self, ip_address: str) -> str:
        """Fetch a profile from official HTTPS, then a verified community snapshot.

        The unauthenticated HTTP mirror used for discovery is never used for
        connection profiles. A community HTTPS snapshot is only a fallback
        and must be no older than 24 hours and match its pinned SHA-256 manifest.
        """
        try:
            selected_ip = str(ipaddress.ip_address(ip_address))
        except ValueError as exc:
            raise VpnGateError(
                "The selected server IP address is invalid."
            ) from exc

        if not ipaddress.ip_address(selected_ip).is_global:
            raise VpnGateError(
                "The selected server IP address is not public."
            )

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
        except (HTTPError, URLError, TimeoutError, OSError) as official_error:
            try:
                safe_profile, mirror_source = self._fetch_community_mirror_profile(
                    selected_ip
                )
            except VpnGateError as mirror_error:
                raise VpnGateError(
                    "The official VPN Gate HTTPS API could not be reached, and the "
                    "verified community HTTPS snapshot was also unavailable. "
                    f"Official API error: {official_error}. "
                    f"Community snapshot error: {mirror_error}"
                ) from mirror_error

            self.last_profile_source = mirror_source
            self.last_profile_fetched_at = mirror_source.rsplit("fetched ", 1)[-1].rstrip(")")
            self.last_source = mirror_source
            return safe_profile

        if len(payload_bytes) > _MAX_RESPONSE_BYTES:
            raise VpnGateError(
                "The official VPN Gate response exceeded the 15 MB limit."
            )

        try:
            payload = payload_bytes.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise VpnGateError(
                "The official VPN Gate response was not valid UTF-8."
            ) from exc

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

        safe_profile = self._decode_and_validate_profile(server, selected_ip)
        self.last_profile_source = "Official VPN Gate HTTPS API"
        self.last_profile_fetched_at = None
        self.last_source = VPN_GATE_API_URL
        return safe_profile
