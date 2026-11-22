"""Shared data models used by provider adapters and the UI."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class VpnServer:
    """A public VPN relay as described by its provider."""

    host_name: str
    ip_address: str
    score: int
    ping_ms: int | None
    speed_bps: int
    country: str
    country_code: str
    sessions: int
    uptime_seconds: int
    total_users: int
    total_traffic_bytes: int
    log_policy: str
    operator: str
    openvpn_config_base64: str | None = None

    @property
    def supports_openvpn(self) -> bool:
        return bool(self.openvpn_config_base64)

    @property
    def speed_mbps(self) -> float:
        return self.speed_bps / 1_000_000
