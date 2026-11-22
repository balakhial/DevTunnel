"""Provider interface."""

from typing import Protocol

from devtunnel.core.models import VpnServer


class ServerProvider(Protocol):
    """A source capable of returning public VPN server metadata."""

    @property
    def name(self) -> str: ...

    def fetch_servers(self) -> list[VpnServer]:
        """Fetch and parse the provider's current server list."""
        ...
