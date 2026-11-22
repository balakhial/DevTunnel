# DevTunnel

**DevTunnel** is a Windows-first desktop application for discovering and evaluating public VPN relay servers, with a developer-focused workflow for tools such as Android Studio, Gradle and Git.

> **Current status: discovery and diagnostics foundation.** DevTunnel retrieves and displays the public VPN Gate server list, filters and sorts relays, and can run bounded ICMP reachability checks. It does not establish VPN tunnels yet.

## Goals

- Discover public relay servers from supported providers.
- Validate and compare server metadata before a user chooses one.
- Keep provider discovery, connection engines and the user interface independent.
- Make connection actions explicit and visible to the user.
- Never silently route traffic or install network drivers.

## Architecture

```
src/devtunnel/
  app.py                 # PySide6 desktop UI
  core/models.py         # Provider-independent data models
  core/sorting.py        # Stable semantic sorting for server rows
  core/diagnostics.py    # Safe, bounded ICMP reachability checks
  providers/base.py      # Provider interface
  providers/vpngate.py   # VPN Gate CSV client, parser and mirror fallback
```

## VPN Gate data sources

DevTunnel tries these endpoints in order:

1. Official HTTPS API: https://www.vpngate.net/api/iphone/
2. Tested mirror fallback: http://150.40.105.20:16086/api/iphone/

The mirror uses plain HTTP because the tested network could reach it while the primary hostname was inaccessible. **HTTP does not authenticate or encrypt the response.** Treat all mirror-provided server metadata and especially embedded OpenVPN profiles as untrusted. This release only displays the list; it does not import or launch profiles or establish VPN connections. Do not use mirror-delivered profile data for a future connection without adding an authenticated source or a separate integrity-verification mechanism.

VPN Gate is a volunteer-operated public relay network. Server availability, performance and operator practices can vary. The provider's published list is not a security audit or a guarantee of privacy.

## Relay reachability checks

The desktop app can send one ICMP echo request to each discovered relay to provide a quick reachability indication. Checks run outside the GUI thread with at most 12 concurrent probes and a 1.2-second ping timeout. Duplicate addresses are checked once. Only globally routable IP addresses are probed; private, loopback, link-local, reserved and malformed addresses are skipped.

ICMP is commonly filtered or rate-limited by networks and relay operators. A missing reply does not prove that an OpenVPN service is offline, and an ICMP reply does not prove that a VPN tunnel can be established. The locally measured latency is separate from the provider-reported Ping value. No VPN profile is downloaded, launched or trusted by this diagnostic feature.

## Requirements

- Windows 10/11 (initial target)
- Python 3.10 or newer (Python 3.14 supported by current PySide6 releases)
- Internet access to at least one configured provider endpoint

## Development setup

PowerShell:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m devtunnel
```

Run tests:

```powershell
python -m pytest
```

## Roadmap

1. Project foundation, VPN Gate discovery, server list UI, filters and semantic sorting. (implemented)
2. Bounded ICMP reachability diagnostics and local latency display. (implemented; ICMP limitations apply)
3. OpenVPN profile acquisition and validation from authenticated/trustworthy sources.
4. OpenVPN integration with explicit user consent, executable discovery and safe process management.
5. Connection status, IP verification and disconnect/recovery flows.
6. Developer proxy profiles for Android Studio / Gradle / Git.
7. Packaging, installer, signing and release automation.

## Security notes

- Public VPN relays are operated by third parties. Do not assume they are suitable for sensitive accounts or confidential traffic.
- Server metadata and downloaded VPN profiles are untrusted input.
- The HTTP mirror is not authenticated; its contents may be modified in transit. Never treat a profile received from it as trustworthy.
- Future connection support must validate profiles, avoid shell-string execution, use argument arrays, and clearly explain routes/DNS changes.
- DevTunnel will not bundle unknown executables or automatically elevate privileges.
- No credentials, personal configuration or downloaded profiles belong in Git.

## License

The project license will be selected before the first public release. Third-party components retain their own licenses.
