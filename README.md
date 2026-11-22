# DevTunnel

**DevTunnel** is a Windows-first desktop application for discovering and evaluating public VPN relay servers, with a developer-focused workflow for tools such as Android Studio, Gradle and Git.

> **Current status: discovery, diagnostics and experimental OpenVPN connection.** DevTunnel retrieves and displays VPN Gate relays, filters and sorts them, measures ICMP reachability, exports CSV, and includes an explicit connect/disconnect flow. Real tunnel operation still requires local Windows and network verification.

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
  core/export.py         # Atomic, spreadsheet-safe CSV export
  core/openvpn.py        # Read-only local OpenVPN CLI discovery
  core/profiles.py       # Strict VPN Gate profile validation
  core/vpn_session.py   # Managed OpenVPN process and loopback control
  providers/base.py      # Provider interface
  providers/vpngate.py   # VPN Gate CSV client, parser and mirror fallback
```

## VPN Gate data sources

DevTunnel tries these endpoints in order:

1. Official HTTPS API: https://www.vpngate.net/api/iphone/
2. Tested mirror fallback: http://150.40.105.20:16086/api/iphone/

The mirror uses plain HTTP because the tested network could reach it while the primary hostname was inaccessible. **HTTP does not authenticate or encrypt the response.** Treat all mirror-provided server metadata and especially embedded OpenVPN profiles as untrusted. The mirror is used only to populate the discovery list. A connection attempt fetches the selected server profile again from the official HTTPS API and refuses HTTP fallback, HTTPS downgrade, or redirects to an untrusted host.

VPN Gate is a volunteer-operated public relay network. Server availability, performance and operator practices can vary. The provider's published list is not a security audit or a guarantee of privacy.

## Relay reachability checks

The desktop app can send one ICMP echo request to each discovered relay to provide a quick reachability indication. Checks run outside the GUI thread with at most 12 concurrent probes, a 1.2-second ping timeout and a 500-unique-address per-run cap. Duplicate addresses are checked once. Only globally routable IP addresses are probed; private, loopback, link-local, reserved and malformed addresses are skipped.

ICMP is commonly filtered or rate-limited by networks and relay operators. A missing reply does not prove that an OpenVPN service is offline, and an ICMP reply does not prove that a VPN tunnel can be established. The locally measured latency is separate from the provider-reported Ping value. No VPN profile is downloaded, launched or trusted by this diagnostic feature.

## CSV export

The desktop app can export the currently filtered and sorted server rows, including provider metrics and local reachability results, to a UTF-8 CSV file suitable for spreadsheet applications. Export is atomic, excludes OpenVPN profile/certificate material, and escapes untrusted text that could otherwise be interpreted as a spreadsheet formula.

## Experimental OpenVPN connection

Select a row that advertises OpenVPN support and use the Connect button. DevTunnel fetches that server's profile again through the official VPN Gate HTTPS API. The selected IP must still appear in the fresh server list, the profile must decode correctly, and its directives must pass a strict allowlist validator. Profiles that use external files, scripts, plugins, nested configuration, custom management directives, or a remote address different from the selected server are rejected.

The OpenVPN process is launched with an argument array and shell=False. The profile and a randomly generated management password are written to a temporary directory and removed when the session ends. The process is controlled through a password-protected management socket bound only to 127.0.0.1. If DevTunnel exits unexpectedly and loses that controller, OpenVPN is configured to exit rather than leave an unmanaged tunnel process behind. VPN Gate's documented public credentials (username vpn, password vpn) are sent only when the relay explicitly requests them. Interactive token challenges and private-key passphrases are not automated.

Every connection requires an explicit in-app confirmation. Public relays are operated by volunteers. A connection may change Windows routes and DNS and may send all Internet traffic through that relay. The relay operator may observe traffic that is not protected by end-to-end encryption. Do not use public relays for sensitive accounts or confidential traffic. Use the in-app Disconnect action for a graceful stop.

DevTunnel does not automatically elevate privileges or install network drivers. Depending on the OpenVPN version and Windows driver/service setup, a connection may require the OpenVPN Interactive Service or manually starting DevTunnel with the required privileges. The implementation is experimental and has not yet been exercised on the user's Windows machine.

Connection setup first tries the official https://www.vpngate.net/api/iphone/ endpoint. If it is unreachable, DevTunnel can use a separately maintained community HTTPS snapshot from GeorgeXie2333/vpngate-list-mirror. The snapshot is pinned to a full Git commit, its exact CSV byte length and SHA-256 are checked, its source URL must identify the official VPN Gate API, and it is rejected if older than 24 hours. A same-commit GitHub Raw URL is used if the CDN download fails. These checks protect file integrity and cross-version consistency; because the index and files share one publisher, they do not independently authenticate that publisher or prove that the publisher copied the official source honestly. The app discloses this fallback in the confirmation dialog. The unauthenticated HTTP mirror tested for discovery is never used for a connection profile.
## Local OpenVPN prerequisite check

Official Windows Community installer: https://openvpn.net/community-downloads/

DevTunnel can look for the OpenVPN command-line executable on `PATH` and in standard Windows OpenVPN Community Edition installation directories. This is a read-only filesystem check: it does not install, launch, elevate or configure OpenVPN. Finding the executable is only a prerequisite check, not a VPN connection test.

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
3. Filtered CSV export of server metadata and diagnostics. (implemented)
4. Read-only OpenVPN CLI discovery. (implemented)
5. Fresh OpenVPN profile acquisition from official HTTPS and strict validation. (implemented)
6. Experimental OpenVPN connection, state tracking and graceful disconnect. (implemented; pending local Windows verification)
7. External IP verification and disconnect/recovery hardening.
8. Developer proxy profiles for Android Studio / Gradle / Git.
9. Packaging, installer, signing and release automation.

## Security notes

- Public VPN relays are operated by third parties. Do not assume they are suitable for sensitive accounts or confidential traffic.
- Server metadata and downloaded VPN profiles are untrusted input; only profiles freshly re-fetched over the official HTTPS API are considered for connection.
- The HTTP mirror is not authenticated; its contents may be modified in transit. Mirror profiles are never launched.
- Connection profiles are allowlist-validated; external scripts, plugins and file references are rejected, and the configured remote IP must match the selected server.
- OpenVPN is started without shell interpretation and controlled through a random-password-protected loopback management socket.
- The app warns that routes and DNS may change; it does not automatically elevate privileges or install network drivers.
- DevTunnel will not bundle unknown executables or automatically elevate privileges.
- No credentials, personal configuration or downloaded profiles belong in Git.

## License

The project license will be selected before the first public release. Third-party components retain their own licenses.
