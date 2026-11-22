"""Strict validation for VPN Gate OpenVPN client profiles."""

from __future__ import annotations

import ipaddress
import re
import shlex


MAX_PROFILE_BYTES = 1024 * 1024
MAX_PROFILE_LINES = 20_000

_ALLOWED_DIRECTIVES = {
    "auth",
    "auth-nocache",
    "auth-retry",
    "auth-user-pass",
    "ca",
    "cert",
    "cipher",
    "client",
    "connect-retry",
    "connect-retry-max",
    "connect-timeout",
    "data-ciphers",
    "data-ciphers-fallback",
    "dev",
    "explicit-exit-notify",
    "keepalive",
    "key",
    "key-direction",
    "mute",
    "mute-replay-warnings",
    "nobind",
    "persist-key",
    "persist-tun",
    "proto",
    "pull",
    "remote",
    "remote-cert-tls",
    "reneg-sec",
    "resolv-retry",
    "route-delay",
    "route-method",
    "sndbuf",
    "rcvbuf",
    "tls-auth",
    "tls-client",
    "tls-crypt",
    "tls-version-min",
    "tun-mtu",
    "verb",
}

_ALLOWED_INLINE_BLOCKS = {
    "ca",
    "cert",
    "extra-certs",
    "key",
    "tls-auth",
    "tls-crypt",
    "dh",
}

_TAG_PATTERN = re.compile(r"^</?([a-z][a-z0-9-]*)>$", re.IGNORECASE)


class OpenVPNProfileError(ValueError):
    """Raised when a profile is unsafe or does not match its selected relay."""


def validate_vpngate_profile(profile_text: str, expected_ip: str) -> str:
    """Validate and normalize a VPN Gate profile for one specific server.

    The profile must be the result of an authenticated HTTPS fetch from the
    official VPN Gate API. Only a deliberately small set of OpenVPN directives
    and inline cryptographic material are accepted. External files, scripts,
    plugins, nested configs, management options, and alternate remotes are
    rejected.
    """
    try:
        expected_address = ipaddress.ip_address(expected_ip)
    except ValueError as exc:
        raise OpenVPNProfileError("The selected server IP address is invalid.") from exc

    if not expected_address.is_global:
        raise OpenVPNProfileError("The selected server IP address is not public.")

    if not isinstance(profile_text, str):
        raise OpenVPNProfileError("The OpenVPN profile must be text.")

    encoded = profile_text.encode("utf-8")
    if not encoded or len(encoded) > MAX_PROFILE_BYTES:
        raise OpenVPNProfileError("The OpenVPN profile is empty or exceeds 1 MiB.")
    if "\x00" in profile_text:
        raise OpenVPNProfileError("The OpenVPN profile contains a NUL byte.")

    lines = profile_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if len(lines) > MAX_PROFILE_LINES:
        raise OpenVPNProfileError("The OpenVPN profile contains too many lines.")

    output: list[str] = []
    remote_count = 0
    has_client = False
    has_tun = False
    has_ca = False
    has_remote_cert_check = False
    inline_block: str | None = None
    inline_lines: list[str] = []

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue

        if inline_block is not None:
            if line.lower() == f"</{inline_block}>":
                if not inline_lines:
                    raise OpenVPNProfileError(
                        f"Inline <{inline_block}> block is empty (line {line_number})."
                    )
                output.append(f"</{inline_block}>")
                if inline_block == "ca":
                    has_ca = True
                inline_block = None
                inline_lines = []
                continue

            if line.startswith("<") or line.startswith(">"):
                raise OpenVPNProfileError(
                    f"Nested or unexpected inline block on line {line_number}."
                )
            output.append(raw_line)
            inline_lines.append(line)
            continue

        if line.startswith("#") or line.startswith(";"):
            continue

        if line.startswith("<"):
            match = _TAG_PATTERN.fullmatch(line)
            if not match or line.startswith("</"):
                raise OpenVPNProfileError(
                    f"Invalid inline block tag on line {line_number}."
                )
            tag = match.group(1).lower()
            if tag not in _ALLOWED_INLINE_BLOCKS:
                raise OpenVPNProfileError(
                    f"Inline <{tag}> blocks are not allowed."
                )
            inline_block = tag
            inline_lines = []
            output.append(f"<{tag}>")
            continue

        try:
            tokens = shlex.split(line, comments=True, posix=True)
        except ValueError as exc:
            raise OpenVPNProfileError(
                f"Invalid quoting on profile line {line_number}."
            ) from exc

        if not tokens:
            continue

        directive = tokens[0].lower()
        arguments = tokens[1:]

        if directive not in _ALLOWED_DIRECTIVES:
            raise OpenVPNProfileError(
                f"OpenVPN directive '{directive}' is not permitted."
            )

        if directive == "remote":
            if len(arguments) not in (2, 3):
                raise OpenVPNProfileError(
                    f"Invalid remote directive on line {line_number}."
                )
            try:
                remote_address = ipaddress.ip_address(arguments[0])
            except ValueError as exc:
                raise OpenVPNProfileError(
                    "The profile remote must use the selected server IP directly."
                ) from exc
            if remote_address != expected_address:
                raise OpenVPNProfileError(
                    "The profile remote does not match the selected server IP."
                )
            try:
                port = int(arguments[1])
            except ValueError as exc:
                raise OpenVPNProfileError(
                    f"Invalid remote port on line {line_number}."
                ) from exc
            if not 1 <= port <= 65535:
                raise OpenVPNProfileError(
                    f"Remote port is out of range on line {line_number}."
                )
            if len(arguments) == 3 and arguments[2].lower() not in {
                "tcp",
                "udp",
                "tcp-client",
                "udp4",
                "udp6",
            }:
                raise OpenVPNProfileError(
                    f"Unsupported remote transport on line {line_number}."
                )
            remote_count += 1

        elif directive == "auth-user-pass":
            if arguments:
                raise OpenVPNProfileError(
                    "External username/password files are not permitted."
                )

        elif directive in {"ca", "cert", "key", "tls-auth", "tls-crypt"}:
            raise OpenVPNProfileError(
                f"External file paths for '{directive}' are not permitted; "
                "use inline cryptographic blocks only."
            )

        elif directive == "dev":
            if len(arguments) != 1 or arguments[0].lower() != "tun":
                raise OpenVPNProfileError("Only the OpenVPN TUN device is permitted.")
            has_tun = True

        elif directive == "client":
            if arguments:
                raise OpenVPNProfileError("The client directive takes no arguments.")
            has_client = True

        elif directive == "remote-cert-tls":
            if len(arguments) != 1 or arguments[0].lower() != "server":
                raise OpenVPNProfileError(
                    "The profile must verify that the remote certificate is for a server."
                )
            has_remote_cert_check = True

        output.append(" ".join(shlex.quote(token) for token in tokens))

    if inline_block is not None:
        raise OpenVPNProfileError(
            f"Unclosed inline <{inline_block}> block."
        )

    if remote_count == 0:
        raise OpenVPNProfileError("The profile has no remote matching the selected server.")
    if not has_client or not has_tun:
        raise OpenVPNProfileError("The profile must contain client and dev tun.")
    if not has_ca:
        raise OpenVPNProfileError("The profile must contain an inline CA certificate.")
    if not has_remote_cert_check:
        raise OpenVPNProfileError(
            "The profile must contain remote-cert-tls server."
        )

    return "\n".join(output).strip() + "\n"
