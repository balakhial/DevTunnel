"""Tests for strict VPN Gate OpenVPN profile validation."""

import pytest

from devtunnel.core.profiles import (
    OpenVPNProfileError,
    validate_vpngate_profile,
)


VALID_PROFILE = """client
dev tun
proto tcp-client
remote 8.8.8.8 443
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth-user-pass
cipher AES-128-CBC
auth SHA1
verb 3
<ca>
-----BEGIN CERTIFICATE-----
ZmFrZS1jZXJ0
-----END CERTIFICATE-----
</ca>
"""


def test_valid_profile_is_normalized_and_keeps_inline_ca():
    result = validate_vpngate_profile(VALID_PROFILE, "8.8.8.8")

    assert "remote 8.8.8.8 443" in result
    assert "<ca>" in result
    assert "-----BEGIN CERTIFICATE-----" in result
    assert "auth-user-pass" in result


@pytest.mark.parametrize(
    "unsafe_line",
    [
        "up evil.bat",
        "down evil.bat",
        "plugin bad.dll",
        "script-security 2",
        "management 0.0.0.0 7505",
        "config other.ovpn",
        "include other.conf",
        "route 0.0.0.0 0.0.0.0",
        "setenv LD_PRELOAD evil",
    ],
)
def test_rejects_unsafe_or_unrecognized_directives(unsafe_line):
    profile = VALID_PROFILE.replace("verb 3", f"{unsafe_line}\nverb 3")

    with pytest.raises(OpenVPNProfileError):
        validate_vpngate_profile(profile, "8.8.8.8")


def test_rejects_profile_for_different_server():
    profile = VALID_PROFILE.replace("remote 8.8.8.8 443", "remote 1.1.1.1 443")

    with pytest.raises(OpenVPNProfileError, match="does not match"):
        validate_vpngate_profile(profile, "8.8.8.8")


def test_rejects_remote_hostname_even_when_server_ip_matches():
    profile = VALID_PROFILE.replace("remote 8.8.8.8 443", "remote example.org 443")

    with pytest.raises(OpenVPNProfileError, match="selected server IP"):
        validate_vpngate_profile(profile, "8.8.8.8")


def test_rejects_external_file_references():
    profile = VALID_PROFILE.replace("auth-user-pass", "auth-user-pass C:\\Users\\me\\secret.txt")

    with pytest.raises(OpenVPNProfileError, match="External username"):
        validate_vpngate_profile(profile, "8.8.8.8")


def test_rejects_missing_remote_certificate_validation():
    profile = VALID_PROFILE.replace("remote-cert-tls server\n", "")

    with pytest.raises(OpenVPNProfileError, match="remote-cert-tls"):
        validate_vpngate_profile(profile, "8.8.8.8")


def test_rejects_unclosed_inline_block():
    profile = VALID_PROFILE.replace("</ca>", "")

    with pytest.raises(OpenVPNProfileError, match="Unclosed inline"):
        validate_vpngate_profile(profile, "8.8.8.8")


def test_rejects_unknown_inline_block():
    profile = VALID_PROFILE.replace("<ca>", "<script>")

    with pytest.raises(OpenVPNProfileError, match="not allowed"):
        validate_vpngate_profile(profile, "8.8.8.8")


def test_rejects_invalid_and_non_public_selected_ip():
    with pytest.raises(OpenVPNProfileError):
        validate_vpngate_profile(VALID_PROFILE, "192.168.1.1")
    with pytest.raises(OpenVPNProfileError):
        validate_vpngate_profile(VALID_PROFILE, "not-an-ip")


def test_rejects_empty_or_oversized_profile():
    with pytest.raises(OpenVPNProfileError):
        validate_vpngate_profile("", "8.8.8.8")
    with pytest.raises(OpenVPNProfileError):
        validate_vpngate_profile("x" * (1024 * 1024 + 1), "8.8.8.8")
