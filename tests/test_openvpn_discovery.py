"""Tests for read-only OpenVPN executable discovery."""

from pathlib import Path

from devtunnel.core.openvpn import locate_openvpn_executable


def test_finds_openvpn_from_path_before_install_directories():
    calls = []

    def fake_lookup(command):
        calls.append(command)
        if command == "openvpn.exe":
            return r"C:\Tools\OpenVPN\bin\openvpn.exe"
        return None

    result = locate_openvpn_executable(
        path_lookup=fake_lookup,
        system_name="Windows",
        environment={"ProgramFiles": r"C:\Program Files"},
        file_check=lambda _path: False,
    )

    assert result == Path(r"C:\Tools\OpenVPN\bin\openvpn.exe")
    assert calls == ["openvpn.exe"]


def test_finds_standard_windows_install_location():
    root = Path("/virtual/program-files")
    expected = root / "OpenVPN" / "bin" / "openvpn.exe"

    result = locate_openvpn_executable(
        path_lookup=lambda _command: None,
        system_name="Windows",
        environment={"ProgramFiles": str(root)},
        file_check=lambda path: path == expected,
    )

    assert result == expected


def test_returns_none_when_openvpn_is_not_installed():
    result = locate_openvpn_executable(
        path_lookup=lambda _command: None,
        system_name="Windows",
        environment={},
        file_check=lambda _path: False,
    )

    assert result is None


def test_does_not_search_windows_install_locations_on_other_platforms():
    checks = []

    result = locate_openvpn_executable(
        path_lookup=lambda _command: None,
        system_name="Linux",
        environment={"ProgramFiles": "/not-used"},
        file_check=lambda path: checks.append(path) or True,
    )

    assert result is None
    assert checks == []
