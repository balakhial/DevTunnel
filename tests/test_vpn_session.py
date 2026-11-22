"""Tests for managed OpenVPN process and loopback management handling."""

from pathlib import Path
import socket
import subprocess

import pytest

from devtunnel.core.vpn_session import OpenVPNSession, OpenVPNSessionError


VALID_PROFILE = """client
dev tun
proto tcp-client
remote 8.8.8.8 443
nobind
persist-key
persist-tun
remote-cert-tls server
auth-user-pass
<ca>
-----BEGIN CERTIFICATE-----
ZmFrZQ==
-----END CERTIFICATE-----
</ca>
"""


class FakeProcess:
    def __init__(self, command, **kwargs):
        self.returncode = None
        self.command = command
        self.kwargs = kwargs
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9


class FakeManagementSocket:
    def __init__(self, received=None):
        self.received = list(received or [])
        self.sent = []
        self.timeout = None
        self.closed = False

    def settimeout(self, value):
        self.timeout = value

    def recv(self, _size):
        if self.received:
            item = self.received.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        raise socket.timeout()

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


def test_build_command_uses_loopback_management_and_no_shell(tmp_path):
    session = OpenVPNSession(
        Path("openvpn.exe"),
        VALID_PROFILE,
        "8.8.8.8",
    )

    command = session._build_command(
        tmp_path / "selected.ovpn",
        tmp_path / "management.pass",
        43210,
    )

    assert command[0] == "openvpn.exe"
    management_index = command.index("--management")
    assert command[management_index + 1:management_index + 3] == [
        "127.0.0.1",
        "43210",
    ]
    assert "--management-hold" in command
    assert "--management-query-passwords" in command
    assert "--management-signal" in command
    assert "--auth-nocache" in command
    assert "0.0.0.0" not in command


def test_start_uses_authenticated_loopback_and_cleans_temporary_files(
    monkeypatch,
):
    fake_socket = FakeManagementSocket(
        [
            b"ENTER PASSWORD:",
            b"SUCCESS: password is correct\r\n",
        ]
    )
    fake_processes = []

    def fake_popen(command, **kwargs):
        process = FakeProcess(command, **kwargs)
        fake_processes.append(process)
        return process

    monkeypatch.setattr(
        "devtunnel.core.vpn_session.socket.create_connection",
        lambda *_args, **_kwargs: fake_socket,
    )

    session = OpenVPNSession(
        "openvpn.exe",
        VALID_PROFILE,
        "8.8.8.8",
        popen_factory=fake_popen,
    )

    session.start()

    assert len(fake_processes) == 1
    process = fake_processes[0]
    assert process.kwargs["shell"] is False
    assert process.kwargs["stdin"] == subprocess.DEVNULL
    assert process.kwargs["stdout"] == subprocess.DEVNULL

    command = process.command
    assert command[command.index("--management") + 1] == "127.0.0.1"
    assert b"ENTER PASSWORD:" not in b"".join(fake_socket.sent)
    assert len(fake_socket.sent) == 5
    assert fake_socket.sent[0].endswith(b"\n")
    assert fake_socket.sent[1:] == [
        b"version 3\n",
        b"state on\n",
        b"log on all\n",
        b"hold release\n",
    ]

    profile_path = Path(command[command.index("--config") + 1])
    password_path = Path(command[command.index("--management") + 3])
    temp_directory = profile_path.parent

    assert profile_path.exists()
    assert password_path.exists()
    assert "remote 8.8.8.8 443" in profile_path.read_text(encoding="utf-8")
    assert password_path.read_text(encoding="ascii").strip()

    session.stop()

    assert fake_socket.sent[-1] == b"signal SIGTERM\n"
    assert fake_socket.closed
    assert process.returncode == 0
    assert not temp_directory.exists()
    assert session.process is None


def test_auth_prompt_is_answered_with_vpngate_public_credentials():
    fake_socket = FakeManagementSocket(
        [b">PASSWORD:Need 'Auth' username/password\r\n"]
    )
    session = OpenVPNSession("openvpn.exe", VALID_PROFILE, "8.8.8.8")
    session._management_socket = fake_socket

    messages = session.poll_messages(timeout=0.1)

    assert messages == [">PASSWORD:Need 'Auth' username/password"]
    assert fake_socket.sent == [
        b'username "Auth" vpn\n',
        b'password "Auth" vpn\n',
    ]


def test_password_static_challenge_is_not_automatically_answered():
    fake_socket = FakeManagementSocket(
        [b">PASSWORD:Need 'Auth' username/password SC:1,Enter token\r\n"]
    )
    session = OpenVPNSession("openvpn.exe", VALID_PROFILE, "8.8.8.8")
    session._management_socket = fake_socket

    with pytest.raises(OpenVPNSessionError, match="interactive authentication challenge"):
        session.poll_messages(timeout=0.1)

    assert fake_socket.sent == []


def test_connected_state_is_detected():
    fake_socket = FakeManagementSocket(
        [b">STATE:1790000000,CONNECTED,SUCCESS,10.8.0.2,8.8.8.8,443\r\n"]
    )
    session = OpenVPNSession("openvpn.exe", VALID_PROFILE, "8.8.8.8")
    session._management_socket = fake_socket

    session.poll_messages(timeout=0.1)

    assert session.connected is True


def test_rejects_invalid_profile_before_creating_a_process():
    with pytest.raises(ValueError):
        OpenVPNSession(
            "openvpn.exe",
            VALID_PROFILE.replace("remote 8.8.8.8", "remote 1.1.1.1"),
            "8.8.8.8",
        )
