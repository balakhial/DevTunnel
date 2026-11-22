"""Tests for managed OpenVPN process and loopback management handling."""

from pathlib import Path
import socket
import subprocess
import threading

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
    def __init__(self, *_args, **_kwargs):
        self.returncode = None
        self.args = _args[0]
        self.kwargs = _kwargs
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
    assert command[command.index("--management") + 1:command.index("--management") + 3] == [
        "127.0.0.1",
        "43210",
    ]
    assert "--management-hold" in command
    assert "--management-query-passwords" in command
    assert "--management-signal" in command
    assert "--auth-nocache" in command
    assert "0.0.0.0" not in command


def test_authenticate_management_sends_random_password():
    server, client = socket.socketpair()
    server.settimeout(1.0)
    client.settimeout(1.0)
    session = OpenVPNSession("openvpn.exe", VALID_PROFILE, "8.8.8.8")
    session._management_socket = client

    def fake_openvpn():
        server.sendall(b"ENTER PASSWORD:")
        received = server.recv(1024)
        assert received == b"secret-management-password\n"
        server.sendall(b"SUCCESS: password is correct\r\n")

    thread = threading.Thread(target=fake_openvpn)
    thread.start()
    session._authenticate_management(
        "secret-management-password",
        timeout=2.0,
    )
    thread.join(timeout=2.0)

    assert not thread.is_alive()
    server.close()
    client.close()


def test_auth_prompt_is_answered_with_vpngate_public_credentials():
    fake_socket = FakeManagementSocket(
        [
            b">PASSWORD:Need 'Auth' username/password\r\n",
        ]
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
        [
            b">PASSWORD:Need 'Auth' username/password SC:1,Enter token\r\n",
        ]
    )
    session = OpenVPNSession("openvpn.exe", VALID_PROFILE, "8.8.8.8")
    session._management_socket = fake_socket

    with pytest.raises(OpenVPNSessionError, match="interactive authentication challenge"):
        session.poll_messages(timeout=0.1)

    assert fake_socket.sent == []


def test_connected_state_is_detected():
    fake_socket = FakeManagementSocket(
        [
            b">STATE:1790000000,CONNECTED,SUCCESS,10.8.0.2,8.8.8.8,443\r\n",
        ]
    )
    session = OpenVPNSession("openvpn.exe", VALID_PROFILE, "8.8.8.8")
    session._management_socket = fake_socket

    session.poll_messages(timeout=0.1)

    assert session.connected is True


def test_stop_sends_graceful_signal_and_cleans_temporary_files(monkeypatch):
    fake_process = FakeProcess()
    fake_socket = FakeManagementSocket()
    captured = {}

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return fake_process

    session = OpenVPNSession(
        "openvpn.exe",
        VALID_PROFILE,
        "8.8.8.8",
        popen_factory=fake_popen,
    )
    session._process = fake_process
    session._management_socket = fake_socket

    temp_dir = Path(__import__("tempfile").mkdtemp(prefix="devtunnel-test-"))
    session._temporary_directory = type(
        "TempDir",
        (),
        {
            "cleanup": lambda self: __import__("shutil").rmtree(temp_dir),
        },
    )()
    profile_path = temp_dir / "selected.ovpn"
    profile_path.write_text(VALID_PROFILE, encoding="utf-8")

    session.stop()

    assert fake_socket.sent == [b"signal SIGTERM\n"]
    assert fake_socket.closed
    assert fake_process.returncode == 0
    assert not temp_dir.exists()
    assert session.process is None


def test_rejects_invalid_profile_before_creating_a_process():
    with pytest.raises(ValueError):
        OpenVPNSession(
            "openvpn.exe",
            VALID_PROFILE.replace("remote 8.8.8.8", "remote 1.1.1.1"),
            "8.8.8.8",
        )
