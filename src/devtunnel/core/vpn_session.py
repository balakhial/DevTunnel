"""Managed OpenVPN subprocess with an authenticated loopback management channel."""

from __future__ import annotations

import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
from collections.abc import Callable

from devtunnel.core.profiles import validate_vpngate_profile


class OpenVPNSessionError(RuntimeError):
    """Raised when an OpenVPN session cannot be started or controlled."""


class OpenVPNSession:
    """Own one OpenVPN process and its private temporary connection files."""

    def __init__(
        self,
        executable: str | Path,
        profile_text: str,
        server_ip: str,
        *,
        popen_factory: Callable[..., subprocess.Popen] | None = None,
    ) -> None:
        self.executable = Path(executable)
        self.server_ip = server_ip
        self.profile_text = validate_vpngate_profile(
            profile_text,
            expected_ip=server_ip,
        )
        self._popen_factory = popen_factory or subprocess.Popen
        self._temporary_directory: tempfile.TemporaryDirectory | None = None
        self._process: subprocess.Popen | None = None
        self._management_socket: socket.socket | None = None
        self._management_buffer = b""
        self._management_password = secrets.token_urlsafe(32)
        self._log_lines: list[str] = []
        self._connected = False

    @property
    def process(self) -> subprocess.Popen | None:
        return self._process

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def recent_logs(self) -> tuple[str, ...]:
        return tuple(self._log_lines[-30:])

    def _build_command(
        self,
        profile_path: Path,
        password_path: Path,
        port: int,
    ) -> list[str]:
        return [
            str(self.executable),
            "--config",
            str(profile_path),
            "--management",
            "127.0.0.1",
            str(port),
            str(password_path),
            "--management-hold",
            "--management-query-passwords",
            "--management-forget-disconnect",
            "--management-signal",
            "--management-log-cache",
            "100",
            "--auth-nocache",
            "--verb",
            "3",
        ]

    @staticmethod
    def _free_loopback_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            return int(listener.getsockname()[1])

    def start(self, *, management_timeout: float = 15.0) -> None:
        if self._process is not None:
            raise OpenVPNSessionError("This OpenVPN session has already been started.")

        self._temporary_directory = tempfile.TemporaryDirectory(
            prefix="devtunnel-openvpn-"
        )
        work_dir = Path(self._temporary_directory.name)
        profile_path = work_dir / "selected-server.ovpn"
        password_path = work_dir / "management.pass"

        profile_path.write_text(
            self.profile_text,
            encoding="utf-8",
            newline="\n",
        )
        password_path.write_text(
            self._management_password + "\n",
            encoding="ascii",
            newline="\n",
        )
        try:
            os.chmod(profile_path, 0o600)
            os.chmod(password_path, 0o600)
        except OSError:
            # On Windows, inherited permissions on the per-user temp directory
            # provide the access boundary; chmod is best-effort there.
            pass

        log_path = work_dir / "openvpn.log"
        port = self._free_loopback_port()
        command = self._build_command(profile_path, password_path, port)

        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        try:
            self._process = self._popen_factory(
                command,
                cwd=str(work_dir),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                creationflags=creationflags,
                shell=False,
            )
            self._management_socket = self._connect_management(
                port,
                timeout=management_timeout,
            )
            self._authenticate_management(
                self._management_password,
                timeout=5.0,
            )
            self._send_command("version 3")
            self._send_command("state on")
            self._send_command("log on all")
            self._send_command("hold release")
        except Exception as exc:
            self.stop()
            if isinstance(exc, OpenVPNSessionError):
                raise
            raise OpenVPNSessionError(
                f"Could not start or control OpenVPN: {exc}"
            ) from exc

    def _connect_management(
        self,
        port: int,
        *,
        timeout: float,
    ) -> socket.socket:
        deadline = time.monotonic() + timeout
        last_error: OSError | None = None

        while time.monotonic() < deadline:
            if self._process is not None and self._process.poll() is not None:
                raise OpenVPNSessionError(
                    "OpenVPN exited before its local management interface became ready. "
                    "Check the OpenVPN version, adapter driver and Windows service."
                )
            try:
                connection = socket.create_connection(
                    ("127.0.0.1", port),
                    timeout=0.5,
                )
                connection.settimeout(0.5)
                return connection
            except OSError as exc:
                last_error = exc
                time.sleep(0.15)

        raise OpenVPNSessionError(
            "Timed out while opening the password-protected local OpenVPN "
            f"management interface. Last error: {last_error}"
        )

    def _authenticate_management(
        self,
        password: str,
        *,
        timeout: float,
    ) -> None:
        if self._management_socket is None:
            raise OpenVPNSessionError("The local management socket is unavailable.")

        deadline = time.monotonic() + timeout
        data = bytearray()
        password_sent = False

        while time.monotonic() < deadline:
            if b"ENTER PASSWORD:" in data and not password_sent:
                self._management_socket.sendall(password.encode("ascii") + b"\n")
                password_sent = True

            if password_sent and b"SUCCESS:" in data:
                return

            if b"AUTH_FAILED" in data or b"ERROR:" in data:
                raise OpenVPNSessionError(
                    "OpenVPN rejected authentication to its local management interface."
                )

            try:
                chunk = self._management_socket.recv(4096)
            except socket.timeout:
                continue

            if not chunk:
                raise OpenVPNSessionError(
                    "OpenVPN closed the local management interface during authentication."
                )
            data.extend(chunk)

        raise OpenVPNSessionError(
            "Timed out while authenticating to the local OpenVPN management interface."
        )

    def _send_command(self, command: str) -> None:
        if self._management_socket is None:
            raise OpenVPNSessionError("The local management socket is unavailable.")
        if "\n" in command or "\r" in command:
            raise ValueError("Management commands must be a single line.")
        self._management_socket.sendall(command.encode("ascii") + b"\n")

    def poll_messages(self, timeout: float = 0.5) -> list[str]:
        """Read management events and answer VPN Gate's documented credentials."""
        if self._management_socket is None:
            return []

        self._management_socket.settimeout(timeout)
        try:
            chunk = self._management_socket.recv(8192)
        except socket.timeout:
            return []

        if not chunk:
            if self._process is not None and self._process.poll() is None:
                raise OpenVPNSessionError(
                    "The OpenVPN management connection was lost."
                )
            return []

        self._management_buffer += chunk
        lines = self._management_buffer.split(b"\n")
        self._management_buffer = lines.pop()
        messages = [
            line.decode("utf-8", errors="replace").strip()
            for line in lines
            if line.strip()
        ]

        for message in messages:
            if message.startswith(">PASSWORD:Need 'Auth' username/password"):
                if " SC:" in message:
                    raise OpenVPNSessionError(
                        "The VPN server requires an interactive authentication challenge "
                        "that DevTunnel does not yet support."
                    )
                # VPN Gate publicly documents these common relay credentials.
                self._send_command('username "Auth" vpn')
                self._send_command('password "Auth" vpn')
            elif message.startswith(">PASSWORD:Need 'Auth' username"):
                self._send_command('username "Auth" vpn')
            elif message.startswith(">PASSWORD:Need 'Private Key'"):
                raise OpenVPNSessionError(
                    "This profile requires a private-key passphrase. "
                    "DevTunnel does not store or invent private-key passwords."
                )
            elif message.startswith(">STATE:"):
                fields = message[len(">STATE:"):].split(",")
                if len(fields) > 1:
                    self._connected = fields[1] == "CONNECTED"
                    if fields[1] == "EXITING":
                        self._connected = False
            elif message.startswith(">LOG:"):
                # Keep recent diagnostics in memory only. Never expose raw
                # management output, credentials or key material in the UI.
                self._log_lines.append(message[:1000])
                self._log_lines = self._log_lines[-30:]

        return messages

    def stop(self, *, graceful_timeout: float = 15.0) -> None:
        process = self._process

        if process is not None and process.poll() is None:
            if self._management_socket is not None:
                try:
                    self._send_command("signal SIGTERM")
                except OSError:
                    pass

            try:
                process.wait(timeout=graceful_timeout)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3.0)

        if self._management_socket is not None:
            try:
                self._management_socket.close()
            except OSError:
                pass
            self._management_socket = None

        self._connected = False
        self._process = None

        if self._temporary_directory is not None:
            self._temporary_directory.cleanup()
            self._temporary_directory = None
