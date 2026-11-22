"""Tests for bounded and safe relay reachability diagnostics."""

from concurrent.futures import ThreadPoolExecutor
import subprocess
import threading
import time

import pytest

from devtunnel.core import diagnostics
from devtunnel.core.diagnostics import (
    ReachabilityResult,
    check_servers_reachability,
    probe_host,
)
from devtunnel.core.models import VpnServer


def make_server(ip_address: str) -> VpnServer:
    return VpnServer(
        host_name=f"relay-{ip_address}",
        ip_address=ip_address,
        score=100,
        ping_ms=None,
        speed_bps=10_000_000,
        country="Test",
        country_code="TS",
        sessions=1,
        uptime_seconds=100,
        total_users=10,
        total_traffic_bytes=100,
        log_policy="unknown",
        operator="test",
    )


@pytest.mark.parametrize(
    "ip_address",
    [
        "not-an-ip",
        "10.0.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "192.168.1.10",
        "::1",
    ],
)
def test_probe_does_not_send_packets_to_invalid_or_non_public_addresses(
    monkeypatch,
    ip_address,
):
    def unexpected_run(*_args, **_kwargs):
        pytest.fail("subprocess.run must not be called for an unsafe address")

    monkeypatch.setattr(diagnostics.subprocess, "run", unexpected_run)

    result = probe_host(ip_address)

    assert result.reachable is None
    assert result.latency_ms is None
    assert result.error in {"invalid_ip_address", "non_public_ip_address"}


def test_probe_parses_windows_style_latency(monkeypatch):
    class Completed:
        returncode = 0
        stdout = "Reply from 8.8.8.8: bytes=32 time=17ms TTL=117"
        stderr = ""

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return Completed()

    monkeypatch.setattr(diagnostics.subprocess, "run", fake_run)
    monkeypatch.setattr(diagnostics.platform, "system", lambda: "Windows")

    result = probe_host("8.8.8.8", timeout_ms=900)

    assert result.reachable is True
    assert result.latency_ms == 17
    assert captured["command"] == ["ping", "-n", "1", "-w", "900", "8.8.8.8"]
    assert captured["kwargs"]["timeout"] == pytest.approx(1.9)
    assert captured["kwargs"]["capture_output"] is True


def test_probe_handles_sub_millisecond_reply(monkeypatch):
    class Completed:
        returncode = 0
        stdout = "Reply from 1.1.1.1: bytes=32 time<1ms TTL=57"
        stderr = ""

    monkeypatch.setattr(
        diagnostics.subprocess,
        "run",
        lambda *_args, **_kwargs: Completed(),
    )

    result = probe_host("1.1.1.1")

    assert result.reachable is True
    assert result.latency_ms == 0.5


def test_probe_reports_timeout(monkeypatch):
    def fake_run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("ping", 2)

    monkeypatch.setattr(diagnostics.subprocess, "run", fake_run)

    result = probe_host("8.8.8.8")

    assert result.reachable is False
    assert result.error == "probe_timeout"


def test_concurrent_checks_are_bounded_and_keep_input_order():
    servers = [make_server(f"8.8.8.{index}") for index in range(1, 9)]
    lock = threading.Lock()
    active = 0
    maximum_active = 0
    progress = []

    def fake_probe(ip_address, _timeout_ms):
        nonlocal active, maximum_active
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
        time.sleep(0.01)
        with lock:
            active -= 1
        return ReachabilityResult(ip_address, True, 10.0)

    results = check_servers_reachability(
        servers,
        max_workers=3,
        progress_callback=lambda done, total: progress.append((done, total)),
        probe=fake_probe,
    )

    assert maximum_active <= 3
    assert [result.ip_address for result in results] == [
        server.ip_address for server in servers
    ]
    assert len(progress) == len(servers)
    assert progress[-1] == (len(servers), len(servers))


def test_duplicate_ips_are_probed_once_but_keep_duplicate_results():
    servers = [make_server("8.8.8.8"), make_server("8.8.8.8")]
    calls = []

    def fake_probe(ip_address, _timeout_ms):
        calls.append(ip_address)
        return ReachabilityResult(ip_address, True, 3.0)

    results = check_servers_reachability(servers, probe=fake_probe)

    assert calls == ["8.8.8.8"]
    assert len(results) == 2
    assert results[0] == results[1]


@pytest.mark.parametrize("max_workers", [0, 33])
def test_concurrency_limit_is_validated(max_workers):
    with pytest.raises(ValueError):
        check_servers_reachability(
            [make_server("8.8.8.8")],
            max_workers=max_workers,
            probe=lambda ip, _timeout: ReachabilityResult(ip, True, 1.0),
        )
