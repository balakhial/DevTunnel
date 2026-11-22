"""Bounded, safe reachability checks for discovered public VPN relays."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import ipaddress
import math
import platform
import re
import subprocess
from collections.abc import Callable, Iterable

from devtunnel.core.models import VpnServer


DEFAULT_TIMEOUT_MS = 1_200
DEFAULT_MAX_WORKERS = 12
MAX_WORKERS_LIMIT = 32
MAX_TARGETS = 500
_MIN_TIMEOUT_MS = 250
_MAX_TIMEOUT_MS = 5_000

# Windows and many English-language ping outputs use "time=12ms" or "time<1ms".
# Some localized Windows builds translate the word for time but retain "ms".
_LATENCY_PATTERN = re.compile(
    r"(?:time|زمان)\s*([=<])\s*(\d+(?:[.,]\d+)?)\s*(?:ms|میلی.?ثانیه)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class ReachabilityResult:
    """One ICMP probe result for a relay IP address.

    reachable=None means the address was deliberately not probed or the local
    ping utility was unavailable. reachable=False means a probe was attempted
    but no reply was received.
    """

    ip_address: str
    reachable: bool | None
    latency_ms: float | None = None
    error: str | None = None


def _ping_command(ip_address: str, timeout_ms: int) -> list[str]:
    """Build a shell-free ping command for the current operating system."""
    system = platform.system()

    if system == "Windows":
        return ["ping", "-n", "1", "-w", str(timeout_ms), ip_address]

    if system == "Darwin":
        return ["ping", "-c", "1", "-W", str(timeout_ms), ip_address]

    # Linux iputils accepts -W in seconds.
    timeout_seconds = max(1, math.ceil(timeout_ms / 1_000))
    return ["ping", "-c", "1", "-W", str(timeout_seconds), ip_address]


def probe_host(
    ip_address: str,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
) -> ReachabilityResult:
    """Send one bounded ICMP echo request to a globally routable IP only.

    Hosts from provider data are untrusted. Private, loopback, link-local,
    reserved and malformed addresses are never probed.
    """
    try:
        address = ipaddress.ip_address(ip_address)
    except ValueError:
        return ReachabilityResult(
            ip_address=ip_address,
            reachable=None,
            error="invalid_ip_address",
        )

    if not address.is_global:
        return ReachabilityResult(
            ip_address=ip_address,
            reachable=None,
            error="non_public_ip_address",
        )

    if not _MIN_TIMEOUT_MS <= timeout_ms <= _MAX_TIMEOUT_MS:
        raise ValueError(
            f"timeout_ms must be between {_MIN_TIMEOUT_MS} and {_MAX_TIMEOUT_MS}."
        )

    command = _ping_command(str(address), timeout_ms)
    run_options = {
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": timeout_ms / 1_000 + 1.0,
        "check": False,
    }
    if platform.system() == "Windows":
        run_options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    try:
        completed = subprocess.run(command, **run_options)
    except subprocess.TimeoutExpired:
        return ReachabilityResult(
            ip_address=str(address),
            reachable=False,
            error="probe_timeout",
        )
    except FileNotFoundError:
        return ReachabilityResult(
            ip_address=str(address),
            reachable=None,
            error="ping_utility_not_found",
        )
    except OSError as exc:
        return ReachabilityResult(
            ip_address=str(address),
            reachable=None,
            error=f"ping_execution_failed: {exc}",
        )

    if completed.returncode != 0:
        return ReachabilityResult(
            ip_address=str(address),
            reachable=False,
            error="no_icmp_reply",
        )

    output = f"{completed.stdout or ''}\n{completed.stderr or ''}"
    match = _LATENCY_PATTERN.search(output)
    latency_ms: float | None = None

    if match:
        comparator, raw_value = match.groups()
        parsed = float(raw_value.replace(",", "."))
        latency_ms = parsed / 2 if comparator == "<" else parsed

    return ReachabilityResult(
        ip_address=str(address),
        reachable=True,
        latency_ms=latency_ms,
    )


def check_servers_reachability(
    servers: Iterable[VpnServer],
    *,
    max_workers: int = DEFAULT_MAX_WORKERS,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    progress_callback: Callable[[int, int], None] | None = None,
    probe: Callable[[str, int], ReachabilityResult] | None = None,
) -> list[ReachabilityResult]:
    """Check unique server IPs with a hard cap on concurrent ICMP probes.

    Results retain the input server order. Duplicate IP addresses are probed
    once. The progress callback receives (completed_count, total_count).
    """
    if not 1 <= max_workers <= MAX_WORKERS_LIMIT:
        raise ValueError(
            f"max_workers must be between 1 and {MAX_WORKERS_LIMIT}."
        )
    if not _MIN_TIMEOUT_MS <= timeout_ms <= _MAX_TIMEOUT_MS:
        raise ValueError(
            f"timeout_ms must be between {_MIN_TIMEOUT_MS} and {_MAX_TIMEOUT_MS}."
        )

    server_list = list(servers)
    unique_ips = list(dict.fromkeys(server.ip_address for server in server_list))
    if not unique_ips:
        return []
    if len(unique_ips) > MAX_TARGETS:
        raise ValueError(
            f"At most {MAX_TARGETS} unique server IPs can be checked in one run."
        )

    probe_function = probe or probe_host
    results_by_ip: dict[str, ReachabilityResult] = {}
    completed_count = 0

    with ThreadPoolExecutor(
        max_workers=min(max_workers, len(unique_ips)),
        thread_name_prefix="devtunnel-probe",
    ) as executor:
        futures = {
            executor.submit(probe_function, ip_address, timeout_ms): ip_address
            for ip_address in unique_ips
        }

        for future in as_completed(futures):
            ip_address = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = ReachabilityResult(
                    ip_address=ip_address,
                    reachable=None,
                    error=f"probe_failed: {exc}",
                )

            results_by_ip[ip_address] = result
            completed_count += 1

            if progress_callback is not None:
                progress_callback(completed_count, len(unique_ips))

    return [results_by_ip[server.ip_address] for server in server_list]
