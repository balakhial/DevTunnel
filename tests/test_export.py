"""Tests for atomic and safe server CSV export."""

import csv

import pytest

from devtunnel.core.diagnostics import ReachabilityResult
from devtunnel.core.export import export_servers_to_csv
from devtunnel.core.models import VpnServer


def make_server(country: str = "Japan") -> VpnServer:
    return VpnServer(
        host_name="relay-example",
        ip_address="8.8.8.8",
        score=100,
        ping_ms=25,
        speed_bps=12_500_000,
        country=country,
        country_code="JP",
        sessions=4,
        uptime_seconds=1000,
        total_users=10,
        total_traffic_bytes=100,
        log_policy="unknown",
        operator="test",
        openvpn_config_base64="c2VjcmV0LWNvbmZpZw==",
    )


def test_export_writes_utf8_csv_without_exporting_profiles(tmp_path):
    destination = tmp_path / "servers.csv"
    server = make_server()
    count = export_servers_to_csv(
        [server],
        destination,
        reachability={
            server.ip_address: ReachabilityResult(
                server.ip_address,
                True,
                7.5,
            )
        },
    )

    assert count == 1
    content = destination.read_text(encoding="utf-8-sig")
    assert "Japan" in content
    assert "8.8.8.8" in content
    assert "در دسترس" in content
    assert "7.5" in content
    assert server.openvpn_config_base64 not in content

    with destination.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.reader(handle))
    assert len(rows) == 2
    assert rows[1][3] == "12.50"


@pytest.mark.parametrize(
    "country",
    [
        '=HYPERLINK("https://bad.example")',
        '   =HYPERLINK("https://bad.example")',
        "+SUM(1,1)",
        "@malicious",
    ],
)
def test_export_escapes_spreadsheet_formula_prefixes(tmp_path, country):
    destination = tmp_path / "servers.csv"

    export_servers_to_csv(
        [make_server(country=country)],
        destination,
    )

    with destination.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.reader(handle))

    assert rows[1][0].startswith("'")


def test_export_supports_empty_lists(tmp_path):
    destination = tmp_path / "empty.csv"

    count = export_servers_to_csv([], destination)

    assert count == 0
    with destination.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.reader(handle))
    assert len(rows) == 1


def test_export_fails_when_parent_directory_is_missing(tmp_path):
    missing_destination = tmp_path / "missing" / "servers.csv"

    with pytest.raises(FileNotFoundError):
        export_servers_to_csv([], missing_destination)
