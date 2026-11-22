"""Headless integration tests for the PySide6 desktop window."""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import csv

import pytest
from PySide6.QtWidgets import QApplication

from devtunnel.app import MainWindow
from devtunnel.core.diagnostics import ReachabilityResult
from devtunnel.core.models import VpnServer


@pytest.fixture(scope="session")
def qapp():
    application = QApplication.instance() or QApplication([])
    yield application


def make_server(
    *,
    ip_address: str,
    country: str,
    speed_bps: int,
    has_openvpn: bool,
) -> VpnServer:
    return VpnServer(
        host_name=f"relay-{ip_address}",
        ip_address=ip_address,
        score=100,
        ping_ms=30,
        speed_bps=speed_bps,
        country=country,
        country_code="XX",
        sessions=5,
        uptime_seconds=1000,
        total_users=100,
        total_traffic_bytes=1000,
        log_policy="unknown",
        operator="test",
        openvpn_config_base64="Y29uZmln" if has_openvpn else None,
    )


def test_window_initializes_without_enabling_server_actions(qapp):
    window = MainWindow()

    assert window.table.columnCount() == 8
    assert window.table.rowCount() == 0
    assert not window.check_button.isEnabled()
    assert not window.export_button.isEnabled()
    assert window.openvpn_check_button.isEnabled()

    window.close()


def test_filtering_sorting_and_openvpn_filter_work_together(qapp):
    window = MainWindow()
    servers = [
        make_server(
            ip_address="8.8.8.8",
            country="Japan",
            speed_bps=50_000_000,
            has_openvpn=True,
        ),
        make_server(
            ip_address="1.1.1.1",
            country="Canada",
            speed_bps=10_000_000,
            has_openvpn=False,
        ),
    ]

    window._show_servers(servers, "https://www.vpngate.net/api/iphone/")
    window._set_busy(False)

    assert window.table.rowCount() == 2
    window._on_header_clicked(3)
    assert window.table.item(0, 1).text() == "1.1.1.1"

    window.openvpn_filter.setChecked(True)
    assert window.table.rowCount() == 1
    assert window.table.item(0, 1).text() == "8.8.8.8"

    window.close()


def test_reachability_result_is_rendered_in_its_own_columns(qapp):
    window = MainWindow()
    server = make_server(
        ip_address="8.8.8.8",
        country="Japan",
        speed_bps=50_000_000,
        has_openvpn=True,
    )
    window._reachability[server.ip_address] = ReachabilityResult(
        server.ip_address,
        True,
        6.25,
    )

    window._populate_table([server])

    assert window.table.item(0, 6).text() == "در دسترس"
    assert window.table.item(0, 7).text() == "6.2"

    window.close()


def test_csv_button_exports_currently_filtered_rows(qapp, monkeypatch, tmp_path):
    window = MainWindow()
    server = make_server(
        ip_address="8.8.8.8",
        country="Japan",
        speed_bps=50_000_000,
        has_openvpn=True,
    )
    window._show_servers([server], "https://www.vpngate.net/api/iphone/")
    window._set_busy(False)
    destination = tmp_path / "current-servers.csv"

    monkeypatch.setattr(
        "devtunnel.app.QFileDialog.getSaveFileName",
        lambda *_args: (str(destination), "CSV Files (*.csv)"),
    )

    window.export_current_servers()

    assert destination.exists()
    with destination.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.reader(handle))
    assert len(rows) == 2
    assert rows[1][1] == "8.8.8.8"

    window.close()



def test_openvpn_check_reports_found_executable(qapp, monkeypatch):
    window = MainWindow()
    executable = r"C:\Program Files\OpenVPN\bin\openvpn.exe"
    monkeypatch.setattr(
        "devtunnel.app.locate_openvpn_executable",
        lambda: executable,
    )

    window.check_openvpn_installation()

    assert executable in window.status_label.text()
    assert "هیچ اتصال VPN برقرار نشده" in window.status_label.text()
    window.close()


def test_openvpn_check_reports_missing_executable(qapp, monkeypatch):
    window = MainWindow()
    monkeypatch.setattr(
        "devtunnel.app.locate_openvpn_executable",
        lambda: None,
    )

    window.check_openvpn_installation()

    assert "پیدا نشد" in window.status_label.text()
    window.close()
