"""Minimal desktop shell for the first DevTunnel milestone."""

import sys

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from devtunnel import __version__
from devtunnel.providers.vpngate import VpnGateError, VpnGateProvider


class ServerRefreshWorker(QThread):
    """Download provider data away from the GUI thread."""

    succeeded = Signal(object)
    failed = Signal(str)

    def run(self) -> None:
        try:
            servers = VpnGateProvider().fetch_servers()
        except VpnGateError as exc:
            self.failed.emit(str(exc))
            return
        self.succeeded.emit(servers)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"DevTunnel {__version__}")
        self.resize(920, 600)
        self._worker: ServerRefreshWorker | None = None

        title = QLabel("DevTunnel")
        title.setObjectName("title")
        subtitle = QLabel("کشف و ارزیابی سرورهای عمومی VPN")
        subtitle.setObjectName("subtitle")

        self.status_label = QLabel("برای دریافت فهرست سرورها روی دکمه زیر کلیک کنید.")
        self.refresh_button = QPushButton("دریافت فهرست سرورها")
        self.refresh_button.clicked.connect(self.refresh_servers)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["کشور", "آدرس IP", "Ping (ms)", "سرعت (Mbps)", "کاربران هم‌زمان", "OpenVPN"]
        )
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        layout = QVBoxLayout()
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(self.status_label)
        layout.addWidget(self.refresh_button)
        layout.addWidget(self.table)

        central = QWidget()
        central.setLayout(layout)
        self.setCentralWidget(central)
        self.setStyleSheet(
            """
            QMainWindow, QWidget { background: #101820; color: #edf2f7; }
            QLabel#title { font-size: 28px; font-weight: 700; color: #55c2d8; }
            QLabel#subtitle { font-size: 14px; color: #a9bac8; padding-bottom: 8px; }
            QPushButton { background: #167d9a; border: 0; border-radius: 7px;
                          padding: 10px 16px; color: white; font-weight: 600; }
            QPushButton:disabled { background: #425563; color: #a9bac8; }
            QTableWidget { background: #17232d; alternate-background-color: #1d2c38;
                           gridline-color: #344653; }
            QHeaderView::section { background: #223542; padding: 8px; border: 0; }
            """
        )

    def refresh_servers(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return

        self.refresh_button.setEnabled(False)
        self.status_label.setText("در حال دریافت اطلاعات از VPN Gate…")
        self._worker = ServerRefreshWorker(self)
        self._worker.succeeded.connect(self._show_servers)
        self._worker.failed.connect(self._show_error)
        self._worker.finished.connect(lambda: self.refresh_button.setEnabled(True))
        self._worker.start()

    def _show_servers(self, servers: list) -> None:
        self.table.setRowCount(len(servers))
        for row_index, server in enumerate(servers):
            values = [
                server.country,
                server.ip_address,
                str(server.ping_ms) if server.ping_ms is not None else "—",
                f"{server.speed_mbps:.2f}",
                str(server.sessions),
                "بله" if server.supports_openvpn else "خیر",
            ]
            for column, value in enumerate(values):
                self.table.setItem(row_index, column, QTableWidgetItem(value))

        self.status_label.setText(f"{len(servers)} سرور از VPN Gate دریافت شد. هنوز هیچ اتصالی برقرار نشده است.")

    def _show_error(self, message: str) -> None:
        self.status_label.setText("دریافت فهرست سرورها ناموفق بود.")
        QMessageBox.warning(self, "خطا در دریافت اطلاعات", message)


def main() -> int:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()
