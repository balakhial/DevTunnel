
"""Desktop application for DevTunnel server discovery."""

import sys
import traceback

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from devtunnel import __version__
from devtunnel.providers.vpngate import (
    VPN_GATE_MIRROR_API_URL,
    VpnGateError,
    VpnGateProvider,
)


class ServerRefreshWorker(QThread):
    """Download server information outside the GUI thread."""

    succeeded = Signal(object, str)
    failed = Signal(str)

    def run(self) -> None:
        provider = VpnGateProvider()

        try:
            servers = provider.fetch_servers()
            self.succeeded.emit(
                servers,
                provider.last_source or "",
            )
        except Exception:
            self.failed.emit(traceback.format_exc())


class ServerTableItem(QTableWidgetItem):
    """Sort numeric values numerically."""

    def __lt__(self, other: QTableWidgetItem) -> bool:
        left = self.data(Qt.ItemDataRole.UserRole)
        right = other.data(Qt.ItemDataRole.UserRole)

        if left is not None and right is not None:
            try:
                return float(left) < float(right)
            except (TypeError, ValueError):
                pass

        return super().__lt__(other)


class MainWindow(QMainWindow):

    def __init__(self) -> None:
        super().__init__()

        self.setWindowTitle(f"DevTunnel {__version__}")
        self.resize(1050, 680)

        self._worker: ServerRefreshWorker | None = None
        self._servers: list = []
        self._source = ""

        # --------------------------------------------------
        # Header
        # --------------------------------------------------

        title = QLabel("DevTunnel")
        title.setObjectName("title")

        subtitle = QLabel("کشف و ارزیابی سرورهای عمومی VPN")
        subtitle.setObjectName("subtitle")

        self.status_label = QLabel(
            "برای دریافت فهرست سرورها روی دکمه زیر کلیک کنید."
        )
        self.status_label.setWordWrap(True)

        # --------------------------------------------------
        # Progress bar
        # --------------------------------------------------

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(8)

        # --------------------------------------------------
        # Refresh button
        # --------------------------------------------------

        self.refresh_button = QPushButton(
            "دریافت فهرست سرورها"
        )
        self.refresh_button.clicked.connect(
            self.refresh_servers
        )

        # --------------------------------------------------
        # Filters
        # --------------------------------------------------

        filter_layout = QHBoxLayout()

        country_label = QLabel("کشور:")

        self.country_filter = QComboBox()
        self.country_filter.addItem("همه کشورها")
        self.country_filter.currentIndexChanged.connect(
            self._apply_filters
        )

        self.openvpn_filter = QCheckBox(
            "فقط سرورهای دارای OpenVPN"
        )
        self.openvpn_filter.stateChanged.connect(
            self._apply_filters
        )

        filter_layout.addWidget(country_label)
        filter_layout.addWidget(self.country_filter)
        filter_layout.addWidget(self.openvpn_filter)
        filter_layout.addStretch()

        self.result_label = QLabel("تعداد سرورها: ۰")

        # --------------------------------------------------
        # Server table
        # --------------------------------------------------

        self.table = QTableWidget(0, 6)

        self.table.setHorizontalHeaderLabels(
            [
                "کشور",
                "آدرس IP",
                "Ping (ms)",
                "سرعت (Mbps)",
                "کاربران هم‌زمان",
                "OpenVPN",
            ]
        )

        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )

        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )

        self.table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )

        self.table.setAlternatingRowColors(True)

        self.table.setSortingEnabled(False)

        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )

        self.table.horizontalHeader().setSortIndicatorShown(True)

        # --------------------------------------------------
        # Main layout
        # --------------------------------------------------

        layout = QVBoxLayout()

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(self.status_label)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.refresh_button)
        layout.addLayout(filter_layout)
        layout.addWidget(self.result_label)
        layout.addWidget(self.table)

        central = QWidget()
        central.setLayout(layout)

        self.setCentralWidget(central)

        # --------------------------------------------------
        # Styles
        # --------------------------------------------------

        self.setStyleSheet(
            """
            QMainWindow, QWidget {
                background: #101820;
                color: #edf2f7;
            }

            QLabel#title {
                font-size: 28px;
                font-weight: 700;
                color: #55c2d8;
            }

            QLabel#subtitle {
                font-size: 14px;
                color: #a9bac8;
                padding-bottom: 8px;
            }

            QPushButton {
                background: #167d9a;
                border: 0;
                border-radius: 7px;
                padding: 10px 16px;
                color: white;
                font-weight: 600;
            }

            QPushButton:disabled {
                background: #425563;
                color: #a9bac8;
            }

            QComboBox {
                background: #223542;
                border: 1px solid #425563;
                border-radius: 5px;
                padding: 6px;
                min-width: 150px;
            }

            QCheckBox {
                spacing: 8px;
            }

            QTableWidget {
                background: #17232d;
                alternate-background-color: #1d2c38;
                gridline-color: #344653;
                selection-background-color: #167d9a;
            }

            QHeaderView::section {
                background: #223542;
                padding: 8px;
                border: 0;
            }

            QProgressBar {
                background: #223542;
                border: none;
                border-radius: 4px;
            }

            QProgressBar::chunk {
                background: #55c2d8;
                border-radius: 4px;
            }
            """
        )

    # ======================================================
    # Refresh servers
    # ======================================================

    def refresh_servers(self) -> None:

        if (
            self._worker is not None
            and self._worker.isRunning()
        ):
            return

        self.refresh_button.setEnabled(False)

        self.progress_bar.setVisible(True)

        self.status_label.setText(
            "در حال اتصال به VPN Gate و دریافت فهرست سرورها…"
        )

        self._worker = ServerRefreshWorker(self)

        self._worker.succeeded.connect(
            self._handle_success
        )

        self._worker.failed.connect(
            self._show_error
        )

        self._worker.finished.connect(
            self._on_refresh_finished
        )

        self._worker.start()

    # ======================================================
    # Worker completion
    # ======================================================

    def _on_refresh_finished(self) -> None:

        self.progress_bar.setVisible(False)
        self.refresh_button.setEnabled(True)

    def _handle_success(
        self,
        servers: list,
        source: str,
    ) -> None:

        try:
            self._show_servers(servers, source)

        except Exception:
            error = traceback.format_exc()

            self.status_label.setText(
                "خطا هنگام نمایش اطلاعات سرورها."
            )

            QMessageBox.critical(
                self,
                "خطای نمایش اطلاعات",
                error,
            )

    # ======================================================
    # Display servers
    # ======================================================

    def _show_servers(
        self,
        servers: list,
        source: str,
    ) -> None:

        self._servers = list(servers)
        self._source = source

        current_country = self.country_filter.currentText()

        countries = sorted(
            {
                server.country
                for server in self._servers
                if server.country
            },
            key=str.casefold,
        )

        self.country_filter.blockSignals(True)

        self.country_filter.clear()
        self.country_filter.addItem("همه کشورها")
        self.country_filter.addItems(countries)

        country_index = self.country_filter.findText(
            current_country
        )

        if country_index >= 0:
            self.country_filter.setCurrentIndex(
                country_index
            )

        self.country_filter.blockSignals(False)

        self._apply_filters()

        if source == VPN_GATE_MIRROR_API_URL:

            self.status_label.setText(
                f"{len(servers)} سرور از آینه HTTP دریافت شد. "
                "هشدار: اطلاعات این مسیر احراز هویت نشده و "
                "برای اتصال VPN قابل اعتماد نیست."
            )

        else:

            self.status_label.setText(
                f"{len(servers)} سرور از API رسمی VPN Gate دریافت شد. "
                "هنوز هیچ اتصالی برقرار نشده است."
            )

    # ======================================================
    # Apply filters
    # ======================================================

    def _apply_filters(self, *_args) -> None:

        selected_country = self.country_filter.currentText()
        only_openvpn = self.openvpn_filter.isChecked()

        filtered = [
            server
            for server in self._servers
            if (
                selected_country == "همه کشورها"
                or server.country == selected_country
            )
            and (
                not only_openvpn
                or server.supports_openvpn
            )
        ]

        self._populate_table(filtered)

        self.result_label.setText(
            f"تعداد سرورها: {len(filtered)} "
            f"از {len(self._servers)}"
        )

    # ======================================================
    # Populate table
    # ======================================================

    def _populate_table(self, servers: list) -> None:
        self.table.setSortingEnabled(False)
        self.table.clearContents()
        self.table.setRowCount(len(servers))

        for row_index, server in enumerate(servers):
            ping = (
                str(server.ping_ms)
                if server.ping_ms is not None
                else "—"
            )

            values = [
                server.country,
                server.ip_address,
                ping,
                f"{server.speed_mbps:.2f}",
                str(server.sessions),
                "بله" if server.supports_openvpn else "خیر",
            ]

            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                self.table.setItem(row_index, column, item)

    # ======================================================
    # Error handling
    # ======================================================

    def _show_error(self, error: str) -> None:
        self.status_label.setText(
            "خطا در دریافت فهرست سرورها."
        )
        QMessageBox.critical(
            self,
            "خطا در دریافت سرورها",
            error,
        )


# ==========================================================
# Application entry point
# ==========================================================

def main() -> int:
    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    return app.exec()
