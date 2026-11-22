
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
from devtunnel.core.diagnostics import (
    DEFAULT_MAX_WORKERS,
    DEFAULT_TIMEOUT_MS,
    ReachabilityResult,
    check_servers_reachability,
)
from devtunnel.core.sorting import sort_servers
from devtunnel.providers.vpngate import (
    VPN_GATE_MIRROR_API_URL,
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


class ServerCheckWorker(QThread):
    """Run bounded ICMP probes without blocking the GUI thread."""

    progress = Signal(int, int)
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, servers: list, parent=None) -> None:
        super().__init__(parent)
        self._servers = list(servers)

    def run(self) -> None:
        try:
            results = check_servers_reachability(
                self._servers,
                progress_callback=lambda done, total: self.progress.emit(
                    done,
                    total,
                ),
            )
            self.succeeded.emit(results)
        except Exception:
            self.failed.emit(traceback.format_exc())


class MainWindow(QMainWindow):

    def __init__(self) -> None:
        super().__init__()

        self.setWindowTitle(f"DevTunnel {__version__}")
        self.resize(1050, 680)

        self._worker: ServerRefreshWorker | None = None
        self._check_worker: ServerCheckWorker | None = None
        self._servers: list = []
        self._source = ""
        self._reachability: dict[str, ReachabilityResult] = {}
        self._sort_column: int | None = None
        self._sort_descending = False

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

        self.check_button = QPushButton(
            "بررسی دسترس‌پذیری سرورها"
        )
        self.check_button.setEnabled(False)
        self.check_button.clicked.connect(
            self.check_servers
        )

        action_layout = QHBoxLayout()
        action_layout.addWidget(self.refresh_button)
        action_layout.addWidget(self.check_button)
        action_layout.addStretch()

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

        self.table = QTableWidget(0, 8)

        self.table.setHorizontalHeaderLabels(
            [
                "کشور",
                "آدرس IP",
                "Ping منبع (ms)",
                "سرعت (Mbps)",
                "کاربران هم‌زمان",
                "OpenVPN",
                "دسترس‌پذیری",
                "تأخیر محلی (ms)",
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

        header = self.table.horizontalHeader()
        header.setSortIndicatorShown(False)
        header.sectionClicked.connect(self._on_header_clicked)

        # --------------------------------------------------
        # Main layout
        # --------------------------------------------------

        layout = QVBoxLayout()

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(self.status_label)
        layout.addWidget(self.progress_bar)
        layout.addLayout(action_layout)
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

        if self._is_busy():
            return

        self._set_busy(True)
        self.progress_bar.setRange(0, 0)
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
        self.progress_bar.setRange(0, 0)
        self._worker = None
        self._set_busy(False)

    def _is_busy(self) -> bool:
        return (
            (self._worker is not None and self._worker.isRunning())
            or (
                self._check_worker is not None
                and self._check_worker.isRunning()
            )
        )

    def _set_busy(self, busy: bool) -> None:
        self.refresh_button.setEnabled(not busy)
        self.check_button.setEnabled(
            not busy and bool(self._servers)
        )

    def check_servers(self) -> None:
        if self._is_busy() or not self._servers:
            return

        self._set_busy(True)
        self.progress_bar.setRange(0, len(self._servers))
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.status_label.setText(
            "در حال بررسی دسترس‌پذیری سرورها با حداکثر "
            f"{DEFAULT_MAX_WORKERS} درخواست هم‌زمان و مهلت "
            f"{DEFAULT_TIMEOUT_MS} میلی‌ثانیه…"
        )

        self._check_worker = ServerCheckWorker(self._servers, self)
        self._check_worker.progress.connect(self._on_check_progress)
        self._check_worker.succeeded.connect(self._handle_check_success)
        self._check_worker.failed.connect(self._show_error)
        self._check_worker.finished.connect(self._on_check_finished)
        self._check_worker.start()

    def _on_check_progress(self, completed: int, total: int) -> None:
        self.progress_bar.setRange(0, total)
        self.progress_bar.setValue(completed)
        self.status_label.setText(
            f"در حال بررسی دسترسی سرورها: {completed} از {total}"
        )

    def _handle_check_success(
        self,
        results: list[ReachabilityResult],
    ) -> None:
        self._reachability = {
            result.ip_address: result
            for result in results
        }
        self._apply_filters()

        reachable = sum(
            result.reachable is True for result in results
        )
        unreachable = sum(
            result.reachable is False for result in results
        )
        skipped = len(results) - reachable - unreachable

        self.status_label.setText(
            "بررسی پایان یافت: "
            f"{reachable} پاسخ‌گو، {unreachable} بدون پاسخ، "
            f"{skipped} بررسی‌نشده. "
            "پاسخ ICMP تضمین‌کننده امکان اتصال VPN نیست."
        )

    def _on_check_finished(self) -> None:
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 0)
        self._check_worker = None
        self._set_busy(False)

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
        self._reachability.clear()

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

        if self._sort_column is not None:
            filtered = sort_servers(
                filtered,
                column=self._sort_column,
                descending=self._sort_descending,
                reachability=self._reachability,
            )

        self._populate_table(filtered)

        self.result_label.setText(
            f"تعداد سرورها: {len(filtered)} "
            f"از {len(self._servers)}"
        )

    def _on_header_clicked(self, column: int) -> None:
        if column == self._sort_column:
            self._sort_descending = not self._sort_descending
        else:
            self._sort_column = column
            self._sort_descending = False

        self.table.horizontalHeader().setSortIndicator(
            column,
            (
                Qt.SortOrder.DescendingOrder
                if self._sort_descending
                else Qt.SortOrder.AscendingOrder
            ),
        )
        self.table.horizontalHeader().setSortIndicatorShown(True)
        self._apply_filters()

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

            check = self._reachability.get(server.ip_address)
            if check is None:
                reachability_text = "بررسی‌نشده"
                local_latency = "—"
            elif check.reachable is True:
                reachability_text = "در دسترس"
                local_latency = (
                    f"{check.latency_ms:.1f}"
                    if check.latency_ms is not None
                    else "نامشخص"
                )
            elif check.reachable is False:
                reachability_text = "بدون پاسخ"
                local_latency = "—"
            else:
                reachability_text = "قابل بررسی نیست"
                local_latency = "—"

            values = [
                server.country,
                server.ip_address,
                ping,
                f"{server.speed_mbps:.2f}",
                str(server.sessions),
                "بله" if server.supports_openvpn else "خیر",
                reachability_text,
                local_latency,
            ]

            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                self.table.setItem(row_index, column, item)

    def closeEvent(self, event) -> None:
        if self._is_busy():
            self.status_label.setText(
                "یک عملیات شبکه در حال اجراست؛ پس از پایان آن می‌توانید برنامه را ببندید."
            )
            event.ignore()
            return

        super().closeEvent(event)

    # ======================================================
    # Error handling
    # ======================================================

    def _show_error(self, error: str) -> None:
        self.status_label.setText(
            "اجرای عملیات با خطا روبه‌رو شد."
        )
        QMessageBox.critical(
            self,
            "خطای عملیات DevTunnel",
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
