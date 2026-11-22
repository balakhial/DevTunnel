
"""Desktop application for DevTunnel server discovery."""

import sys
import threading
import time
import traceback

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
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
from devtunnel.core.export import export_servers_to_csv
from devtunnel.core.models import VpnServer
from devtunnel.core.openvpn import locate_openvpn_executable
from devtunnel.core.sorting import sort_servers
from devtunnel.core.vpn_session import OpenVPNSession, OpenVPNSessionError
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


class OpenVPNConnectionWorker(QThread):
    """Fetch a trusted profile and own the OpenVPN process until disconnect."""

    state_changed = Signal(str)
    connected = Signal()
    failed = Signal(str)

    def __init__(
        self,
        executable,
        server: VpnServer,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._executable = executable
        self._server = server
        self._stop_requested = threading.Event()

    def request_disconnect(self) -> None:
        self._stop_requested.set()

    def run(self) -> None:
        session: OpenVPNSession | None = None
        failure_message: str | None = None

        try:
            self.state_changed.emit(
                "در حال دریافت پروفایل تازه از API رسمی و امن VPN Gate…"
            )
            profile = VpnGateProvider().fetch_server_profile(
                self._server.ip_address
            )
            if self._stop_requested.is_set():
                return

            session = OpenVPNSession(
                self._executable,
                profile,
                self._server.ip_address,
            )
            self.state_changed.emit(
                "در حال راه‌اندازی OpenVPN و رابط مدیریتی محلی…"
            )
            session.start()

            connect_deadline = time.monotonic() + 180.0
            connected_once = False

            while not self._stop_requested.is_set():
                process = session.process
                if process is None:
                    raise OpenVPNSessionError(
                        "فرایند OpenVPN پیش از پایان نشست متوقف شد."
                    )

                exit_code = process.poll()
                if exit_code is not None:
                    recent = "\\n".join(session.recent_logs[-8:])
                    detail = f"\\n{recent}" if recent else ""
                    raise OpenVPNSessionError(
                        f"فرایند OpenVPN با کد {exit_code} خارج شد.{detail}"
                    )

                messages = session.poll_messages(timeout=0.5)
                for message in messages:
                    if message.startswith(">STATE:"):
                        fields = message[len(">STATE:"):].split(",")
                        if len(fields) > 1:
                            state = fields[1]
                            self.state_changed.emit(state)
                            if state == "CONNECTED" and not connected_once:
                                connected_once = True
                                self.connected.emit()

                if not connected_once and time.monotonic() >= connect_deadline:
                    raise OpenVPNSessionError(
                        "پس از ۱۸۰ ثانیه اتصال برقرار نشد. "
                        "می‌توانی سرور دیگری را امتحان کنی."
                    )

        except Exception as exc:
            if not self._stop_requested.is_set():
                failure_message = str(exc)
        finally:
            if session is not None:
                try:
                    session.stop()
                except Exception as exc:
                    cleanup_message = f"خطا هنگام پاک‌سازی OpenVPN: {exc}"
                    failure_message = (
                        f"{failure_message}\\n{cleanup_message}"
                        if failure_message
                        else cleanup_message
                    )

            if failure_message:
                self.failed.emit(failure_message)



class MainWindow(QMainWindow):

    def __init__(self) -> None:
        super().__init__()

        self.setWindowTitle(f"DevTunnel {__version__}")
        self.resize(1050, 680)

        self._worker: ServerRefreshWorker | None = None
        self._check_worker: ServerCheckWorker | None = None
        self._connection_worker: OpenVPNConnectionWorker | None = None
        self._connection_error: str | None = None
        self._disconnect_requested = False
        self._connection_ever_established = False
        self._servers: list = []
        self._visible_servers: list = []
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

        self.export_button = QPushButton("خروجی CSV")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_current_servers)

        self.openvpn_check_button = QPushButton("بررسی نصب OpenVPN")
        self.openvpn_check_button.setToolTip(
            "فقط مسیر فایل اجرایی را بررسی می‌کند؛ چیزی نصب یا اجرا نمی‌شود."
        )
        self.openvpn_check_button.clicked.connect(
            self.check_openvpn_installation
        )

        self.connect_button = QPushButton("اتصال به سرور انتخاب‌شده")
        self.connect_button.setEnabled(False)
        self.connect_button.clicked.connect(self.connect_selected_server)

        self.disconnect_button = QPushButton("قطع اتصال")
        self.disconnect_button.setEnabled(False)
        self.disconnect_button.clicked.connect(self.disconnect_vpn)

        action_layout = QHBoxLayout()
        action_layout.addWidget(self.refresh_button)
        action_layout.addWidget(self.check_button)
        action_layout.addWidget(self.export_button)
        action_layout.addWidget(self.openvpn_check_button)
        action_layout.addWidget(self.connect_button)
        action_layout.addWidget(self.disconnect_button)
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
        self.table.itemSelectionChanged.connect(
            self._update_connection_controls
        )

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
        self._worker.finished.connect(
            self._worker.deleteLater
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
            or (
                self._connection_worker is not None
                and self._connection_worker.isRunning()
            )
        )

    def _set_busy(self, busy: bool) -> None:
        self.refresh_button.setEnabled(not busy)
        self.check_button.setEnabled(
            not busy and bool(self._servers)
        )
        self.export_button.setEnabled(
            not busy and bool(self._visible_servers)
        )
        self.openvpn_check_button.setEnabled(not busy)
        self.connect_button.setEnabled(
            not busy and self._selected_server_for_connection() is not None
        )
        self.disconnect_button.setEnabled(
            self._connection_worker is not None
            and self._connection_worker.isRunning()
        )

    def _selected_server_for_connection(self) -> VpnServer | None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self._visible_servers):
            return None
        server = self._visible_servers[row]
        return server if server.supports_openvpn else None

    def _update_connection_controls(self) -> None:
        self.connect_button.setEnabled(
            not self._is_busy()
            and self._selected_server_for_connection() is not None
        )

    def connect_selected_server(self) -> None:
        if self._is_busy():
            return

        server = self._selected_server_for_connection()
        if server is None:
            QMessageBox.information(
                self,
                "انتخاب سرور",
                "ابتدا یک سرور دارای OpenVPN را از جدول انتخاب کن.",
            )
            return

        executable = locate_openvpn_executable()
        if executable is None:
            QMessageBox.warning(
                self,
                "OpenVPN نصب نیست",
                "فایل اجرایی OpenVPN پیدا نشد. ابتدا OpenVPN Community را "
                "از نشانی رسمی زیر نصب کن؛ DevTunnel چیزی را خودکار نصب نمی‌کند.\\n\\n"
                "https://openvpn.net/community-downloads/",
            )
            return

        answer = QMessageBox.warning(
            self,
            "تأیید اتصال VPN",
            "این سرور یک رله عمومی و داوطلبانه است. با اتصال ممکن است "
            "مسیر پیش‌فرض اینترنت و DNS ویندوز از طریق اپراتور این سرور "
            "عبور کند. اپراتور رله می‌تواند ترافیک رمزنگاری‌نشده را ببیند؛ "
            "برای حساب‌های حساس یا اطلاعات محرمانه از رله عمومی استفاده نکن.\n\n"
            "پروفایل اتصال فقط از API رسمی HTTPS دریافت و پیش از اجرا بررسی "
            "می‌شود. با این حال سرور مقصد شخص ثالث است.\n\n"
            f"سرور: {server.ip_address} — {server.country}\n"
            f"فایل اجرایی OpenVPN: {executable}\n\n"
            "اتصال برقرار شود؟",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        self._connection_error = None
        self._disconnect_requested = False
        self._connection_ever_established = False
        self._connection_worker = OpenVPNConnectionWorker(
            executable,
            server,
            self,
        )
        self._connection_worker.state_changed.connect(
            self._on_connection_state
        )
        self._connection_worker.connected.connect(
            self._on_connection_connected
        )
        self._connection_worker.failed.connect(
            self._on_connection_failed
        )
        self._connection_worker.finished.connect(
            self._on_connection_finished
        )
        self._connection_worker.finished.connect(
            self._connection_worker.deleteLater
        )

        self._set_busy(True)
        self.disconnect_button.setEnabled(True)
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setVisible(True)
        self.status_label.setText(
            f"در حال آماده‌سازی اتصال به {server.ip_address}…"
        )
        self._connection_worker.start()

    def disconnect_vpn(self) -> None:
        worker = self._connection_worker
        if worker is None or not worker.isRunning():
            return

        self._disconnect_requested = True
        self.disconnect_button.setEnabled(False)
        self.status_label.setText(
            "در حال ارسال فرمان قطع امن به OpenVPN…"
        )
        worker.request_disconnect()

    def _on_connection_state(self, state: str) -> None:
        state_messages = {
            "CONNECTING": "در حال اتصال به سرور VPN…",
            "WAIT": "منتظر پاسخ سرور VPN…",
            "AUTH": "در حال احراز هویت با سرور…",
            "GET_CONFIG": "در حال دریافت تنظیمات تونل…",
            "ASSIGN_IP": "در حال دریافت آدرس شبکه VPN…",
            "ADD_ROUTES": "در حال تنظیم مسیرهای شبکه…",
            "CONNECTED": "اتصال VPN برقرار شد.",
            "RECONNECTING": "ارتباط موقتاً قطع شد؛ OpenVPN در حال تلاش مجدد است…",
            "RESOLVE": "در حال شناسایی آدرس سرور…",
            "TCP_CONNECT": "در حال برقراری ارتباط TCP…",
            "EXITING": "OpenVPN در حال خروج از تونل است…",
        }
        self.status_label.setText(
            state_messages.get(state, state)
        )

    def _on_connection_connected(self) -> None:
        self._connection_ever_established = True
        self.status_label.setText(
            "اتصال VPN برقرار شد. برای پایان، از دکمه «قطع اتصال» استفاده کن."
        )

    def _on_connection_failed(self, error: str) -> None:
        self._connection_error = error
        self.status_label.setText("اتصال VPN برقرار نشد.")
        QMessageBox.critical(
            self,
            "خطا در اتصال VPN",
            error,
        )

    def _on_connection_finished(self) -> None:
        self._connection_worker = None
        self.disconnect_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 0)
        self._set_busy(False)

        if self._connection_error:
            self.status_label.setText("اتصال VPN برقرار نشد.")
        elif self._disconnect_requested and self._connection_ever_established:
            self.status_label.setText("اتصال VPN به‌طور امن قطع شد.")
        elif self._disconnect_requested:
            self.status_label.setText("تلاش برای اتصال VPN لغو شد.")
        else:
            self.status_label.setText("فرایند OpenVPN پایان یافت.")

        self._disconnect_requested = False
        self._connection_ever_established = False

    def check_openvpn_installation(self) -> None:
        if self._is_busy():
            return

        executable = locate_openvpn_executable()
        if executable is None:
            self.status_label.setText(
                "OpenVPN CLI پیدا نشد. DevTunnel چیزی نصب یا اجرا نکرده است."
            )
            return

        self.status_label.setText(
            f"OpenVPN CLI پیدا شد: {executable}. "
            "هنوز هیچ اتصال VPN برقرار نشده است."
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
        self._check_worker.finished.connect(
            self._check_worker.deleteLater
        )
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

        self._visible_servers = list(filtered)
        self.export_button.setEnabled(
            not self._is_busy() and bool(self._visible_servers)
        )
        self._update_connection_controls()
        self.result_label.setText(
            f"تعداد سرورها: {len(filtered)} "
            f"از {len(self._servers)}"
        )

    def export_current_servers(self) -> None:
        if not self._visible_servers:
            return

        destination, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "ذخیره فهرست سرورها",
            "devtunnel-servers.csv",
            "CSV Files (*.csv)",
        )
        if not destination:
            return

        if not destination.lower().endswith(".csv"):
            destination += ".csv"

        try:
            count = export_servers_to_csv(
                self._visible_servers,
                destination,
                reachability=self._reachability,
            )
            self.status_label.setText(
                f"خروجی CSV با {count} سرور ذخیره شد: {destination}"
            )
        except Exception:
            error = traceback.format_exc()
            QMessageBox.critical(
                self,
                "خطا در ذخیره خروجی",
                error,
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
                "یک عملیات شبکه یا تونل VPN فعال است؛ ابتدا آن را از داخل برنامه متوقف کن."
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
