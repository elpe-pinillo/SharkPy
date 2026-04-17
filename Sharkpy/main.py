import re
import sys
import time as _time
import psutil

from PyQt5 import QtWidgets, QtGui
from PyQt5.QtWidgets import QTreeWidgetItem, QMenu, QAction, QFileDialog, QItemDelegate, QLineEdit
from PyQt5.QtCore import QEvent, QMetaObject, pyqtSlot, pyqtSignal, Qt, QRegExp
from PyQt5.QtGui import QColor, QRegExpValidator


class HexByteDelegate(QItemDelegate):
    """Cell delegate that restricts input to exactly 2 hex characters."""
    def createEditor(self, parent, option, index):
        ed = QLineEdit(parent)
        ed.setMaxLength(2)
        ed.setValidator(QRegExpValidator(QRegExp("[0-9A-Fa-f]{1,2}"), ed))
        ed.setAlignment(Qt.AlignCenter)
        return ed

    def setModelData(self, editor, model, index):
        text = editor.text().strip().upper()
        if text:
            model.setData(index, text.zfill(2))

import qtmodern.windows
import qtmodern.styles
from gui import qt_ui
try:
    import netifaces
except ImportError:
    import netifaces2 as netifaces
from protocol_parser import get_protocol, packet_src, packet_dst, packet_len
from scapy.all import *
from core import CoreClass
import attack_engine as _atk_engine
from ca_manager import CAManager
from tls_proxy import TLSProxy
from tcp_proxy import TCPProxy

if sys.platform != "win32":
    from p_firewall import flush, tls_intercept, tls_flush, tcp_intercept, tcp_flush, quic_block, quic_unblock


# Wireshark-inspired protocol row colors
_PROTO_COLORS = {
    "HTTP":         QColor(0xe4, 0xfd, 0xe1),
    "HTTPS":        QColor(0xc8, 0xf0, 0xc8),
    "QUIC":         QColor(0xb8, 0xe8, 0xff),
    "DNS":          QColor(0xd0, 0xe8, 0xff),
    "TCP":          QColor(0xe7, 0xe6, 0xff),
    "UDP":          QColor(0xda, 0xff, 0xda),
    "ICMP":         QColor(0xff, 0xf7, 0xb5),
    "ARP":          QColor(0xff, 0xed, 0xd7),
    "SSH":          QColor(0xd0, 0xff, 0xff),
    "FTP":          QColor(0xff, 0xe4, 0xc8),
    "SMB":          QColor(0xff, 0xd0, 0xd0),
    "802.11":       QColor(0xff, 0xf0, 0xcc),
    "BT":           QColor(0xe8, 0xd5, 0xff),
    "BLE":          QColor(0xf0, 0xd8, 0xff),
    "CAN":          QColor(0xd5, 0xf5, 0xe3),
    "Unknown":      QColor(0xf0, 0xf0, 0xf0),
}


VERSION = "0.2"

class SniffTool(QtWidgets.QMainWindow, qt_ui.Ui_MainWindow):
    _rep_response_ready  = pyqtSignal(object, object, object)  # resp_bytes (or None), status_str, state_dict
    _intr_result_ready   = pyqtSignal(object)           # result dict
    def __init__(self):
        super().__init__()
        self.c = CoreClass(self)
        self.setupUi(self)
        self.setWindowTitle(f"SharkPy  v{VERSION}")
        self.statusBar.setStyleSheet("border :3px solid black;")
        self.statusBar.showMessage(f"SharkPy v{VERSION}  —  ready", 0)
        self.t = None
        self.running_info.setText("Ready to sniff")
        self.packet_list = []
        self.time_list = []        # parallel to packet_list: capture time offset per packet
        self.auto_down_scroll = True
        self.initial_time = 0.0
        self.debugmode = False
        self._active_filter = ""
        # rep_loaded_packet removed — each Repeater sub-tab carries its own pkt in _rep_tabs[i]['pkt']
        self._sessions = {}             # session key -> session dict
        self._session_keys = []         # ordered list of session keys for table lookup

        # TLS interception
        self._ca = CAManager()
        self._tls_proxy = TLSProxy(self._ca, parent=self)
        self._tls_proxy.data_intercepted.connect(self._on_tls_data)
        self._tls_intercept_rows = []
        self._tls_http_bufs = {}        # conn_id -> {host, port, req, resp}

        # Plaintext TCP interception
        self._tcp_proxy = TCPProxy(parent=self)
        self._tcp_proxy.data_intercepted.connect(self._on_tcp_data)
        self._tcp_proxy.conn_failed.connect(self._on_tcp_conn_failed)
        self._tcp_http_bufs = {}        # conn_id -> {host, port, req, resp}
        self._tcp_conn_count = 0

        self.interface_2.addItem("Any...")
        self.interface_2.addItems(netifaces.interfaces())
        for _iface in self._discover_extra_interfaces():
            if self.interface_2.findText(_iface) == -1:
                self.interface_2.addItem(_iface)
        self.interface_2.currentTextChanged.connect(self._on_iface_changed)

        # Capture mode selector added below the interface combo
        self.mode_combo = QtWidgets.QComboBox()
        if sys.platform == "win32":
            self.mode_combo.addItem("Intercept  (WinDivert – modify/drop)")
            self.mode_combo.setToolTip(
                "Intercept: holds packets in-kernel via WinDivert — "
                "allows modify/drop. Requires the WinDivert driver and admin rights.\n"
                "Sniff: passive capture via Npcap — sees all layers but read-only."
            )
        else:
            self.mode_combo.addItem("Intercept  (NFQUEUE – modify/drop)")
            self.mode_combo.setToolTip(
                "Intercept: routes traffic through iptables NFQUEUE — "
                "allows modify/drop but only sees L3+.\n"
                "Sniff: passive raw-socket capture — sees full L2 frames but read-only."
            )
        self.mode_combo.addItem("Sniff  (passive – all layers)")
        self.verticalLayout.addWidget(self.mode_combo)

        self.haltButton.setEnabled(False)
        self.sCorruptButton.setEnabled(False)
        self.deb_nextButton.setEnabled(False)
        self.deb_continueButton.setEnabled(False)

        # Signals
        self.sniffButton.clicked.connect(self.sniff_button_event)
        self.haltButton.clicked.connect(self.stop_button_event)
        self.clearButton.clicked.connect(self.clear_view)
        self.filterButton.clicked.connect(self._apply_filter)
        self.filterText.returnPressed.connect(self._apply_filter)
        self.filter_table.cellClicked.connect(self.show_packet)
        self.filter_table.cellClicked.connect(self.show_hex_packet)
        self.corruptButton.clicked.connect(self.corrupt_button_event)
        self.sCorruptButton.clicked.connect(self.stop_corrupt_button_event)
        self.deb_breakButton.clicked.connect(self.deb_break_button_event)
        self.deb_continueButton.clicked.connect(self.deb_continue_button_event)
        self.deb_nextButton.clicked.connect(self.deb_next_button_event)
        self.filter_table.itemChanged.connect(self.updateObject)
        self.filter_table.installEventFilter(self)
        self.sessions_table.installEventFilter(self)
        self.http_table.installEventFilter(self)
        self._marked_rows = set()   # rows marked by user (black background)
        self.detail_tree_widget.itemChanged.connect(self.updateFilterTable)
        self.detail_tree_widget.currentItemChanged.connect(self._on_tree_selection_changed)
        self.hex_table.cellClicked.connect(self._on_hex_cell_clicked)
        self.hex_table.cellChanged.connect(self._on_hex_cell_changed)
        self._hex_sync = False   # guard against feedback loops
        self._intercept_sync = False

        # TLS signals
        self.tls_gen_ca_btn.clicked.connect(self._tls_gen_ca)
        self.tls_export_ca_btn.clicked.connect(self._tls_export_ca)
        self.tls_start_btn.clicked.connect(self._tls_start)
        self.tls_stop_btn.clicked.connect(self._tls_stop)
        self.tls_table.cellClicked.connect(self._tls_show_row)
        self._update_ca_status()

        # TCP proxy signals
        self.tcp_start_btn.clicked.connect(self._tcp_start)
        self.tcp_stop_btn.clicked.connect(self._tcp_stop)

        # Repeater — multi-tab setup
        self._rep_tabs = []          # list of per-tab state dicts
        self._rep_sync = False       # guard: hex↔ascii cell sync
        self._rep_tree_sync = False  # guard: tree↔hex sync
        self._held_row = None        # row index of currently held packet
        self._rep_response_ready.connect(self._rep_show_response)
        self.rep_loadButton.clicked.connect(self._repeater_load)
        self.rep_new_tab_btn.clicked.connect(lambda: self._rep_add_tab())
        self.rep_inner_tabs.tabCloseRequested.connect(self._rep_close_tab)
        self._rep_add_tab("Tab 1")   # create the first tab
        self.proc_refresh_btn.clicked.connect(self._refresh_proc_list)
        self._refresh_proc_list()

        # Intruder — multi-tab setup
        self._intr_tabs = []         # list of per-tab state dicts
        self._intr_stop_flag = False
        self._intr_pos_colors  = [
            QColor(0xff, 0xeb, 0x3b),  # yellow
            QColor(0x4f, 0xc3, 0xf7),  # cyan
            QColor(0xa5, 0xd6, 0xa7),  # green
            QColor(0xff, 0xab, 0x40),  # orange
            QColor(0xce, 0x93, 0xd8),  # purple
            QColor(0xef, 0x9a, 0x9a),  # pink
        ]
        self._intr_result_ready.connect(self._intr_show_result)
        self.intr_new_tab_btn.clicked.connect(lambda: self._intr_add_tab())
        self.intr_inner_tabs.tabCloseRequested.connect(self._intr_close_tab)
        self.intr_start_btn.clicked.connect(self._intr_start)
        self.intr_stop_btn.clicked.connect(self._intr_stop)
        self._intr_add_tab("Tab 1")  # create the first tab

        # Sessions signals
        self.refreshSessionsButton.clicked.connect(self._refresh_sessions)
        self.sessions_table.cellClicked.connect(self._show_session_stream)
        self.followStreamButton.clicked.connect(self._follow_stream)

        # Crypto signals
        self._crypto_last_bytes = None   # bytes of the last processed output
        self._crypto_input_fmt_prev = 0  # tracks previous input format index for live reformat
        self.crypto_load_capture_btn.clicked.connect(self._crypto_load_from_capture)
        self.crypto_load_rep_btn.clicked.connect(self._crypto_load_from_repeater)
        self.crypto_clear_btn.clicked.connect(self._crypto_clear)
        self.crypto_fwd_btn.clicked.connect(lambda: self._crypto_process('forward'))
        self.crypto_rev_btn.clicked.connect(lambda: self._crypto_process('reverse'))
        self.crypto_send_rep_btn.clicked.connect(self._crypto_send_to_repeater)
        self.crypto_copy_btn.clicked.connect(self._crypto_copy_output)
        self.crypto_input_fmt.currentIndexChanged.connect(self._crypto_input_fmt_changed)
        self.crypto_output_fmt.currentIndexChanged.connect(self._crypto_output_fmt_changed)

        # Statistics menu
        self.actionIPv4_Statistics.triggered.connect(lambda: self._show_statistics(4))
        self.actionIPv6_Statistics.triggered.connect(lambda: self._show_statistics(6))

        # About
        self.actionAbout.triggered.connect(self._show_about)

        # Inspector tab
        self._proxy_http_entries = []   # list of dicts
        self._proxy_dns_entries  = []
        self._proxy_conv_map     = {}   # stream_key -> conv dict
        self._proxy_conv_list    = []   # ordered list of conv dicts
        self._tls_hs_entries     = []   # TLS handshake records
        self._creds_entries      = []   # captured credentials
        self._smb_entries        = []   # SMB operations
        self._sql_entries        = []   # SQL queries (MySQL / PostgreSQL)
        self.insp_tabs.currentChanged.connect(self._insp_tab_changed)
        self.proxy_clear_btn.clicked.connect(self._proxy_clear)
        self.proxy_clear_filter_btn.clicked.connect(lambda: self.proxy_filter_edit.clear())
        self.proxy_filter_edit.textChanged.connect(self._proxy_apply_filter)
        self.http_table.currentCellChanged.connect(lambda r, c, pr, pc: self._proxy_http_row_selected(r))
        self.dns_table.currentCellChanged.connect(lambda r, c, pr, pc: self._proxy_dns_row_selected(r))
        self.conv_table.currentCellChanged.connect(lambda r, c, pr, pc: self._proxy_conv_row_selected(r))
        self.telnet_table.currentCellChanged.connect(lambda r, c, pr, pc: self._proxy_telnet_row_selected(r))
        self.tls_hs_table.currentCellChanged.connect(lambda r, c, pr, pc: self._insp_tls_hs_row_selected(r))
        self.creds_table.currentCellChanged.connect(lambda r, c, pr, pc: self._insp_creds_row_selected(r))
        self.creds_copy_btn.clicked.connect(self._insp_creds_copy)
        self.smb_table.currentCellChanged.connect(lambda r, c, pr, pc: self._insp_smb_row_selected(r))
        self.sql_table.currentCellChanged.connect(lambda r, c, pr, pc: self._insp_sql_row_selected(r))
        self.sql_copy_btn.clicked.connect(self._insp_sql_copy)

        # Telnet session state
        self._telnet_sessions = []   # list of session dicts
        self._telnet_map = {}        # stream_key -> session dict

        self._wifi_frames   = []     # list of captured 802.11 frames
        self._bt_events     = []     # list of captured Bluetooth packets

        # Capture tab — WiFi / Bluetooth sub-tab row selection
        self.wifi_table.currentCellChanged.connect(
            lambda r, c, pr, pc: self._proxy_wifi_row_selected(r))
        self.bt_table.currentCellChanged.connect(
            lambda r, c, pr, pc: self._proxy_bt_row_selected(r))

        # Attack tab
        self._atk_threads = {}   # name -> (thread, stop_event)
        self._atk_populate_ifaces()
        self.atk_arp_start.clicked.connect(lambda: self._atk_start("arp"))
        self.atk_arp_stop.clicked.connect(lambda: self._atk_stop("arp"))
        self.atk_dns_start.clicked.connect(lambda: self._atk_start("dns"))
        self.atk_dns_stop.clicked.connect(lambda: self._atk_stop("dns"))
        self.atk_dns_add_row.clicked.connect(self._atk_dns_add_row)
        self.atk_dns_del_row.clicked.connect(self._atk_dns_del_row)
        self.atk_deauth_start.clicked.connect(lambda: self._atk_start("deauth"))
        self.atk_deauth_stop.clicked.connect(lambda: self._atk_stop("deauth"))
        self.atk_dhs_start.clicked.connect(lambda: self._atk_start("dhs"))
        self.atk_dhs_stop.clicked.connect(lambda: self._atk_stop("dhs"))
        self.atk_rd_start.clicked.connect(lambda: self._atk_start("rd"))
        self.atk_rd_stop.clicked.connect(lambda: self._atk_stop("rd"))
        self.atk_ll_start.clicked.connect(lambda: self._atk_start("ll"))
        self.atk_ll_stop.clicked.connect(lambda: self._atk_stop("ll"))
        # Auto-fill Our IP when interface changes (Rogue DHCP drives all fields)
        self.atk_rd_iface.currentTextChanged.connect(self._atk_autofill_ip)
        # Trigger once with the current value to pre-populate on load
        self._atk_autofill_ip(self.atk_rd_iface.currentText())
        # Seed DNS table with one empty row
        self._atk_dns_add_row()

        # Menu signals — File
        self.actionOpen.triggered.connect(self.load_pcap)
        self.actionSave.triggered.connect(self.save_pcap)
        self.actionSave_as.triggered.connect(self.save_pcap)
        self.actionClose.triggered.connect(self.close)
        self._recent_files = []
        self._update_recent_menu()

        # Menu signals — Capture
        self.actionSniff.triggered.connect(self.sniff_button_event)
        self.actionHalt.triggered.connect(self.stop_button_event)
        self.actionOptions.triggered.connect(lambda: self.tabWidget.setCurrentIndex(0))
        self.actionInterfaces.triggered.connect(self._show_interfaces_dialog)
        self.actionFirewall.triggered.connect(self._show_firewall_dialog)

        # Menu signals — Replacer
        self.actionRules.triggered.connect(lambda: self.tabWidget.setCurrentIndex(0))

        # Menu signals — Settings
        self.actionLight_Mode.triggered.connect(self._apply_light_theme)
        self.actionDark_Mode.triggered.connect(self._apply_dark_theme)

    # ------------------------------------------------------------------
    # Packet table editing
    # ------------------------------------------------------------------

    def updateObject(self, item):
        if item.column() not in (1, 2):
            return
        if item.row() >= len(self.packet_list):
            return
        packet = self.packet_list[item.row()]
        if item.column() == 1:
            if packet.haslayer(IP):
                packet[IP].src = item.text()
            elif packet.haslayer(Ether):
                packet[Ether].src = item.text()
        elif item.column() == 2:
            if packet.haslayer(IP):
                packet[IP].dst = item.text()
            elif packet.haslayer(Ether):
                packet[Ether].dst = item.text()
        self.packet_list[item.row()] = packet

    def updateTreeView(self, item):
        pass

    def updateFilterTable(self, item):
        pass

    # ------------------------------------------------------------------
    # Context menu
    # ------------------------------------------------------------------

    def eventFilter(self, source, event):
        if event.type() == QEvent.ContextMenu and source is self.filter_table:
            self._show_packet_context_menu(event.globalPos())
            return True
        if event.type() == QEvent.ContextMenu and source is self.sessions_table:
            self._show_session_context_menu(event.globalPos())
            return True
        if event.type() == QEvent.ContextMenu and source is self.http_table:
            self._show_proxy_http_context_menu(event.globalPos())
            return True
        if event.type() == QEvent.ContextMenu:
            # Check if source is any Intruder tab's results table
            for tab_state in self._intr_tabs:
                if source is tab_state['results_table']:
                    self._intr_result_context_menu(event.globalPos(), source)
                    return True
        return super().eventFilter(source, event)

    def _show_packet_context_menu(self, global_pos):
        rows = sorted({item.row() for item in self.filter_table.selectedItems()})
        if not rows:
            return
        row = rows[0]
        if row >= len(self.packet_list):
            return
        pkt = self.packet_list[row]

        menu = QMenu(self)

        # ── Send to … ─────────────────────────────────────────────────────
        a = menu.addAction("Send to Repeater")
        a.triggered.connect(lambda: self._ctx_send_to_repeater(row))

        a = menu.addAction("Send to Intruder")
        a.triggered.connect(lambda: self._ctx_send_to_intruder(row))

        a = menu.addAction("Send to Crypto")
        a.triggered.connect(lambda: self._ctx_send_to_crypto(row))

        menu.addSeparator()

        # ── Apply as Filter ───────────────────────────────────────────────
        filter_menu = menu.addMenu("Apply as Filter")
        prepare_menu = menu.addMenu("Prepare as Filter")

        filter_items = self._build_filter_suggestions(pkt)
        for label, expr in filter_items:
            fm_action = filter_menu.addAction(label)
            fm_action.triggered.connect(lambda checked, e=expr: self._ctx_apply_filter(e))
            pm_action = prepare_menu.addAction(label)
            pm_action.triggered.connect(lambda checked, e=expr: self._ctx_prepare_filter(e))

        menu.addSeparator()

        # ── Conversation Filter ───────────────────────────────────────────
        conv_menu = menu.addMenu("Conversation Filter")
        for label, expr in self._build_conversation_filters(pkt):
            ca = conv_menu.addAction(label)
            ca.triggered.connect(lambda checked, e=expr: self._ctx_apply_filter(e))

        menu.addSeparator()

        # ── Follow Stream ─────────────────────────────────────────────────
        if pkt.haslayer(TCP):
            a = menu.addAction("Follow TCP Stream")
            a.triggered.connect(lambda: self._ctx_follow_stream(pkt, "TCP"))
        if pkt.haslayer(UDP):
            a = menu.addAction("Follow UDP Stream")
            a.triggered.connect(lambda: self._ctx_follow_stream(pkt, "UDP"))

        menu.addSeparator()

        # ── Cross-tab navigation ──────────────────────────────────────────
        a = menu.addAction("Go to Proxy Entry")
        a.triggered.connect(lambda: self._ctx_goto_proxy_from_pkt(pkt))

        menu.addSeparator()

        # ── Copy ──────────────────────────────────────────────────────────
        copy_menu = menu.addMenu("Copy")

        a = copy_menu.addAction("As Hex")
        a.triggered.connect(lambda: self._ctx_copy_hex(pkt))

        a = copy_menu.addAction("As Escaped String")
        a.triggered.connect(lambda: self._ctx_copy_escaped(pkt))

        a = copy_menu.addAction("Summary")
        a.triggered.connect(lambda: QtWidgets.QApplication.clipboard().setText(pkt.summary()))

        copy_menu.addSeparator()

        if pkt.haslayer(IP):
            a = copy_menu.addAction(f"Source IP  ({pkt[IP].src})")
            a.triggered.connect(lambda: QtWidgets.QApplication.clipboard().setText(pkt[IP].src))
            a = copy_menu.addAction(f"Destination IP  ({pkt[IP].dst})")
            a.triggered.connect(lambda: QtWidgets.QApplication.clipboard().setText(pkt[IP].dst))
        if pkt.haslayer(TCP):
            a = copy_menu.addAction(f"Src Port  ({pkt[TCP].sport})")
            a.triggered.connect(lambda: QtWidgets.QApplication.clipboard().setText(str(pkt[TCP].sport)))
            a = copy_menu.addAction(f"Dst Port  ({pkt[TCP].dport})")
            a.triggered.connect(lambda: QtWidgets.QApplication.clipboard().setText(str(pkt[TCP].dport)))
        if pkt.haslayer(UDP):
            a = copy_menu.addAction(f"Src Port  ({pkt[UDP].sport})")
            a.triggered.connect(lambda: QtWidgets.QApplication.clipboard().setText(str(pkt[UDP].sport)))
            a = copy_menu.addAction(f"Dst Port  ({pkt[UDP].dport})")
            a.triggered.connect(lambda: QtWidgets.QApplication.clipboard().setText(str(pkt[UDP].dport)))

        menu.addSeparator()

        # ── Mark / Ignore ─────────────────────────────────────────────────
        is_marked = row in self._marked_rows
        mark_label = "Unmark Packet" if is_marked else "Mark Packet"
        a = menu.addAction(mark_label)
        a.triggered.connect(lambda: self._ctx_toggle_mark(row))

        a = menu.addAction("Ignore Packet  (hide row)")
        a.triggered.connect(lambda: self.filter_table.setRowHidden(row, True))

        a = menu.addAction("Show All Ignored")
        a.triggered.connect(lambda: [self.filter_table.setRowHidden(r, False)
                                     for r in range(self.filter_table.rowCount())])

        menu.addSeparator()

        # ── Compare ───────────────────────────────────────────────────────
        cmp_action = menu.addAction("Compare Packets")
        if len(rows) == 2:
            row_a, row_b = rows[0], rows[1]
            cmp_action.triggered.connect(lambda: self._show_packet_diff(row_a, row_b))
        else:
            cmp_action.setEnabled(False)
            cmp_action.setToolTip("Select exactly 2 packets to compare")

        menu.addSeparator()

        # ── Export ────────────────────────────────────────────────────────
        a = menu.addAction("Export Packet as PCAP…")
        a.triggered.connect(lambda: self._ctx_export_pcap([self.packet_list[r] for r in rows]))

        menu.exec_(global_pos)

    # ── Context menu helpers ──────────────────────────────────────────────

    def _build_filter_suggestions(self, pkt):
        items = []
        if pkt.haslayer(IP):
            items.append((f"Source IP  (ip.src == {pkt[IP].src})",   f"ip.src == {pkt[IP].src}"))
            items.append((f"Destination IP  (ip.dst == {pkt[IP].dst})", f"ip.dst == {pkt[IP].dst}"))
        if pkt.haslayer(TCP):
            items.append((f"Src Port  (tcp.port == {pkt[TCP].sport})", f"tcp.port == {pkt[TCP].sport}"))
            items.append((f"Dst Port  (tcp.port == {pkt[TCP].dport})", f"tcp.port == {pkt[TCP].dport}"))
            items.append(("Protocol: TCP", "tcp"))
        if pkt.haslayer(UDP):
            items.append((f"Src Port  (udp.port == {pkt[UDP].sport})", f"udp.port == {pkt[UDP].sport}"))
            items.append((f"Dst Port  (udp.port == {pkt[UDP].dport})", f"udp.port == {pkt[UDP].dport}"))
            items.append(("Protocol: UDP", "udp"))
        if pkt.haslayer(ICMP):
            items.append(("Protocol: ICMP", "icmp"))
        proto = get_protocol(pkt)
        if proto not in ("TCP", "UDP", "ICMP", "IP", "Unknown"):
            items.append((f"Protocol: {proto}", proto.lower()))
        return items

    def _build_conversation_filters(self, pkt):
        items = []
        src = dst = None
        if pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
            items.append((f"IP  {src} ↔ {dst}", f"ip.addr == {src} && ip.addr == {dst}"))
        elif pkt.haslayer(IPv6):
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
            items.append((f"IPv6  {src} ↔ {dst}", f"ipv6.addr == {src} && ipv6.addr == {dst}"))
        if src and dst:
            if pkt.haslayer(TCP):
                sp, dp = pkt[TCP].sport, pkt[TCP].dport
                items.append((f"TCP  {src}:{sp} ↔ {dst}:{dp}",
                              f"ip.addr == {src} && ip.addr == {dst} && tcp.port == {sp} && tcp.port == {dp}"))
            if pkt.haslayer(UDP):
                sp, dp = pkt[UDP].sport, pkt[UDP].dport
                items.append((f"UDP  {src}:{sp} ↔ {dst}:{dp}",
                              f"ip.addr == {src} && ip.addr == {dst} && udp.port == {sp} && udp.port == {dp}"))
        return items

    def _ctx_apply_filter(self, expr):
        self.filterText.setText(expr)
        self._apply_filter()

    def _ctx_prepare_filter(self, expr):
        self.filterText.setText(expr)
        self.filterText.setFocus()

    def _ctx_send_to_repeater(self, row):
        self.filter_table.selectRow(row)
        self._repeater_load()

    def _ctx_send_to_intruder(self, row):
        if row >= len(self.packet_list):
            return
        pkt = self.packet_list[row]
        s = self._intr_current()
        if s is None:
            return
        self._intr_load_bytes_s(bytes(pkt), pkt, s)
        self._goto_tab(self.tab_intruder)

    def _ctx_send_to_crypto(self, row):
        if row >= len(self.packet_list):
            return
        pkt = self.packet_list[row]
        if pkt.haslayer(Raw):
            data = bytes(pkt[Raw].load)
        else:
            data = bytes(pkt)
        self._crypto_set_input_bytes(data)
        self._goto_tab(self.tab_crypto)

    def _ctx_follow_stream(self, pkt, proto):
        self._refresh_sessions()
        key = self._session_key(pkt)
        if key and key in self._sessions:
            idx = self._session_keys.index(key)
            self.sessions_table.selectRow(idx)
            self._show_session_stream(idx, 0)
            self._goto_tab(self.tab_sessions)

    # ------------------------------------------------------------------
    # Cross-tab navigation helpers
    # ------------------------------------------------------------------

    def _ctx_goto_proxy_from_pkt(self, pkt):
        """From capture: jump to the first matching Proxy entry for this stream."""
        sk = self._proxy_stream_key(pkt)
        for idx, entry in enumerate(self._proxy_http_entries):
            if entry.get('stream_key') == sk:
                for r in range(self.http_table.rowCount()):
                    it = self.http_table.item(r, 0)
                    if it and it.data(Qt.UserRole) == idx:
                        self.insp_tabs.setCurrentIndex(0)
                        self.http_table.selectRow(r)
                        self._proxy_http_row_selected(r)
                        self._goto_tab(self.tab_proxy)
                        return
        # Fallback: check Telnet
        if pkt.haslayer(TCP):
            from scapy.layers.inet import TCP as _TCP
            port = pkt[_TCP].dport if pkt.haslayer(_TCP) else None
            if port == 23 or (pkt.haslayer(_TCP) and pkt[_TCP].sport == 23):
                self.insp_tabs.setCurrentIndex(5)
                self._goto_tab(self.tab_proxy)
                return
        QtWidgets.QMessageBox.information(
            self, "Not found", "No Inspector entry found for this stream.\n"
            "The stream may not have been parsed by the Inspector tab.")

    def _ctx_goto_capture_from_session_key(self, key):
        """Apply a capture filter to show only packets in this session."""
        try:
            proto, ep_a, ep_b = key
            ip_a, port_a = ep_a.rsplit(':', 1)
            ip_b, port_b = ep_b.rsplit(':', 1)
            proto_l = proto.lower()
            expr = (f"ip.addr == {ip_a} && ip.addr == {ip_b} && "
                    f"{proto_l}.port == {port_a} && {proto_l}.port == {port_b}")
        except Exception:
            return
        self._ctx_apply_filter(expr)
        self._goto_tab(self.tab_capture)

    def _ctx_goto_proxy_from_session_key(self, key):
        """From sessions: jump to the first Proxy HTTP entry for this session."""
        try:
            _, ep_a, ep_b = key
            ip_a, port_a = ep_a.rsplit(':', 1)
            ip_b, port_b = ep_b.rsplit(':', 1)
            endpoints = frozenset([(ip_a, int(port_a)), (ip_b, int(port_b))])
        except Exception:
            return
        for idx, entry in enumerate(self._proxy_http_entries):
            sk = entry.get('stream_key')
            if sk and len(sk) == 4:
                src, sport, dst, dport = sk
                if frozenset([(src, sport), (dst, dport)]) == endpoints:
                    for r in range(self.http_table.rowCount()):
                        it = self.http_table.item(r, 0)
                        if it and it.data(Qt.UserRole) == idx:
                            self.insp_tabs.setCurrentIndex(0)
                            self.http_table.selectRow(r)
                            self._proxy_http_row_selected(r)
                            self._goto_tab(self.tab_proxy)
                            return
        QtWidgets.QMessageBox.information(
            self, "Not found", "No Inspector entry found for this session.")

    def _ctx_goto_session_from_proxy_entry(self, entry):
        """From proxy: jump to the matching session in the Sessions tab."""
        sk = entry.get('stream_key')
        if not sk:
            return
        self._refresh_sessions()
        target_key = None
        if len(sk) == 4:
            src, sport, dst, dport = sk
            ep_a, ep_b = f"{src}:{sport}", f"{dst}:{dport}"
            candidate = ('TCP', min(ep_a, ep_b), max(ep_a, ep_b))
            if candidate in self._sessions:
                target_key = candidate
        if target_key is None and len(sk) >= 2:
            # TLS entry: match by destination port
            port = sk[1]
            for k in self._session_keys:
                if f":{port}" in k[1] or f":{port}" in k[2]:
                    target_key = k
                    break
        if target_key:
            idx = self._session_keys.index(target_key)
            self.sessions_table.selectRow(idx)
            self._show_session_stream(idx, 0)
            self._goto_tab(self.tab_sessions)
        else:
            QtWidgets.QMessageBox.information(
                self, "Not found", "No session found for this Proxy entry.")

    def _ctx_goto_capture_from_proxy_entry(self, entry):
        """From proxy: filter capture to show packets for this stream."""
        sk = entry.get('stream_key')
        if sk and len(sk) == 4:
            src, sport, dst, dport = sk
            ep_a, ep_b = f"{src}:{sport}", f"{dst}:{dport}"
            session_key = ('TCP', min(ep_a, ep_b), max(ep_a, ep_b))
            self._ctx_goto_capture_from_session_key(session_key)
        else:
            # TLS entry: filter by host/port
            host = entry.get('host', '')
            port = sk[1] if sk and len(sk) >= 2 else None
            if port:
                self._ctx_apply_filter(f"tcp.port == {port}")
                self._goto_tab(self.tab_capture)

    # ------------------------------------------------------------------
    # Sessions context menu
    # ------------------------------------------------------------------

    def _show_session_context_menu(self, global_pos):
        rows = sorted({item.row() for item in self.sessions_table.selectedItems()})
        if not rows:
            row = self.sessions_table.rowAt(
                self.sessions_table.viewport().mapFromGlobal(global_pos).y())
            if row < 0:
                return
            rows = [row]
        row = rows[0]
        if row >= len(self._session_keys):
            return
        key = self._session_keys[row]

        menu = QMenu(self)
        a = menu.addAction("Show in Capture")
        a.triggered.connect(lambda: self._ctx_goto_capture_from_session_key(key))
        a = menu.addAction("Go to Proxy Entry")
        a.triggered.connect(lambda: self._ctx_goto_proxy_from_session_key(key))
        menu.exec_(global_pos)

    # ------------------------------------------------------------------
    # Proxy HTTP context menu
    # ------------------------------------------------------------------

    def _show_proxy_http_context_menu(self, global_pos):
        rows = sorted({item.row() for item in self.http_table.selectedItems()})
        if not rows:
            row = self.http_table.rowAt(
                self.http_table.viewport().mapFromGlobal(global_pos).y())
            if row < 0:
                return
            rows = [row]
        row = rows[0]
        it = self.http_table.item(row, 0)
        if not it:
            return
        idx = it.data(Qt.UserRole)
        if idx is None or idx >= len(self._proxy_http_entries):
            return
        entry = self._proxy_http_entries[idx]

        menu = QMenu(self)
        a = menu.addAction("Show in Capture")
        a.triggered.connect(lambda: self._ctx_goto_capture_from_proxy_entry(entry))
        a = menu.addAction("Go to Session")
        a.triggered.connect(lambda: self._ctx_goto_session_from_proxy_entry(entry))
        menu.addSeparator()
        a = menu.addAction("Send to Repeater")
        a.triggered.connect(lambda: self._ctx_proxy_entry_to_repeater(entry))
        menu.exec_(global_pos)

    def _ctx_proxy_entry_to_repeater(self, entry):
        """Load the raw request bytes from a proxy HTTP entry into the Repeater."""
        from scapy.layers.inet import IP, TCP
        raw = entry.get('req_raw', b'')
        if not raw:
            return
        s = self._rep_current()
        if s is None:
            return
        try:
            host = entry.get('host', '127.0.0.1') or '127.0.0.1'
            port = entry.get('port', 80) or 80
            pkt = IP(dst=host) / TCP(dport=port) / raw
        except Exception:
            return
        s['pkt'] = pkt
        pkt_bytes = bytes(pkt)
        s['info_bar'].setText(f"  {host}:{port}  (from Proxy)")
        s['info_bar'].show()
        self._rep_fill_table(pkt_bytes)
        self._rep_refresh_tree(pkt_bytes)
        s['response_area'].setRowCount(0)
        s['resp_tree'].clear()
        s['resp_status'].setText("")
        self._goto_tab(self.tab_repeater)

    def _ctx_copy_hex(self, pkt):
        data = bytes(pkt)
        hexstr = ' '.join(f'{b:02X}' for b in data)
        QtWidgets.QApplication.clipboard().setText(hexstr)

    def _ctx_copy_escaped(self, pkt):
        data = bytes(pkt)
        escaped = ''.join(f'\\x{b:02x}' for b in data)
        QtWidgets.QApplication.clipboard().setText(escaped)

    def _ctx_toggle_mark(self, row):
        if row in self._marked_rows:
            self._marked_rows.discard(row)
            # Restore original protocol color
            if row < len(self.packet_list):
                proto = get_protocol(self.packet_list[row])
                color = _PROTO_COLORS.get(proto, _PROTO_COLORS.get(proto.split()[0], None))
                for c in range(self.filter_table.columnCount()):
                    item = self.filter_table.item(row, c)
                    if item:
                        item.setBackground(color if color else QtGui.QBrush())
                        item.setForeground(QColor(0, 0, 0))
        else:
            self._marked_rows.add(row)
            self._color_row(row, QColor(0x00, 0x00, 0x00), QColor(0xff, 0xff, 0xff))

    def _ctx_export_pcap(self, packets):
        path, _ = QFileDialog.getSaveFileName(self, "Export PCAP", "", "PCAP files (*.pcap)")
        if path:
            try:
                wrpcap(path, packets)
            except Exception as e:
                QtWidgets.QMessageBox.warning(self, "Export failed", str(e))

    # ------------------------------------------------------------------
    # Capture control
    # ------------------------------------------------------------------

    @staticmethod
    def _nfqueue_holder_pid(queue_num=0):
        """Return the PID holding NFQUEUE <queue_num>, or None if free.

        Reads /proc/net/netfilter/nf_queue which lists active NFQUEUE bindings
        as lines of the form:  queue_num  portid  queue_total  copy_mode ...
        The portid is the netlink port-id, which equals the PID of the binding
        process (kernel convention: nl_pid = pid for the first socket opened by
        that process).
        """
        try:
            with open('/proc/net/netfilter/nf_queue') as fh:
                for line in fh:
                    parts = line.split()
                    if parts and int(parts[0]) == queue_num:
                        return int(parts[1])   # portid == pid
        except (FileNotFoundError, ValueError, PermissionError):
            pass
        return None

    def _check_nfqueue_before_start(self):
        """Return True if safe to proceed; False if the user cancelled."""
        pid = self._nfqueue_holder_pid(0)
        if pid is None:
            return True

        # Try to identify the process name
        try:
            with open(f'/proc/{pid}/comm') as fh:
                pname = fh.read().strip()
        except Exception:
            pname = f"PID {pid}"

        from PyQt5.QtWidgets import QMessageBox
        msg = QMessageBox(self)
        msg.setWindowTitle("NFQUEUE already in use")
        msg.setIcon(QMessageBox.Warning)
        msg.setText(
            f"NFQUEUE 0 is already held by <b>{pname}</b> (PID {pid}).<br><br>"
            "This is usually a leftover SharkPy process that crashed.<br>"
            "Kill it and continue?"
        )
        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.Cancel)
        msg.setDefaultButton(QMessageBox.Yes)
        if msg.exec_() != QMessageBox.Yes:
            return False

        import signal as _signal
        try:
            import os
            os.kill(pid, _signal.SIGTERM)
            import time as _t; _t.sleep(0.4)
            if self._nfqueue_holder_pid(0) == pid:
                os.kill(pid, _signal.SIGKILL)
                _t.sleep(0.2)
        except (ProcessLookupError, PermissionError) as e:
            QMessageBox.critical(self, "Could not kill process",
                                 f"Failed to kill PID {pid}: {e}\n"
                                 "Try running: sudo kill -9 " + str(pid))
            return False
        return True

    def sniff_button_event(self):
        selected_interface = str(self.interface_2.currentText())
        ports = self._selected_proc_ports()
        intercept_mode = self.mode_combo.currentIndex() == 0

        # On Linux intercept mode, verify NFQUEUE 0 is free before starting
        if sys.platform != "win32" and intercept_mode:
            if not self._check_nfqueue_before_start():
                return   # user cancelled or kill failed — leave buttons as-is

        self.sniffButton.setEnabled(False)
        self.haltButton.setEnabled(True)

        if intercept_mode:
            if sys.platform == "win32":
                inner = lambda: self.c.run_windivert(selected_interface, port_filter=ports)
            else:
                inner = lambda: self.c.run(selected_interface, port_filter=ports)
        else:
            bpf = self._ports_to_bpf(ports)
            inner = lambda: self.c.run_sniff(selected_interface, bpf_filter=bpf)

        def _guarded():
            try:
                inner()
            except OSError as exc:
                if "queue" in str(exc).lower() or "nfqueue" in str(exc).lower() or "Failed to create" in str(exc):
                    QMetaObject.invokeMethod(self, "_nfqueue_error_dialog",
                                            Qt.QueuedConnection)
                else:
                    raise

        self.t = threading.Thread(target=_guarded, daemon=True)
        self.t.start()

    def stop_button_event(self):
        self.sniffButton.setEnabled(True)
        self.haltButton.setEnabled(False)
        self.c.stop()

    @pyqtSlot()
    def _nfqueue_error_dialog(self):
        """Show a dialog when NFQUEUE 0 is already in use, with a one-click fix."""
        self.sniffButton.setEnabled(True)
        self.haltButton.setEnabled(False)
        self.c.is_started = False

        from PyQt5.QtWidgets import QMessageBox
        msg = QMessageBox(self)
        msg.setWindowTitle("NFQUEUE 0 already in use")
        msg.setIcon(QMessageBox.Warning)
        msg.setText(
            "<b>Failed to create NFQUEUE 0.</b><br><br>"
            "A previous SharkPy session did not clean up its iptables rules.<br>"
            "Click <b>Fix &amp; Retry</b> to flush the stale rules and restart capture, "
            "or <b>Cancel</b> to fix it manually."
        )
        fix_btn = msg.addButton("Fix && Retry", QMessageBox.AcceptRole)
        msg.addButton("Cancel", QMessageBox.RejectRole)
        msg.exec_()
        if msg.clickedButton() is fix_btn:
            import subprocess
            try:
                subprocess.run(["iptables", "--flush"], check=True, capture_output=True)
                subprocess.run(["iptables", "-t", "nat", "--flush"],
                               check=True, capture_output=True)
            except Exception as e:
                QMessageBox.critical(self, "Flush failed",
                                     f"Could not flush iptables rules:\n{e}\n\n"
                                     "Try manually: sudo iptables -F")
                return
            # Re-trigger capture
            self.sniff_button_event()

    # ------------------------------------------------------------------
    # Per-process filtering
    # ------------------------------------------------------------------

    def _refresh_proc_list(self):
        """Populate proc_combo with running processes that have open connections."""
        current = self.proc_combo.currentData()
        self.proc_combo.blockSignals(True)
        self.proc_combo.clear()
        self.proc_combo.addItem("All traffic", userData=None)
        seen_pids = set()
        try:
            conns = psutil.net_connections(kind='inet')
            pid_ports = {}
            for c in conns:
                if c.pid and c.laddr:
                    pid_ports.setdefault(c.pid, set()).add(c.laddr.port)
                    if c.raddr:
                        pid_ports[c.pid].add(c.raddr.port)
            for pid, ports in sorted(pid_ports.items()):
                if pid in seen_pids:
                    continue
                seen_pids.add(pid)
                try:
                    name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    name = f"PID {pid}"
                label = f"{name}  (PID {pid})"
                self.proc_combo.addItem(label, userData=pid)
        except Exception:
            pass
        # Restore previous selection if still present
        if current is not None:
            idx = self.proc_combo.findData(current)
            if idx >= 0:
                self.proc_combo.setCurrentIndex(idx)
        self.proc_combo.blockSignals(False)

    def _selected_proc_ports(self):
        """Return set of ports for the selected process, or None for all traffic."""
        pid = self.proc_combo.currentData()
        if pid is None:
            return None
        ports = set()
        try:
            for c in psutil.net_connections(kind='inet'):
                if c.pid == pid:
                    if c.laddr:
                        ports.add(c.laddr.port)
                    if c.raddr:
                        ports.add(c.raddr.port)
        except Exception:
            pass
        return ports if ports else None

    @staticmethod
    def _ports_to_bpf(ports):
        """Convert a set of ports to a BPF filter string."""
        if not ports:
            return None
        clauses = " or ".join(f"port {p}" for p in sorted(ports))
        return clauses

    # ------------------------------------------------------------------
    # Replacer / automod
    # ------------------------------------------------------------------

    def corrupt_button_event(self):
        self.corruptButton.setEnabled(False)
        self.sCorruptButton.setEnabled(True)
        self.c.automod = True

    def stop_corrupt_button_event(self):
        self.sCorruptButton.setEnabled(False)
        self.corruptButton.setEnabled(True)
        self.c.automod = False

    # ------------------------------------------------------------------
    # Debug / intercept stepping
    # ------------------------------------------------------------------

    _STYLE_INTERCEPT_ON  = "background-color: #c0392b; color: white; font-weight: bold;"
    _STYLE_HELD_ROW      = QColor(0xff, 0x80, 0x00)   # orange — packet waiting
    _STYLE_HELD_TEXT     = QColor(0xff, 0xff, 0xff)
    _STYLE_RELEASED_ROW  = QColor(0xaa, 0xaa, 0xaa)   # gray — packet passed through

    def deb_break_button_event(self):
        self.deb_breakButton.setEnabled(False)
        self.deb_breakButton.setStyleSheet(self._STYLE_INTERCEPT_ON)
        self.deb_nextButton.setEnabled(True)
        self.deb_continueButton.setEnabled(True)
        self.debugmode = True

    def deb_next_button_event(self):
        """Forward the held packet (with any edits applied) and mark it gray."""
        self.c._edited_bytes = self._read_held_hex_bytes()
        self._set_hex_editable(False)
        if self._held_row is not None:
            self._color_row(self._held_row, self._STYLE_RELEASED_ROW, QColor(0, 0, 0))
            self._held_row = None
        self.c.debug_step()

    def deb_continue_button_event(self):
        """Disable intercept mode; forward any held packet unchanged."""
        self.deb_breakButton.setEnabled(True)
        self.deb_breakButton.setStyleSheet("")
        self.deb_nextButton.setEnabled(False)
        self.deb_continueButton.setEnabled(False)
        self.c._edited_bytes = None
        self._set_hex_editable(False)
        if self._held_row is not None:
            self._color_row(self._held_row, self._STYLE_RELEASED_ROW, QColor(0, 0, 0))
            self._held_row = None
        self.debugmode = False
        self.c.debug_step()

    def _set_hex_editable(self, editable):
        """Enable/disable editing of hex cells in the capture hex_table."""
        t = self.hex_table
        trigger = (QtWidgets.QAbstractItemView.DoubleClicked
                   if editable else QtWidgets.QAbstractItemView.NoEditTriggers)
        t.setEditTriggers(trigger)
        # Style the table to signal edit mode
        t.setStyleSheet("QTableWidget { border: 2px solid #c0392b; }" if editable else "")

    def _read_held_hex_bytes(self):
        """Read current hex cells from capture hex_table back to bytes."""
        t = self.hex_table
        result = []
        for r in range(t.rowCount()):
            for c in range(self._HEX_FIRST, self._HEX_LAST + 1):
                item = t.item(r, c)
                if item is None or item.text().strip() == "":
                    break
                try:
                    result.append(int(item.text().strip(), 16))
                except ValueError:
                    result.append(0)
        return bytes(result) if result else None

    def _on_hex_cell_changed(self, row, col):
        """Sync hex↔ascii in the capture hex_table during intercept edit."""
        if self._intercept_sync or not self.debugmode:
            return
        t = self.hex_table
        self._intercept_sync = True
        try:
            if self._HEX_FIRST <= col <= self._HEX_LAST:
                item = t.item(row, col)
                if not item:
                    return
                try:
                    byte = int(item.text().strip(), 16)
                except ValueError:
                    return
                asc = chr(byte) if 32 <= byte < 127 else "."
                asc_col = self._ASC_FIRST + (col - self._HEX_FIRST)
                asc_item = t.item(row, asc_col)
                if asc_item:
                    asc_item.setText(asc)
            elif self._ASC_FIRST <= col <= self._ASC_LAST:
                item = t.item(row, col)
                if not item:
                    return
                text = item.text()
                byte = ord(text[0]) if text else 0
                hex_col = self._HEX_FIRST + (col - self._ASC_FIRST)
                hex_item = t.item(row, hex_col)
                if hex_item:
                    hex_item.setText(f"{byte:02X}")
        finally:
            self._intercept_sync = False

    def _color_row(self, row, bg, fg):
        for c in range(self.filter_table.columnCount()):
            item = self.filter_table.item(row, c)
            if item:
                item.setBackground(bg)
                item.setForeground(fg)

    # ------------------------------------------------------------------
    # View helpers
    # ------------------------------------------------------------------

    def clear_view(self):
        self.filter_table.clearContents()
        self.filter_table.setRowCount(0)
        self.detail_tree_widget.clear()
        self.hex_table.setRowCount(0)
        self.packet_list = []
        self.time_list = []
        self.c.packet_counter = 0
        self.c.myturn = 0
        self.initial_time = 0.0
        self._active_filter = ""
        self.filterText.clear()
        self.filterText.setStyleSheet("")
        self._wifi_frames.clear()
        self._bt_events.clear()
        self.wifi_table.setRowCount(0)
        self.bt_table.setRowCount(0)
        self.wifi_detail.clear()
        self.bt_detail.clear()

    # ------------------------------------------------------------------
    # Wireshark-like packet detail tree
    # ------------------------------------------------------------------

    def _layer_summary(self, layer):
        """One-line descriptive header for each protocol layer tree node."""
        n = layer.name
        f = layer.fields

        if n == "Ethernet":
            return (f"Ethernet II,  Src: {f.get('src','?')}  "
                    f"\u2192  Dst: {f.get('dst','?')}")

        if n == "IP":
            return (f"Internet Protocol Version 4,  "
                    f"Src: {f.get('src','?')},  Dst: {f.get('dst','?')}")

        if n == "IPv6":
            return (f"Internet Protocol Version 6,  "
                    f"Src: {f.get('src','?')},  Dst: {f.get('dst','?')}")

        if n == "TCP":
            try:
                flag_str = str(layer.flags)
            except Exception:
                flag_str = str(f.get('flags', ''))
            suffix = f"  [{flag_str}]" if flag_str else ""
            return (f"Transmission Control Protocol,  "
                    f"Src Port: {f.get('sport','?')},  "
                    f"Dst Port: {f.get('dport','?')}{suffix}")

        if n == "UDP":
            return (f"User Datagram Protocol,  "
                    f"Src Port: {f.get('sport','?')},  Dst Port: {f.get('dport','?')},  "
                    f"Len: {f.get('len','?')}")

        if n == "ICMP":
            _ICMP_TYPES = {
                0: "Echo Reply", 3: "Destination Unreachable",
                8: "Echo Request", 11: "Time Exceeded",
                5: "Redirect", 9: "Router Advertisement",
            }
            t = f.get('type', '?')
            return f"Internet Control Message Protocol  ({_ICMP_TYPES.get(t, f'type {t}')})"

        if n == "ARP":
            op = {1: "request", 2: "reply"}.get(f.get('op', 0), "?")
            return (f"Address Resolution Protocol  ({op})  "
                    f"{f.get('psrc','?')} \u2192 {f.get('pdst','?')}")

        if n == "DNS":
            qr = "Response" if f.get('qr') else "Query"
            qdcount = f.get('qdcount', 0)
            return f"Domain Name System  ({qr},  {qdcount} question(s))"

        if n == "Raw":
            load = getattr(layer, 'load', b'')
            return f"Data  ({len(load)} bytes)"

        return n

    def _format_field(self, layer_name, fname, fval):
        """Human-readable 'Label: value' for a single packet field."""
        _LABELS = {
            "sport":    "Source Port",
            "dport":    "Destination Port",
            "ttl":      "Time to Live",
            "seq":      "Sequence Number",
            "ack":      "Acknowledgment Number",
            "window":   "Window Size",
            "dataofs":  "Data Offset",
            "reserved": "Reserved",
            "urgptr":   "Urgent Pointer",
            "frag":     "Fragment Offset",
            "version":  "Version",
            "ihl":      "Header Length",
            "tos":      "DSCP / ECN",
            "len":      "Total Length",
            "id":       "Identification",
            "flags":    "Flags",
            "chksum":   "Checksum",
            "proto":    "Protocol",
            "plen":     "Payload Length",
            "hlim":     "Hop Limit",
            "nh":       "Next Header",
        }
        label = _LABELS.get(fname, fname)

        if fname == "proto" and layer_name == "IP":
            _PROTO_NUMS = {1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6", 58: "ICMPv6", 89: "OSPF"}
            name = _PROTO_NUMS.get(fval, str(fval))
            return f"{label}: {name} ({fval})"

        if fname in ("chksum", "id") and isinstance(fval, int):
            return f"{label}: {fval:#06x}"

        if fname == "type" and layer_name == "Ethernet" and isinstance(fval, int):
            _ETYPES = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6",
                       0x8100: "802.1Q", 0x0842: "WOL"}
            name = _ETYPES.get(fval, "Unknown")
            return f"EtherType: {name} ({fval:#06x})"

        if fname == "ihl" and isinstance(fval, int):
            return f"{label}: {fval * 4} bytes ({fval})"

        if fname == "flags" and layer_name == "IP" and isinstance(fval, int):
            bits = []
            if fval & 0x2: bits.append("Don't Fragment")
            if fval & 0x1: bits.append("More Fragments")
            bits_str = ", ".join(bits) or "None"
            return f"{label}: {fval:#05x}  ({bits_str})"

        if fname == "flags" and layer_name == "TCP":
            try:
                return f"{label}: {fval}  ({int(fval):#04x})"
            except Exception:
                return f"{label}: {fval}"

        return f"{label}: {fval}"

    # ------------------------------------------------------------------
    # Byte-range helpers for tree↔hex sync
    # ------------------------------------------------------------------

    @staticmethod
    def _field_ranges(layer, pkt_bytes):
        """Return {field_name: (abs_start, abs_end)} for each field in layer."""
        layer_start = len(pkt_bytes) - len(bytes(layer))
        ranges = {}
        bit_pos = 0
        for fd in layer.fields_desc:
            try:
                val = layer.getfieldval(fd.name)
                built = fd.addfield(layer, b'', val)
                size_bits = len(built) * 8
            except Exception:
                size_bits = getattr(fd, 'size', None) or getattr(fd, 'sz', 1) * 8
            byte_start = layer_start + bit_pos // 8
            byte_end   = layer_start + (bit_pos + size_bits + 7) // 8
            ranges[fd.name] = (byte_start, byte_end)
            bit_pos += size_bits
        return ranges

    def _set_range(self, item, start, end):
        """Store byte range as Qt.UserRole on a tree item."""
        item.setData(0, Qt.UserRole, (start, end))

    def _get_range(self, item):
        """Return (start, end) stored on tree item, or None."""
        return item.data(0, Qt.UserRole) if item else None

    # ------------------------------------------------------------------
    # Packet detail tree
    # ------------------------------------------------------------------

    def show_packet(self, row, col):
        self.detail_tree_widget.clear()
        if row >= len(self.packet_list):
            return
        pkt = self.packet_list[row]
        pkt_bytes = bytes(pkt)
        t = self.time_list[row] if row < len(self.time_list) else 0.0

        # ── Frame summary (no byte range — spans whole packet) ─────────
        frame_node = QTreeWidgetItem(self.detail_tree_widget,
            [f"Frame {row + 1}: {len(pkt_bytes)} bytes captured"])
        self._set_range(frame_node, 0, len(pkt_bytes))
        QTreeWidgetItem(frame_node, [f"Frame Number: {row + 1}"])
        QTreeWidgetItem(frame_node, [f"Capture Time: {t:.6f} seconds"])
        QTreeWidgetItem(frame_node, [f"Frame Length: {len(pkt_bytes)} bytes ({len(pkt_bytes) * 8} bits)"])

        # ── Protocol layers ────────────────────────────────────────────
        layer = pkt
        while layer and layer.name != "NoPayload":
            layer_bytes = bytes(layer)
            layer_start = len(pkt_bytes) - len(layer_bytes)
            payload_len = len(bytes(layer.payload)) if (layer.payload and layer.payload.name != "NoPayload") else 0
            layer_end   = len(pkt_bytes) - payload_len

            if layer.name == "Raw":
                load = getattr(layer, 'load', b'')
                raw_node = QTreeWidgetItem(self.detail_tree_widget,
                    [f"Data  ({len(load)} bytes)"])
                self._set_range(raw_node, layer_start, layer_end)
                QTreeWidgetItem(raw_node, [f"Hex: {load.hex()}"])
                try:
                    text = load.decode('utf-8', errors='replace')
                    if any(32 <= ord(c) < 127 for c in text):
                        preview = text[:300].replace('\r\n', ' ↵ ').replace('\n', ' ↵ ')
                        QTreeWidgetItem(raw_node, [f"Text: {preview}"])
                except Exception:
                    pass
            else:
                node = QTreeWidgetItem(self.detail_tree_widget,
                    [self._layer_summary(layer)])
                self._set_range(node, layer_start, layer_end)
                try:
                    franges = self._field_ranges(layer, pkt_bytes)
                except Exception:
                    franges = {}
                for fname, fval in layer.fields.items():
                    child = QTreeWidgetItem(node, [self._format_field(layer.name, fname, fval)])
                    if fname in franges:
                        self._set_range(child, *franges[fname])

            layer = layer.payload if layer.payload else None

        self.detail_tree_widget.expandAll()

    # ------------------------------------------------------------------
    # Hex dump  (grid: offset | 16 hex cells | gap | 16 ascii cells)
    # ------------------------------------------------------------------

    # Column layout constants
    _HEX_OFF  = 0          # offset column
    _HEX_FIRST = 1         # first hex byte column
    _HEX_LAST  = 16        # last hex byte column
    _HEX_GAP   = 17        # visual gap
    _ASC_FIRST = 18        # first ascii column
    _ASC_LAST  = 33        # last ascii column

    _COL_HIGHLIGHT = QColor(0x26, 0x8b, 0xd2)   # Wireshark-style blue
    _COL_HL_TEXT   = QColor(0xff, 0xff, 0xff)

    def show_hex_packet(self, row, col):
        t = self.hex_table
        t.setRowCount(0)
        if row >= len(self.packet_list):
            return
        data = bytes(self.packet_list[row])
        n_rows = (len(data) + 15) // 16
        t.setRowCount(n_rows)

        # Set column widths once on first populate
        t.setColumnWidth(self._HEX_OFF, 48)
        for c in range(self._HEX_FIRST, self._HEX_LAST + 1):
            t.setColumnWidth(c, 26)
        t.setColumnWidth(self._HEX_GAP, 10)
        for c in range(self._ASC_FIRST, self._ASC_LAST + 1):
            t.setColumnWidth(c, 13)

        for r in range(n_rows):
            t.setRowHeight(r, 18)
            chunk = data[r * 16:(r + 1) * 16]

            off_item = QtWidgets.QTableWidgetItem(f"{r * 16:04x}")
            off_item.setForeground(QColor(0x99, 0x99, 0x99))
            t.setItem(r, self._HEX_OFF, off_item)

            for i, byte in enumerate(chunk):
                hex_item = QtWidgets.QTableWidgetItem(f"{byte:02X}")
                hex_item.setTextAlignment(Qt.AlignCenter)
                t.setItem(r, self._HEX_FIRST + i, hex_item)

                asc = chr(byte) if 32 <= byte < 127 else "."
                asc_item = QtWidgets.QTableWidgetItem(asc)
                asc_item.setTextAlignment(Qt.AlignCenter)
                t.setItem(r, self._ASC_FIRST + i, asc_item)

    # ------------------------------------------------------------------
    # Tree ↔ hex bidirectional sync
    # ------------------------------------------------------------------

    def _highlight_bytes(self, start, end):
        """Highlight hex + ascii cells for byte range [start, end)."""
        t = self.hex_table
        # Clear previous highlight
        for r in range(t.rowCount()):
            for c in range(1, 34):
                item = t.item(r, c)
                if item:
                    item.setBackground(QtGui.QBrush())
                    item.setForeground(QtGui.QBrush())
        if start is None or end is None or start >= end:
            return
        for byte_idx in range(start, end):
            r, i = divmod(byte_idx, 16)
            if r >= t.rowCount():
                break
            for col in (self._HEX_FIRST + i, self._ASC_FIRST + i):
                item = t.item(r, col)
                if item:
                    item.setBackground(self._COL_HIGHLIGHT)
                    item.setForeground(self._COL_HL_TEXT)
        # Scroll to first highlighted row
        first_row = start // 16
        if first_row < t.rowCount():
            t.scrollToItem(t.item(first_row, self._HEX_FIRST))

    def _on_tree_selection_changed(self, current, previous):
        if self._hex_sync or current is None:
            return
        br = self._get_range(current)
        if br:
            self._highlight_bytes(br[0], br[1])
        else:
            self._highlight_bytes(None, None)

    def _on_hex_cell_clicked(self, row, col):
        """Clicking a hex or ascii cell selects the matching tree field."""
        # Only react to hex or ascii cells
        if col in (self._HEX_OFF, self._HEX_GAP):
            return
        if self._HEX_FIRST <= col <= self._HEX_LAST:
            byte_idx = row * 16 + (col - self._HEX_FIRST)
        elif self._ASC_FIRST <= col <= self._ASC_LAST:
            byte_idx = row * 16 + (col - self._ASC_FIRST)
        else:
            return

        # Walk the tree depth-first for the narrowest matching item
        best = None
        best_span = None
        root = self.detail_tree_widget.invisibleRootItem()

        def walk(item):
            nonlocal best, best_span
            br = self._get_range(item)
            if br and br[0] <= byte_idx < br[1]:
                span = br[1] - br[0]
                if best_span is None or span < best_span:
                    best = item
                    best_span = span
            for i in range(item.childCount()):
                walk(item.child(i))

        for i in range(root.childCount()):
            walk(root.child(i))

        if best:
            self._hex_sync = True
            self.detail_tree_widget.setCurrentItem(best)
            self.detail_tree_widget.scrollToItem(best)
            if best.parent():
                best.parent().setExpanded(True)
            br = self._get_range(best)
            self._highlight_bytes(br[0], br[1])
            self._hex_sync = False

    # ------------------------------------------------------------------
    # Packet list (called from capture thread via QueuedConnection)
    # ------------------------------------------------------------------

    @pyqtSlot("PyQt_PyObject", "PyQt_PyObject")
    def push_packets(self, spacket, row="null"):
        is_new = (row == "null")
        if is_new:
            row = self.filter_table.rowCount()
            self.packet_list.append(spacket)
            if self.initial_time == 0.0:
                self.initial_time = _time.time()
            self.time_list.append(_time.time() - self.initial_time)
            self.filter_table.insertRow(row)
        else:
            self.packet_list[row] = spacket

        try:
            proto = get_protocol(spacket)
        except Exception:
            proto = "Unknown"
        t_display = self.time_list[row] if row < len(self.time_list) else 0.0
        color = _PROTO_COLORS.get(proto, _PROTO_COLORS.get(proto.split()[0], None))

        def _safe(fn, default=""):
            try:
                return str(fn())
            except Exception:
                return default

        cols = [
            str(round(t_display, 6)),
            _safe(lambda: packet_src(spacket)),
            _safe(lambda: packet_dst(spacket)),
            proto,
            _safe(lambda: packet_len(spacket)),
            _safe(lambda: spacket.summary()),
        ]
        # Temporarily block itemChanged so editing updates don't re-trigger push
        self.filter_table.blockSignals(True)
        for c, text in enumerate(cols):
            item = QtWidgets.QTableWidgetItem(text)
            # Only src/dst (cols 1,2) are editable
            if c not in (1, 2):
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            if color:
                item.setBackground(color)
                item.setForeground(QColor(0, 0, 0))
            self.filter_table.setItem(row, c, item)
        self.filter_table.blockSignals(False)

        # If intercept mode is active, mark this new row as held (orange)
        if is_new and self.debugmode:
            if self._held_row is not None:
                self._color_row(self._held_row, self._STYLE_RELEASED_ROW, QColor(0, 0, 0))
            self._held_row = row
            self._color_row(row, self._STYLE_HELD_ROW, self._STYLE_HELD_TEXT)
            self.filter_table.scrollToItem(self.filter_table.item(row, 0))
            # Auto-show hex + detail and enable editing
            self.filter_table.selectRow(row)
            self.show_packet(row, 0)
            self.show_hex_packet(row, 0)
            self._set_hex_editable(True)

        # Apply active filter immediately to the new row
        if is_new and self._active_filter:
            hidden = not self._matches_filter(spacket, self._active_filter)
            self.filter_table.setRowHidden(row, hidden)

        if self.auto_down_scroll and is_new:
            sb = self.filter_table.verticalScrollBar()
            if sb.value() >= sb.maximum() - 3:
                self.filter_table.scrollToBottom()

        # Feed proxy tab with new packets only
        if is_new:
            try:
                self._proxy_ingest(spacket, self.time_list[row])
            except Exception as _proxy_exc:
                import logging as _lg
                _lg.getLogger(__name__).warning("proxy_ingest error: %s", _proxy_exc, exc_info=True)

    def expand(self, x):
        yield x.name
        while x.payload:
            x = x.payload
            yield x.name

    # ------------------------------------------------------------------
    # Display filter
    # ------------------------------------------------------------------

    def _apply_filter(self):
        expr = self.filterText.text().strip()
        self._active_filter = expr
        match_count = 0
        for row in range(self.filter_table.rowCount()):
            if row >= len(self.packet_list):
                break
            matches = self._matches_filter(self.packet_list[row], expr)
            self.filter_table.setRowHidden(row, not matches)
            if matches:
                match_count += 1
        # Color bar green/red like Wireshark
        if not expr:
            self.filterText.setStyleSheet("")
        elif match_count:
            self.filterText.setStyleSheet("background-color: #c8e6c9; color: #1b5e20;")
        else:
            self.filterText.setStyleSheet("background-color: #ffcdd2; color: #b71c1c;")

    def _matches_filter(self, pkt, expr):
        if not expr:
            return True

        # AND / OR  (recurse on each clause)
        if re.search(r'\s+&&\s+|\s+and\s+', expr, re.IGNORECASE):
            parts = re.split(r'\s+(?:&&|and)\s+', expr, flags=re.IGNORECASE)
            return all(self._matches_filter(pkt, p.strip()) for p in parts)
        if re.search(r'\s+\|\|\s+|\s+or\s+', expr, re.IGNORECASE):
            parts = re.split(r'\s+(?:\|\||or)\s+', expr, flags=re.IGNORECASE)
            return any(self._matches_filter(pkt, p.strip()) for p in parts)

        lower = expr.lower().strip()

        # Protocol name shortcuts
        _PROTO_CHECKS = {
            'tcp':   lambda p: p.haslayer(TCP),
            'udp':   lambda p: p.haslayer(UDP),
            'icmp':  lambda p: p.haslayer(ICMP),
            'arp':   lambda p: p.haslayer(ARP),
            'ip':    lambda p: p.haslayer(IP),
            'ipv6':  lambda p: p.haslayer(IPv6),
            'http':  lambda p: p.haslayer(TCP) and (80 in (p[TCP].dport, p[TCP].sport)),
            'https': lambda p: p.haslayer(TCP) and (443 in (p[TCP].dport, p[TCP].sport)),
            'dns':   lambda p: (p.haslayer(UDP) and (53 in (p[UDP].dport, p[UDP].sport)))
                               or (p.haslayer(TCP) and (53 in (p[TCP].dport, p[TCP].sport))),
            'ssh':   lambda p: p.haslayer(TCP) and (22 in (p[TCP].dport, p[TCP].sport)),
            'ftp':   lambda p: p.haslayer(TCP) and (21 in (p[TCP].dport, p[TCP].sport)),
            'smtp':  lambda p: p.haslayer(TCP) and (25 in (p[TCP].dport, p[TCP].sport)),
            'smb':   lambda p: p.haslayer(TCP) and (445 in (p[TCP].dport, p[TCP].sport)),
        }
        if lower in _PROTO_CHECKS:
            try:
                return _PROTO_CHECKS[lower](pkt)
            except Exception:
                return False

        # field operator value   e.g.  ip.src == 1.2.3.4
        m = re.match(r'^([\w.]+)\s*(==|!=|eq|ne|>=|<=|>|<|contains)\s*(.+)$', lower)
        if m:
            field, op, value = m.group(1), m.group(2), m.group(3).strip().strip('"\'')
            try:
                return self._eval_field(pkt, field, op, value)
            except Exception:
                return False

        # Fallback: text search across visible columns
        haystack = " ".join([
            packet_src(pkt), packet_dst(pkt),
            get_protocol(pkt), pkt.summary(),
        ]).lower()
        return lower in haystack

    def _eval_field(self, pkt, field, op, value):
        def cmp(a, b):
            try:
                a, b = int(a), int(b)
            except (ValueError, TypeError):
                a, b = str(a).lower(), str(b).lower()
            if op in ('==', 'eq'): return a == b
            if op in ('!=', 'ne'): return a != b
            if op == '>':          return a > b
            if op == '<':          return a < b
            if op == '>=':         return a >= b
            if op == '<=':         return a <= b
            if op == 'contains':   return str(b) in str(a)
            return False

        _MAP = {
            'ip.src':     lambda p: p.haslayer(IP)  and cmp(p[IP].src,   value),
            'ip.dst':     lambda p: p.haslayer(IP)  and cmp(p[IP].dst,   value),
            'ip.addr':    lambda p: p.haslayer(IP)  and (cmp(p[IP].src, value) or cmp(p[IP].dst, value)),
            'ip.ttl':     lambda p: p.haslayer(IP)  and cmp(p[IP].ttl,   value),
            'ip.proto':   lambda p: p.haslayer(IP)  and cmp(p[IP].proto, value),
            'ipv6.src':   lambda p: p.haslayer(IPv6) and cmp(p[IPv6].src, value),
            'ipv6.dst':   lambda p: p.haslayer(IPv6) and cmp(p[IPv6].dst, value),
            'ipv6.addr':  lambda p: p.haslayer(IPv6) and (cmp(p[IPv6].src, value) or cmp(p[IPv6].dst, value)),
            'eth.src':    lambda p: p.haslayer(Ether) and cmp(p[Ether].src, value),
            'eth.dst':    lambda p: p.haslayer(Ether) and cmp(p[Ether].dst, value),
            'eth.addr':   lambda p: p.haslayer(Ether) and (cmp(p[Ether].src, value) or cmp(p[Ether].dst, value)),
            'tcp.port':   lambda p: p.haslayer(TCP) and (cmp(p[TCP].sport, value) or cmp(p[TCP].dport, value)),
            'tcp.srcport':lambda p: p.haslayer(TCP) and cmp(p[TCP].sport, value),
            'tcp.dstport':lambda p: p.haslayer(TCP) and cmp(p[TCP].dport, value),
            'udp.port':   lambda p: p.haslayer(UDP) and (cmp(p[UDP].sport, value) or cmp(p[UDP].dport, value)),
            'udp.srcport':lambda p: p.haslayer(UDP) and cmp(p[UDP].sport, value),
            'udp.dstport':lambda p: p.haslayer(UDP) and cmp(p[UDP].dport, value),
            'frame.len':  lambda p: cmp(len(bytes(p)), value),
        }
        handler = _MAP.get(field)
        return handler(pkt) if handler else False

    # ------------------------------------------------------------------
    # pcap save / load
    # ------------------------------------------------------------------

    def save_pcap(self):
        if not self.packet_list:
            QtWidgets.QMessageBox.information(self, "Save", "No packets to save.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save capture", "", "PCAP files (*.pcap);;All files (*)"
        )
        if not path:
            return
        if not path.lower().endswith('.pcap'):
            path += '.pcap'
        try:
            wrpcap(path, self.packet_list)
            self.statusBar.showMessage(
                f"Saved {len(self.packet_list)} packets to {path}", 4000
            )
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Save Error", str(e))

    def load_pcap(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open capture", "", "PCAP files (*.pcap *.pcapng);;All files (*)"
        )
        if not path:
            return
        try:
            packets = list(rdpcap(path))
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Load Error", str(e))
            return
        if not packets:
            QtWidgets.QMessageBox.information(self, "Load", "No packets found in file.")
            return
        self.clear_view()
        self._proxy_clear()
        # Push packets into view (timestamps will be set to current time by push_packets)
        for pkt in packets:
            self.push_packets(pkt)
        # Overwrite timestamps using the original PCAP packet times
        base_ts = float(packets[0].time)
        for i, pkt in enumerate(packets):
            if i < len(self.time_list):
                self.time_list[i] = round(float(pkt.time) - base_ts, 6)
                it = self.filter_table.item(i, 0)
                if it:
                    it.setText(str(self.time_list[i]))
        self.statusBar.showMessage(
            f"Loaded {len(packets)} packets from {path}", 4000
        )
        self._add_recent_file(path)

    # ------------------------------------------------------------------
    # Recent files
    # ------------------------------------------------------------------

    def _add_recent_file(self, path):
        if path in self._recent_files:
            self._recent_files.remove(path)
        self._recent_files.insert(0, path)
        self._recent_files = self._recent_files[:8]
        self._update_recent_menu()

    def _update_recent_menu(self):
        self.actionOpen_Recent.setEnabled(bool(self._recent_files))
        # Build a submenu on actionOpen_Recent's parent menu
        menu = self.menufile
        # Remove existing recent submenu if present
        if hasattr(self, '_recent_menu') and self._recent_menu:
            menu.removeAction(self._recent_menu.menuAction())
        self._recent_menu = QtWidgets.QMenu("Open Recent", self)
        for path in self._recent_files:
            import os
            a = self._recent_menu.addAction(os.path.basename(path))
            a.setToolTip(path)
            a.triggered.connect(lambda checked=False, p=path: self._load_recent(p))
        if self._recent_files:
            self._recent_menu.addSeparator()
            clr = self._recent_menu.addAction("Clear Recent")
            clr.triggered.connect(self._clear_recent)
        # Insert after actionOpen_Recent in the menu
        menu.insertMenu(self.actionClose, self._recent_menu)

    def _load_recent(self, path):
        import os
        if not os.path.exists(path):
            QtWidgets.QMessageBox.warning(self, "File Not Found", f"File no longer exists:\n{path}")
            self._recent_files.remove(path)
            self._update_recent_menu()
            return
        # Reuse load_pcap logic but bypass dialog
        try:
            packets = list(rdpcap(path))
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Load Error", str(e))
            return
        if not packets:
            QtWidgets.QMessageBox.information(self, "Load", "No packets found in file.")
            return
        self.clear_view()
        self._proxy_clear()
        for pkt in packets:
            self.push_packets(pkt)
        base_ts = float(packets[0].time)
        for i, pkt in enumerate(packets):
            if i < len(self.time_list):
                self.time_list[i] = round(float(pkt.time) - base_ts, 6)
                it = self.filter_table.item(i, 0)
                if it:
                    it.setText(str(self.time_list[i]))
        self.statusBar.showMessage(f"Loaded {len(packets)} packets from {path}", 4000)
        self._add_recent_file(path)

    def _clear_recent(self):
        self._recent_files.clear()
        self._update_recent_menu()

    # ------------------------------------------------------------------
    # About dialog
    # ------------------------------------------------------------------

    def _show_about(self):
        QtWidgets.QMessageBox.about(
            self,
            f"About SharkPy  v{VERSION}",
            f"<h2>SharkPy  <span style='color:#4a9eff'>v{VERSION}</span></h2>"
            "<p>A network analysis and interception tool combining<br>"
            "Wireshark-style packet capture with Burp Suite-style<br>"
            "protocol inspection and manipulation.</p>"
            "<hr>"
            "<table style='margin-top:6px'>"
            "<tr><td><b>Tabs</b></td><td>Capture · Repeater · Sessions · TLS · Intruder · Inspector · Crypto · Attack</td></tr>"
            "<tr><td><b>Protocols</b></td><td>TCP/UDP · HTTP/S · DNS · TLS · FTP · Telnet · SMB · 802.11 · BLE · CAN</td></tr>"
            "<tr><td><b>Built with</b></td><td>Python · Scapy · PyQt5</td></tr>"
            "</table>"
        )

    # Interfaces dialog
    # ------------------------------------------------------------------

    def _show_interfaces_dialog(self):
        try:
            import netifaces
        except ImportError:
            import netifaces2 as netifaces
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView, QPushButton, QHBoxLayout
        dlg = QDialog(self)
        dlg.setWindowTitle("Network Interfaces")
        dlg.resize(560, 320)
        layout = QVBoxLayout(dlg)
        tbl = QTableWidget(0, 4)
        tbl.setHorizontalHeaderLabels(["Interface", "IPv4 Address", "IPv6 Address", "MAC"])
        tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        tbl.horizontalHeader().setStretchLastSection(True)
        tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        tbl.setSelectionBehavior(QTableWidget.SelectRows)
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            ipv4 = ", ".join(a['addr'] for a in addrs.get(netifaces.AF_INET, []))
            ipv6 = ", ".join(a['addr'].split('%')[0] for a in addrs.get(netifaces.AF_INET6, []))
            mac  = ", ".join(a['addr'] for a in addrs.get(netifaces.AF_LINK, []))
            r = tbl.rowCount(); tbl.insertRow(r)
            for c, v in enumerate([iface, ipv4, ipv6, mac]):
                tbl.setItem(r, c, QTableWidgetItem(v))
        layout.addWidget(tbl)
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.close)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)
        dlg.exec_()

    # ------------------------------------------------------------------
    # Firewall dialog
    # ------------------------------------------------------------------

    def _show_firewall_dialog(self):
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QPlainTextEdit, QPushButton, QHBoxLayout
        import subprocess, sys
        dlg = QDialog(self)
        dlg.setWindowTitle("Firewall Rules (iptables)")
        dlg.resize(700, 480)
        layout = QVBoxLayout(dlg)
        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setFont(QtGui.QFont("Monospace", 9))
        if sys.platform == "win32":
            view.setPlainText("iptables is not available on Windows.")
        else:
            out = []
            for cmd in [
                ["iptables", "-L", "-n", "-v"],
                ["iptables", "-t", "nat", "-L", "-n", "-v"],
                ["ip6tables", "-L", "-n", "-v"],
            ]:
                try:
                    r = subprocess.run(cmd, capture_output=True, text=True)
                    out.append("$ " + " ".join(cmd))
                    out.append(r.stdout or r.stderr or "(no output)")
                    out.append("")
                except FileNotFoundError:
                    out.append(f"Command not found: {cmd[0]}")
            view.setPlainText("\n".join(out))
        layout.addWidget(view)
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.close)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)
        dlg.exec_()

    # ------------------------------------------------------------------
    # Themes
    # ------------------------------------------------------------------

    def _apply_light_theme(self):
        QtWidgets.QApplication.instance().setStyleSheet("")

    def _apply_dark_theme(self):
        QtWidgets.QApplication.instance().setStyleSheet("""
            QMainWindow, QDialog, QWidget {
                background-color: #2b2b2b; color: #f0f0f0;
            }
            QMenuBar { background-color: #3c3f41; color: #f0f0f0; }
            QMenuBar::item:selected { background-color: #4c5052; }
            QMenu { background-color: #3c3f41; color: #f0f0f0; border: 1px solid #555; }
            QMenu::item:selected { background-color: #4c7899; }
            QTabWidget::pane { border: 1px solid #555; }
            QTabBar::tab { background: #3c3f41; color: #f0f0f0; padding: 4px 10px; border: 1px solid #555; }
            QTabBar::tab:selected { background: #4c7899; }
            QTableWidget { background-color: #313335; color: #f0f0f0; gridline-color: #555;
                           selection-background-color: #4c7899; }
            QHeaderView::section { background-color: #3c3f41; color: #f0f0f0; border: 1px solid #555; }
            QLineEdit, QTextEdit, QPlainTextEdit { background-color: #313335; color: #f0f0f0;
                                                   border: 1px solid #555; }
            QComboBox { background-color: #3c3f41; color: #f0f0f0; border: 1px solid #555; }
            QComboBox QAbstractItemView { background-color: #3c3f41; color: #f0f0f0; }
            QPushButton { background-color: #4c5052; color: #f0f0f0; border: 1px solid #666;
                          padding: 3px 8px; }
            QPushButton:hover { background-color: #5c6365; }
            QPushButton:disabled { color: #888; }
            QGroupBox { color: #f0f0f0; border: 1px solid #555; margin-top: 6px; }
            QGroupBox::title { color: #aaa; }
            QScrollBar:vertical { background: #3c3f41; width: 10px; }
            QScrollBar::handle:vertical { background: #666; min-height: 20px; }
            QSplitter::handle { background: #555; }
            QTreeWidget { background-color: #313335; color: #f0f0f0;
                          selection-background-color: #4c7899; }
            QStatusBar { background-color: #3c3f41; color: #f0f0f0; }
        """)

    # ------------------------------------------------------------------
    # TLS interception
    # ------------------------------------------------------------------

    def _update_ca_status(self):
        if self._ca.is_ready:
            self.tls_ca_status.setText(f"CA ready  ({self._ca.ca_cert_path})")
            self.tls_ca_status.setStyleSheet("color: green;")
        else:
            self.tls_ca_status.setText("CA: not generated")
            self.tls_ca_status.setStyleSheet("color: gray;")

    def _tls_gen_ca(self):
        reply = QtWidgets.QMessageBox.question(
            self, "Generate CA",
            "Generate a new root CA?\n\n"
            "If you already have one, this will replace it and invalidate\n"
            "all previously trusted certificates.",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
        )
        if reply != QtWidgets.QMessageBox.Yes:
            return
        try:
            self._ca.generate_ca()
            self._update_ca_status()
            QtWidgets.QMessageBox.information(
                self, "CA Generated",
                f"CA certificate saved to:\n{self._ca.ca_cert_path}\n\n"
                "Click 'Export CA cert...' and install it in your OS / browser\n"
                "trust store so forged certificates are accepted.",
            )
        except Exception as exc:
            QtWidgets.QMessageBox.critical(self, "Error", str(exc))

    def _tls_export_ca(self):
        if not self._ca.is_ready:
            QtWidgets.QMessageBox.warning(self, "No CA", "Generate a CA first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CA certificate", "SharkPy-CA.crt",
            "Certificate (*.crt);;All files (*)"
        )
        if path:
            try:
                self._ca.export_ca(path)
                QtWidgets.QMessageBox.information(
                    self, "Exported",
                    f"CA cert saved to:\n{path}\n\n"
                    "Install it as a trusted root CA in your OS or browser.\n\n"
                    "  Linux :  sudo cp SharkPy-CA.crt /usr/local/share/ca-certificates/\n"
                    "           sudo update-ca-certificates\n"
                    "  Windows: double-click → Install → Trusted Root Certification Authorities\n"
                    "  Firefox: Settings → Privacy → Certificates → Import",
                )
            except Exception as exc:
                QtWidgets.QMessageBox.critical(self, "Export failed", str(exc))

    @staticmethod
    def _parse_ports(text, default):
        """Parse comma-separated port string; return list of ints."""
        try:
            return [int(p.strip()) for p in text.split(',') if p.strip()]
        except ValueError:
            return [default]

    def _tls_start(self):
        if not self._ca.is_ready:
            QtWidgets.QMessageBox.warning(
                self, "No CA",
                "Generate a CA first (and install it as trusted).")
            return
        try:
            proxy_port = int(self.tls_proxy_port.text())
        except ValueError:
            QtWidgets.QMessageBox.warning(self, "Invalid port", "Proxy port must be a number.")
            return
        intercept_ports = self._parse_ports(self.tls_intercept_port.text(), 443)

        self._tls_proxy.listen_port = proxy_port
        self._tls_proxy.start()

        if sys.platform != "win32":
            try:
                tls_intercept(intercept_ports, proxy_port)
            except Exception as exc:
                QtWidgets.QMessageBox.warning(
                    self, "iptables failed",
                    f"{exc}\n\nProxy is running but traffic is not being redirected.\n"
                    "Make sure you are root and iptables is available.",
                )
            if self.tls_block_quic_cb.isChecked():
                try:
                    quic_block(intercept_ports)
                except Exception:
                    pass

        ports_str = ', '.join(str(p) for p in intercept_ports)
        quic_note = "  +QUIC blocked" if (sys.platform != "win32" and self.tls_block_quic_cb.isChecked()) else ""
        self.tls_proxy_status.setText(f"Active  [{ports_str} → {proxy_port}]{quic_note}")
        self.tls_proxy_status.setStyleSheet("color: #40c060; font-weight: bold;")
        self.tls_start_btn.setEnabled(False)
        self.tls_stop_btn.setEnabled(True)

    def _tls_stop(self):
        try:
            proxy_port = int(self.tls_proxy_port.text())
        except ValueError:
            proxy_port = 8443
        intercept_ports = self._parse_ports(self.tls_intercept_port.text(), 443)

        self._tls_proxy.stop()

        if sys.platform != "win32":
            try:
                tls_flush(intercept_ports, proxy_port)
            except Exception:
                pass
            try:
                quic_unblock(intercept_ports)
            except Exception:
                pass

        self.tls_proxy_status.setText("Stopped")
        self.tls_proxy_status.setStyleSheet("")
        self.tls_start_btn.setEnabled(True)
        self.tls_stop_btn.setEnabled(False)

    def _tcp_start(self):
        try:
            proxy_port = int(self.tcp_proxy_port.text())
        except ValueError:
            QtWidgets.QMessageBox.warning(self, "Invalid port", "Proxy port must be a number.")
            return
        intercept_ports = self._parse_ports(self.tcp_intercept_port.text(), 80)

        self._tcp_proxy.listen_port = proxy_port
        self._tcp_proxy.start()

        if sys.platform != "win32":
            try:
                tcp_intercept(intercept_ports, proxy_port)
            except Exception as exc:
                QtWidgets.QMessageBox.warning(
                    self, "iptables failed",
                    f"{exc}\n\nTCP proxy is running but traffic is not being redirected.\n"
                    "Make sure you are root and iptables is available.",
                )

        ports_str = ', '.join(str(p) for p in intercept_ports)
        self.tcp_proxy_status.setText(f"Active  [{ports_str} → {proxy_port}]")
        self.tcp_proxy_status.setStyleSheet("color: #40c060; font-weight: bold;")
        self.tcp_start_btn.setEnabled(False)
        self.tcp_stop_btn.setEnabled(True)

    def _tcp_stop(self):
        try:
            proxy_port = int(self.tcp_proxy_port.text())
        except ValueError:
            proxy_port = 8080
        intercept_ports = self._parse_ports(self.tcp_intercept_port.text(), 80)

        self._tcp_proxy.stop()

        if sys.platform != "win32":
            try:
                tcp_flush(intercept_ports, proxy_port)
            except Exception:
                pass

        self.tcp_proxy_status.setText("Stopped")
        self.tcp_proxy_status.setStyleSheet("")
        self.tcp_start_btn.setEnabled(True)
        self.tcp_stop_btn.setEnabled(False)

    def closeEvent(self, event):
        """Stop capture thread, flush iptables, stop proxies — in that order."""
        # 1. Stop the capture thread and wait for it to exit so it can't
        #    call back into this (soon-to-be-deleted) Qt object.
        try:
            if self.c.is_started:
                self.c.stop()
        except Exception:
            pass
        try:
            if hasattr(self, 't') and self.t.is_alive():
                self.t.join(timeout=1)
        except Exception:
            pass

        # 2. Flush iptables (Linux only).
        if sys.platform != "win32":
            try:
                if self.tls_stop_btn.isEnabled():
                    self._tls_stop()
            except Exception:
                pass
            try:
                if self.tcp_stop_btn.isEnabled():
                    self._tcp_stop()
            except Exception:
                pass
            try:
                flush()
            except Exception:
                pass

        # 3. Stop proxy threads.
        try:
            self._tls_proxy.stop()
        except Exception:
            pass
        try:
            self._tcp_proxy.stop()
        except Exception:
            pass

        # 4. Stop all running attack threads.
        for name, (t, stop_ev) in list(getattr(self, '_atk_threads', {}).items()):
            stop_ev.set()

        event.accept()

    @pyqtSlot(str, int, int, str, bytes)
    def _on_tcp_data(self, hostname: str, conn_id: int, port: int,
                     direction: str, data: bytes):
        """Handle a plaintext TCP chunk — feed into Proxy tab."""
        is_new_conn = conn_id not in self._tcp_http_bufs
        if is_new_conn:
            self._tcp_http_bufs[conn_id] = {
                'host': hostname, 'port': port,
                'req': b'', 'resp': b'',
            }
            self._tcp_conn_count += 1
            self.tcp_proxy_status.setText(
                f"Active  [{self._tcp_conn_count} conn{'s' if self._tcp_conn_count != 1 else ''}]"
            )

        buf = self._tcp_http_bufs[conn_id]
        t   = _time.time() - self.initial_time if self.initial_time else 0.0

        if direction == '→':
            buf['req'] += data
            for msg in _http_split(buf['req']):
                buf['req'] = buf['req'][len(msg):]
                self._proxy_parse_tls_http(msg, hostname, port, t,
                                           is_request=True, conn_id=conn_id)
        else:
            buf['resp'] += data
            for msg in _http_split(buf['resp']):
                buf['resp'] = buf['resp'][len(msg):]
                self._proxy_parse_tls_http(msg, hostname, port, t,
                                           is_request=False, conn_id=conn_id)

        # Feed raw stream into Conversations view
        self._proxy_ingest_raw_tcp(hostname, port, conn_id, direction, data, t)

        # Auto-switch Inspector tab to Streams on first new TCP connection
        if is_new_conn and self.insp_tabs.currentIndex() == 0 and not self._proxy_http_entries:
            self.insp_tabs.setCurrentIndex(2)

    @pyqtSlot(int, str)
    def _on_tcp_conn_failed(self, conn_id: int, reason: str):
        self.tcp_proxy_status.setText("Error — see below")
        self.tcp_proxy_status.setStyleSheet("color: #e05050; font-weight: bold;")
        QtWidgets.QMessageBox.warning(
            self, "TCP Proxy — connection failed",
            f"Connection {conn_id} could not be handled:\n\n{reason}\n\n"
            "Common causes:\n"
            "• Not running as root (iptables requires root)\n"
            "• SO_ORIGINAL_DST unavailable — try: modprobe nf_conntrack\n"
            "• iptables REDIRECT rule not set (use Start button first)"
        )

    def _proxy_ingest_raw_tcp(self, hostname, port, conn_id, direction, data, t):
        """Feed a raw TCP chunk directly into the Conversations view."""
        key = ('tcp', conn_id)
        if key not in self._proxy_conv_map:
            client = f"{hostname}:?"
            server = f"{hostname}:{port}"
            conv = {
                'proto': 'TCP', 'client': client, 'server': server,
                'pkts': 0, 'bytes': 0, 'start': t,
                'stream_a2b': b'', 'stream_b2a': b'',
                'key': key,
            }
            self._proxy_conv_map[key] = conv
            self._proxy_conv_list.append(conv)
            self._proxy_conv_add_row(conv, len(self._proxy_conv_list) - 1)
        else:
            conv = self._proxy_conv_map[key]

        idx = self._proxy_conv_list.index(conv)
        conv['pkts']  += 1
        conv['bytes'] += len(data)
        if direction == '→':
            conv['stream_a2b'] += data
        else:
            conv['stream_b2a'] += data
        self._proxy_conv_refresh_row(conv, idx)

    @pyqtSlot(str, int, int, str, bytes)
    def _on_tls_data(self, hostname: str, conn_id: int, port: int,
                     direction: str, data: bytes):
        """Called (in main thread) for every intercepted TLS chunk."""
        # ── TLS tab: raw chunk view ───────────────────────────────────
        row = self.tls_table.rowCount()
        self.tls_table.insertRow(row)
        preview = self._tls_preview(data)
        for col, text in enumerate([hostname, direction, str(len(data)), preview]):
            item = QtWidgets.QTableWidgetItem(text)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self.tls_table.setItem(row, col, item)
        self._tls_intercept_rows.append((hostname, direction, data))
        self.tls_table.scrollToBottom()

        # ── Proxy tab: accumulate per-connection and parse HTTP ───────
        if conn_id not in self._tls_http_bufs:
            self._tls_http_bufs[conn_id] = {
                'host': hostname, 'port': port,
                'req': b'', 'resp': b'',
            }
        buf = self._tls_http_bufs[conn_id]
        t = _time.time() - self.initial_time if self.initial_time else 0.0
        if direction == '→':
            buf['req'] += data
            msgs = _http_split(buf['req'])
            for msg in msgs:
                buf['req'] = buf['req'][len(msg):]
                self._proxy_parse_tls_http(msg, hostname, port, t, is_request=True,
                                           conn_id=conn_id)
        else:
            buf['resp'] += data
            msgs = _http_split(buf['resp'])
            for msg in msgs:
                buf['resp'] = buf['resp'][len(msg):]
                self._proxy_parse_tls_http(msg, hostname, port, t, is_request=False,
                                           conn_id=conn_id)

        # ── SQL protocols over TLS (client→server queries only) ───────
        if direction == '→' and port in (3306, 5432, 1433):
            self._insp_parse_sql_from_tls(data, hostname, port, conn_id, t)

    def _insp_parse_sql_from_tls(self, data: bytes, hostname: str, port: int,
                                  conn_id: int, t: float):
        """Parse decrypted SQL bytes coming out of the TLS proxy."""
        src = f"client:{conn_id}"
        dst = hostname
        sport = conn_id   # use conn_id as a stable fake sport so stream keys stay unique
        dport = port
        if port == 3306:
            self._insp_parse_mysql(None, t, data, src, dst, sport, dport)
        elif port == 5432:
            self._insp_parse_pgsql(None, t, data, src, dst, sport, dport)
        elif port == 1433:
            self._insp_parse_mssql(None, t, data, src, dst, sport, dport)

    def _proxy_parse_tls_http(self, raw: bytes, hostname: str, port: int,
                               t: float, is_request: bool, conn_id: int):
        """Parse a complete HTTP message from a decrypted TLS stream and feed
        it into the Proxy tab, pairing requests with responses by conn_id."""
        if not raw:
            return
        # Only process if it looks like HTTP
        if is_request:
            if not any(raw.startswith(m) for m in
                       (b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ',
                        b'OPTIONS ', b'PATCH ', b'CONNECT ')):
                return
        else:
            if not raw.startswith(b'HTTP/'):
                return

        try:
            header_part, _, body = raw.partition(b'\r\n\r\n')
            lines = header_part.split(b'\r\n')
            first_line = lines[0].decode(errors='replace')
        except Exception:
            return

        stream_key = (hostname, port, conn_id)

        if is_request:
            parts  = first_line.split(' ', 2)
            method = parts[0] if parts else 'GET'
            path   = parts[1] if len(parts) > 1 else '/'
            entry  = {
                'time': t, 'method': method, 'host': hostname, 'path': path,
                'status': '—', 'length': '—',
                'req_raw': raw, 'resp_raw': b'',
                'req_headers': self._http_parse_headers(raw),
                'resp_headers': {},
                'req_body': body, 'resp_body': b'',
                'stream_key': stream_key,
            }
            self._proxy_http_entries.append(entry)
            self._proxy_http_add_row(entry, len(self._proxy_http_entries) - 1)
            # Switch Inspector tab to HTTP so the entry is visible
            if self.insp_tabs.currentIndex() != 0:
                self.insp_tabs.setCurrentIndex(0)
        else:
            parts  = first_line.split(' ', 2)
            status = f"{parts[1]} {parts[2]}".strip() if len(parts) >= 3 else first_line
            # Match to the most recent unmatched request on this conn_id stream
            for entry in reversed(self._proxy_http_entries):
                if entry.get('stream_key') == stream_key and entry['status'] == '—':
                    entry['status']       = status
                    entry['length']       = str(len(body))
                    entry['resp_raw']     = raw
                    entry['resp_headers'] = self._http_parse_headers(raw)
                    entry['resp_body']    = body
                    idx = self._proxy_http_entries.index(entry)
                    self._proxy_http_refresh_row(entry, idx)
                    return

    def _tls_show_row(self, row: int, col: int):
        if row >= len(self._tls_intercept_rows):
            return
        hostname, direction, data = self._tls_intercept_rows[row]
        mode = self.tls_view_mode.currentText()
        self.tls_data_view.setPlainText(
            self._tls_render(data, mode, hostname, direction))

    @staticmethod
    def _tls_preview(data: bytes) -> str:
        try:
            text = data.decode('utf-8', errors='strict')
            clean = ''.join(c if 32 <= ord(c) < 127 or c in '\r\n\t' else '.' for c in text)
            return clean[:120].replace('\r\n', ' ').replace('\n', ' ')
        except UnicodeDecodeError:
            return data[:40].hex()

    @staticmethod
    def _tls_render(data: bytes, mode: str, hostname: str, direction: str) -> str:
        header = f"[ {direction}  {hostname}  {len(data)} bytes ]\n"
        if mode == "Force Hex" or (mode.startswith("Auto") and not _is_printable(data)):
            lines = [header]
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_part   = ' '.join(f'{b:02X}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                lines.append(f"  {i:04x}  {hex_part:<47}  {ascii_part}")
            return '\n'.join(lines)
        else:
            return header + data.decode('utf-8', errors='replace')


    # ------------------------------------------------------------------
    # Repeater
    # ------------------------------------------------------------------

    # Repeater column layout (mirrors capture hex grid)
    _REP_OFF   = 0
    _REP_HEX_FIRST = 1
    _REP_HEX_LAST  = 16
    _REP_GAP   = 17
    _REP_ASC_FIRST = 18
    _REP_ASC_LAST  = 33

    def _make_rep_subtab(self, label="Tab"):
        """Build a Repeater sub-tab widget; return (widget, state_dict)."""
        from PyQt5 import QtCore as _QC
        w = QtWidgets.QWidget()
        vbox = QtWidgets.QVBoxLayout(w)
        vbox.setContentsMargins(4, 4, 4, 4)
        vbox.setSpacing(4)

        # Per-tab send button
        tb = QtWidgets.QHBoxLayout()
        tb.setSpacing(6)
        send_btn = QtWidgets.QPushButton("Send")
        tb.addWidget(send_btn)
        tb.addStretch()
        vbox.addLayout(tb)

        # Summary info bar — shown once a packet is loaded
        info_bar = QtWidgets.QLabel("")
        info_bar.setStyleSheet(
            "background:#2b2b2b; color:#c8c8c8; padding:2px 6px; "
            "font-family:monospace; font-size:10pt; border-bottom:1px solid #444;")
        info_bar.setFixedHeight(22)
        info_bar.hide()
        vbox.addWidget(info_bar)

        # Horizontal splitter: request | response
        hsplit = QtWidgets.QSplitter(_QC.Qt.Horizontal)

        # Request side
        req_w = QtWidgets.QWidget()
        req_vb = QtWidgets.QVBoxLayout(req_w)
        req_vb.setContentsMargins(0, 0, 0, 0)
        req_vb.setSpacing(2)
        req_vb.addWidget(QtWidgets.QLabel("Request / Packet"))
        req_vs = QtWidgets.QSplitter(_QC.Qt.Vertical)

        edit_area = QtWidgets.QTableWidget()
        edit_area.setColumnCount(34)
        edit_area.setRowCount(0)
        edit_area.setShowGrid(False)
        edit_area.horizontalHeader().setVisible(False)
        edit_area.verticalHeader().setVisible(False)
        edit_area.setFont(QtGui.QFont("Monospace", 10))
        edit_area.setWordWrap(False)
        edit_area.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        req_vs.addWidget(edit_area)

        detail_tree = QtWidgets.QTreeWidget()
        detail_tree.setColumnCount(1)
        detail_tree.headerItem().setText(0, "Packet Detail")
        detail_tree.header().setVisible(False)
        req_vs.addWidget(detail_tree)

        req_vs.setSizes([300, 200])
        req_vb.addWidget(req_vs)

        # Response side
        resp_w = QtWidgets.QWidget()
        resp_vb = QtWidgets.QVBoxLayout(resp_w)
        resp_vb.setContentsMargins(0, 0, 0, 0)
        resp_vb.setSpacing(2)
        resp_hdr = QtWidgets.QHBoxLayout()
        resp_hdr.addWidget(QtWidgets.QLabel("Response"))
        resp_status = QtWidgets.QLabel("")
        resp_status.setStyleSheet("color:#888; font-style:italic;")
        resp_hdr.addWidget(resp_status)
        resp_hdr.addStretch()
        resp_vb.addLayout(resp_hdr)
        resp_vs = QtWidgets.QSplitter(_QC.Qt.Vertical)

        response_area = QtWidgets.QTableWidget()
        response_area.setColumnCount(34)
        response_area.setRowCount(0)
        response_area.setShowGrid(False)
        response_area.horizontalHeader().setVisible(False)
        response_area.verticalHeader().setVisible(False)
        response_area.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        response_area.setFont(QtGui.QFont("Monospace", 10))
        response_area.setWordWrap(False)
        resp_vs.addWidget(response_area)

        resp_tree = QtWidgets.QTreeWidget()
        resp_tree.setColumnCount(1)
        resp_tree.headerItem().setText(0, "Response Detail")
        resp_tree.header().setVisible(False)
        resp_vs.addWidget(resp_tree)

        resp_vs.setSizes([300, 200])
        resp_vb.addWidget(resp_vs)

        hsplit.addWidget(req_w)
        hsplit.addWidget(resp_w)
        hsplit.setSizes([600, 600])
        vbox.addWidget(hsplit, stretch=1)

        state = {
            'widget':        w,
            'send_btn':      send_btn,
            'info_bar':      info_bar,
            'edit_area':     edit_area,
            'detail_tree':   detail_tree,
            'response_area': response_area,
            'resp_tree':     resp_tree,
            'resp_status':   resp_status,
            'pkt':           None,
        }
        return w, state

    def _rep_add_tab(self, label=None):
        """Add a new Repeater sub-tab and return its state dict."""
        if label is None:
            label = f"Tab {self.rep_inner_tabs.count() + 1}"
        w, state = self._make_rep_subtab(label)
        idx = self.rep_inner_tabs.addTab(w, label)
        self._rep_tabs.append(state)
        self.rep_inner_tabs.setCurrentIndex(idx)
        # Wire per-tab signals (use default-arg capture to bind current state)
        state['edit_area'].cellChanged.connect(
            lambda r, c, s=state: self._rep_cell_changed_s(r, c, s))
        state['detail_tree'].itemChanged.connect(
            lambda item, col, s=state: self._rep_tree_field_changed_s(item, col, s))
        state['send_btn'].clicked.connect(
            lambda checked=False, s=state: self._repeater_send_s(s))
        return state

    def _rep_close_tab(self, index):
        if self.rep_inner_tabs.count() <= 1:
            return  # always keep at least one tab
        self._rep_tabs.pop(index)
        self.rep_inner_tabs.removeTab(index)

    def _rep_current(self):
        idx = self.rep_inner_tabs.currentIndex()
        if 0 <= idx < len(self._rep_tabs):
            return self._rep_tabs[idx]
        return None

    def _rep_fill_table(self, data):
        """Populate the current tab's edit_area from raw bytes."""
        s = self._rep_current()
        if s is None:
            return
        t = s['edit_area']
        t.blockSignals(True)
        t.setRowCount(0)
        n_rows = (len(data) + 15) // 16
        t.setRowCount(n_rows)

        t.setColumnWidth(self._REP_OFF, 48)
        for c in range(self._REP_HEX_FIRST, self._REP_HEX_LAST + 1):
            t.setColumnWidth(c, 26)
        t.setColumnWidth(self._REP_GAP, 10)
        for c in range(self._REP_ASC_FIRST, self._REP_ASC_LAST + 1):
            t.setColumnWidth(c, 13)

        for r in range(n_rows):
            t.setRowHeight(r, 18)
            chunk = data[r * 16:(r + 1) * 16]

            off_item = QtWidgets.QTableWidgetItem(f"{r * 16:04x}")
            off_item.setFlags(off_item.flags() & ~Qt.ItemIsEditable)
            off_item.setForeground(QColor(0x99, 0x99, 0x99))
            t.setItem(r, self._REP_OFF, off_item)

            for i, byte in enumerate(chunk):
                hex_item = QtWidgets.QTableWidgetItem(f"{byte:02X}")
                hex_item.setTextAlignment(Qt.AlignCenter)
                t.setItem(r, self._REP_HEX_FIRST + i, hex_item)

                asc = chr(byte) if 32 <= byte < 127 else "."
                asc_item = QtWidgets.QTableWidgetItem(asc)
                asc_item.setTextAlignment(Qt.AlignCenter)
                t.setItem(r, self._REP_ASC_FIRST + i, asc_item)

        # Apply hex byte delegate to hex columns only
        delegate = HexByteDelegate(t)
        for c in range(self._REP_HEX_FIRST, self._REP_HEX_LAST + 1):
            t.setItemDelegateForColumn(c, delegate)

        t.blockSignals(False)

    def _rep_read_bytes(self, state=None):
        """Read current hex cells back into a bytes object."""
        s = state if state is not None else self._rep_current()
        if s is None:
            return b''
        t = s['edit_area']
        result = []
        for r in range(t.rowCount()):
            for c in range(self._REP_HEX_FIRST, self._REP_HEX_LAST + 1):
                item = t.item(r, c)
                if item is None or item.text().strip() == "":
                    break
                try:
                    val = int(item.text().strip(), 16)
                    result.append(max(0, min(255, val)))
                except ValueError:
                    result.append(0)
        return bytes(result)

    def _rep_cell_changed_s(self, row, col, state):
        """Sync hex↔ascii when the user edits a cell (per-tab)."""
        if self._rep_sync:
            return
        t = state['edit_area']
        self._rep_sync = True
        try:
            if self._REP_HEX_FIRST <= col <= self._REP_HEX_LAST:
                item = t.item(row, col)
                if item is None:
                    return
                text = item.text().strip()
                try:
                    byte = int(text, 16)
                except ValueError:
                    return
                asc = chr(byte) if 32 <= byte < 127 else "."
                asc_col = self._REP_ASC_FIRST + (col - self._REP_HEX_FIRST)
                asc_item = t.item(row, asc_col)
                if asc_item:
                    asc_item.setText(asc)
                else:
                    ni = QtWidgets.QTableWidgetItem(asc)
                    ni.setTextAlignment(Qt.AlignCenter)
                    t.setItem(row, asc_col, ni)
            elif self._REP_ASC_FIRST <= col <= self._REP_ASC_LAST:
                item = t.item(row, col)
                if item is None:
                    return
                text = item.text()
                byte = ord(text[0]) if text else 0
                hex_col = self._REP_HEX_FIRST + (col - self._REP_ASC_FIRST)
                hex_item = t.item(row, hex_col)
                if hex_item:
                    hex_item.setText(f"{byte:02X}")
                else:
                    ni = QtWidgets.QTableWidgetItem(f"{byte:02X}")
                    ni.setTextAlignment(Qt.AlignCenter)
                    t.setItem(row, hex_col, ni)
        finally:
            self._rep_sync = False
        if not self._rep_tree_sync:
            self._rep_refresh_tree(self._rep_read_bytes(state), state)

    def _rep_refresh_tree(self, data, state=None):
        """Rebuild the detail tree from raw bytes. Field items are editable."""
        s = state if state is not None else self._rep_current()
        if s is None:
            return
        tree = s['detail_tree']
        tree.blockSignals(True)
        tree.clear()
        if not data:
            tree.blockSignals(False)
            return
        try:
            pkt = IP(data)
        except Exception:
            try:
                pkt = Ether(data)
            except Exception:
                tree.blockSignals(False)
                return
        layer = pkt
        while layer and layer.name != "NoPayload":
            node = QTreeWidgetItem(tree, [self._layer_summary(layer)])
            node.setFlags(node.flags() & ~Qt.ItemIsEditable)
            if layer.name == "Raw":
                load = getattr(layer, 'load', b'')
                QTreeWidgetItem(node, [f"Hex: {load.hex()}"])
                try:
                    text = load.decode('utf-8', errors='replace')
                    if any(32 <= ord(c) < 127 for c in text):
                        preview = text[:200].replace('\r\n', ' ↵ ').replace('\n', ' ↵ ')
                        QTreeWidgetItem(node, [f"Text: {preview}"])
                except Exception:
                    pass
            else:
                for fname, fval in layer.fields.items():
                    child = QTreeWidgetItem(node, [self._format_field(layer.name, fname, fval)])
                    child.setFlags(child.flags() | Qt.ItemIsEditable)
                    child.setData(0, Qt.UserRole, (layer.name, fname))
            layer = layer.payload if layer.payload else None
        tree.expandAll()
        tree.blockSignals(False)

    def _rep_tree_field_changed_s(self, item, col, state):
        """User edited a field in the detail tree — apply to hex grid (per-tab)."""
        if self._rep_tree_sync:
            return
        meta = item.data(0, Qt.UserRole)
        if meta is None:
            return
        layer_name, field_name = meta
        text = item.text(0)
        if ': ' not in text:
            return
        new_val_str = text.split(': ', 1)[1].strip()

        self._rep_tree_sync = True
        try:
            raw = self._rep_read_bytes(state)
            try:
                pkt = IP(raw)
            except Exception:
                pkt = Ether(raw)
            layer = pkt
            while layer and layer.name != "NoPayload":
                if layer.name == layer_name:
                    try:
                        try:
                            setattr(layer, field_name, int(new_val_str, 0))
                        except ValueError:
                            setattr(layer, field_name, new_val_str)
                        if pkt.haslayer(IP):
                            pkt[IP].len = None
                            pkt[IP].chksum = None
                        if pkt.haslayer(TCP):
                            pkt[TCP].chksum = None
                        if pkt.haslayer(UDP):
                            pkt[UDP].len = None
                            pkt[UDP].chksum = None
                        new_bytes = bytes(pkt)
                        # Fill into current tab (state dict holds edit_area)
                        s = self._rep_current()
                        if s is state:
                            self._rep_fill_table(new_bytes)
                        else:
                            self._rep_fill_table_s(new_bytes, state)
                        self._rep_refresh_tree(new_bytes, state)
                    except Exception:
                        pass
                    break
                layer = layer.payload if layer.payload else None
        finally:
            self._rep_tree_sync = False

    def _rep_fill_table_s(self, data, state):
        """Populate a specific tab's edit_area (used by tree-field-changed when not active tab)."""
        t = state['edit_area']
        t.blockSignals(True)
        t.setRowCount(0)
        n_rows = (len(data) + 15) // 16
        t.setRowCount(n_rows)
        t.setColumnWidth(self._REP_OFF, 48)
        for c in range(self._REP_HEX_FIRST, self._REP_HEX_LAST + 1):
            t.setColumnWidth(c, 26)
        t.setColumnWidth(self._REP_GAP, 10)
        for c in range(self._REP_ASC_FIRST, self._REP_ASC_LAST + 1):
            t.setColumnWidth(c, 13)
        for r in range(n_rows):
            t.setRowHeight(r, 18)
            chunk = data[r * 16:(r + 1) * 16]
            off_item = QtWidgets.QTableWidgetItem(f"{r * 16:04x}")
            off_item.setFlags(off_item.flags() & ~Qt.ItemIsEditable)
            off_item.setForeground(QColor(0x99, 0x99, 0x99))
            t.setItem(r, self._REP_OFF, off_item)
            for i, byte in enumerate(chunk):
                hex_item = QtWidgets.QTableWidgetItem(f"{byte:02X}")
                hex_item.setTextAlignment(Qt.AlignCenter)
                t.setItem(r, self._REP_HEX_FIRST + i, hex_item)
                asc = chr(byte) if 32 <= byte < 127 else "."
                asc_item = QtWidgets.QTableWidgetItem(asc)
                asc_item.setTextAlignment(Qt.AlignCenter)
                t.setItem(r, self._REP_ASC_FIRST + i, asc_item)
        delegate = HexByteDelegate(t)
        for c in range(self._REP_HEX_FIRST, self._REP_HEX_LAST + 1):
            t.setItemDelegateForColumn(c, delegate)
        t.blockSignals(False)

    def _goto_tab(self, widget):
        """Switch to the tab that contains *widget*, regardless of insertion order."""
        idx = self.tabWidget.indexOf(widget)
        if idx >= 0:
            self.tabWidget.setCurrentIndex(idx)

    def _repeater_load(self):
        """Load the first selected Capture-tab packet into the current Repeater tab.

        The hex editor is populated with the *application-layer payload* only —
        not the IP/TCP/UDP headers.  Connection metadata (destination, port,
        transport) is stored in the tab state and used when Send is clicked.
        The protocol detail tree still shows the full packet structure for
        reference.
        """
        selected_rows = sorted({item.row() for item in self.filter_table.selectedItems()})
        if not selected_rows:
            QtWidgets.QMessageBox.information(
                self, "Repeater", "Select a packet in the Capture tab first.")
            return
        row = selected_rows[0]
        if row >= len(self.packet_list):
            return
        s = self._rep_current()
        if s is None:
            return
        pkt = self.packet_list[row]
        t   = self.time_list[row] if row < len(self.time_list) else 0.0
        s['pkt'] = pkt

        # ── Extract connection metadata + application payload ──────────────
        dst_ip = dst_port = None
        transport = "raw"
        is_tls    = False
        payload   = bytes(pkt)      # fallback: full packet bytes

        if pkt.haslayer(TCP):
            dst_ip   = (pkt[IP].dst if pkt.haslayer(IP)
                        else pkt[IPv6].dst if pkt.haslayer(IPv6) else None)
            dst_port = pkt[TCP].dport
            tcp_pl   = (bytes(pkt[TCP].payload)
                        if pkt[TCP].payload
                        and pkt[TCP].payload.name != "NoPayload" else b'')
            is_tls   = dst_port in (443, 8443)
            transport = "tls" if is_tls else "tcp"
            payload   = tcp_pl if tcp_pl else bytes(pkt)   # fallback to raw if SYN/ACK-only

        elif pkt.haslayer(UDP):
            dst_ip   = (pkt[IP].dst if pkt.haslayer(IP)
                        else pkt[IPv6].dst if pkt.haslayer(IPv6) else None)
            dst_port = pkt[UDP].dport
            udp_pl   = (bytes(pkt[UDP].payload)
                        if pkt[UDP].payload
                        and pkt[UDP].payload.name != "NoPayload" else b'')
            transport = "udp"
            payload   = udp_pl if udp_pl else bytes(pkt)

        s['_dst_ip']    = dst_ip
        s['_dst_port']  = dst_port
        s['_transport'] = transport
        s['_tls']       = is_tls

        # ── Info bar ──────────────────────────────────────────────────────
        try:
            from protocol_parser import get_protocol, packet_src
            proto = get_protocol(pkt)
            src   = packet_src(pkt)
            dest  = f"{dst_ip}:{dst_port}" if dst_ip and dst_port else "?"
            label = transport.upper()
            s['info_bar'].setText(
                f"  {t:.6f}s   {src} → {dest}   {proto}   "
                f"{len(payload)} payload bytes   [{label}]")
            s['info_bar'].show()
        except Exception:
            s['info_bar'].hide()

        # ── Populate editor with payload only; tree shows full packet ─────
        self._rep_fill_table(payload)
        self._rep_refresh_tree(bytes(pkt))   # full packet for reference
        s['response_area'].setRowCount(0)
        s['resp_tree'].clear()
        s['resp_status'].setText("")
        self._goto_tab(self.tab_repeater)

    def _repeater_send_s(self, state):
        """Send the packet in a specific tab; update that tab's response widgets."""
        s = state
        if s['pkt'] is None:
            QtWidgets.QMessageBox.information(self, "Repeater", "No packet loaded.")
            return
        s['send_btn'].setEnabled(False)
        s['resp_status'].setText("Sending…")
        s['response_area'].setRowCount(0)
        s['resp_tree'].clear()
        loaded_pkt = s['pkt']

        def _send_thread():
            import socket as _socket
            import ssl as _ssl
            resp_bytes = None
            status     = None
            try:
                payload   = self._rep_read_bytes(s)
                dst_ip    = s.get('_dst_ip')
                dst_port  = s.get('_dst_port')
                transport = s.get('_transport', 'raw')

                if transport in ('tcp', 'tls') and dst_ip and dst_port:
                    # ── TLS: open a fresh TLS connection ─────────────────
                    if transport == 'tls':
                        ctx = _ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = _ssl.CERT_NONE
                        with _socket.create_connection(
                                (dst_ip, dst_port), timeout=5) as raw_sock:
                            with ctx.wrap_socket(
                                    raw_sock, server_hostname=dst_ip) as tls_sock:
                                if payload:
                                    tls_sock.sendall(payload)
                                chunks = []
                                tls_sock.settimeout(2)
                                try:
                                    while True:
                                        chunk = tls_sock.recv(4096)
                                        if not chunk:
                                            break
                                        chunks.append(chunk)
                                except _socket.timeout:
                                    pass
                        resp_bytes = b''.join(chunks)
                        status = (f"TLS {dst_ip}:{dst_port}  ·  "
                                  f"{len(resp_bytes)} bytes received")

                    # ── Plain TCP: open a fresh TCP connection ────────────
                    else:
                        with _socket.create_connection(
                                (dst_ip, dst_port), timeout=5) as sock:
                            if payload:
                                sock.sendall(payload)
                            chunks = []
                            sock.settimeout(2)
                            try:
                                while True:
                                    chunk = sock.recv(4096)
                                    if not chunk:
                                        break
                                    chunks.append(chunk)
                            except _socket.timeout:
                                pass
                        resp_bytes = b''.join(chunks)
                        status = (f"TCP {dst_ip}:{dst_port}  ·  "
                                  f"{len(resp_bytes)} bytes received")

                elif transport == 'udp' and dst_ip and dst_port:
                    # ── UDP: send datagram, wait for reply ────────────────
                    af = (_socket.AF_INET6 if ':' in dst_ip
                          else _socket.AF_INET)
                    sock = _socket.socket(af, _socket.SOCK_DGRAM)
                    sock.settimeout(3)
                    try:
                        sock.sendto(payload, (dst_ip, dst_port))
                        resp_bytes, _ = sock.recvfrom(65535)
                        status = (f"UDP {dst_ip}:{dst_port}  ·  "
                                  f"{len(resp_bytes)} bytes received")
                    except _socket.timeout:
                        status = (f"UDP {dst_ip}:{dst_port}  ·  "
                                  f"sent {len(payload)} bytes (no response)")
                    finally:
                        sock.close()

                else:
                    # ── Raw fallback: ICMP, ARP, control packets ──────────
                    raw = self._rep_read_bytes(s)
                    _ver = (raw[0] >> 4) if raw else 4
                    pkt_send = (IPv6(raw) if _ver == 6
                                else IP(raw) if _ver == 4 else Ether(raw))
                    resp = sr1(pkt_send, timeout=5, verbose=False)
                    resp_bytes = bytes(resp) if resp else None
                    status = (f"{len(resp_bytes)} bytes  ·  {resp.summary()}"
                              if resp else "No response (timeout)")

            except Exception as exc:
                status = f"Error: {exc}"

            self._rep_response_ready.emit(resp_bytes, status, s)

        threading.Thread(target=_send_thread, daemon=True).start()

    def _rep_show_response(self, resp_bytes, status, state):
        """Handle send response — update the specific tab that issued the send."""
        s = state
        s['send_btn'].setEnabled(True)
        s['resp_status'].setText(status)
        if not resp_bytes:
            return
        self._rep_fill_resp_hex_s(resp_bytes, s)
        try:
            resp_pkt = IP(resp_bytes)
        except Exception:
            try:
                resp_pkt = Ether(resp_bytes)
            except Exception:
                resp_pkt = None
        if resp_pkt:
            self._rep_refresh_resp_tree_s(resp_bytes, resp_pkt, s)
        else:
            tree = s['resp_tree']
            tree.clear()
            node = QTreeWidgetItem(tree, [f"Raw data  ({len(resp_bytes)} bytes)"])
            QTreeWidgetItem(node, [f"Hex: {resp_bytes.hex()}"])
            try:
                text = resp_bytes.decode('utf-8', errors='replace')
                if any(32 <= ord(c) < 127 for c in text):
                    preview = text[:500].replace('\r\n', ' ↵ ').replace('\n', ' ↵ ')
                    QTreeWidgetItem(node, [f"Text: {preview}"])
            except Exception:
                pass
            node.setExpanded(True)

    def _rep_fill_resp_hex_s(self, data, state):
        t = state['response_area']
        t.setRowCount(0)
        n_rows = (len(data) + 15) // 16
        t.setRowCount(n_rows)
        t.setColumnWidth(self._REP_OFF, 48)
        for c in range(self._REP_HEX_FIRST, self._REP_HEX_LAST + 1):
            t.setColumnWidth(c, 26)
        t.setColumnWidth(self._REP_GAP, 10)
        for c in range(self._REP_ASC_FIRST, self._REP_ASC_LAST + 1):
            t.setColumnWidth(c, 13)
        for r in range(n_rows):
            t.setRowHeight(r, 18)
            chunk = data[r * 16:(r + 1) * 16]
            off_item = QtWidgets.QTableWidgetItem(f"{r * 16:04x}")
            off_item.setForeground(QColor(0x99, 0x99, 0x99))
            t.setItem(r, self._REP_OFF, off_item)
            for i, byte in enumerate(chunk):
                hi = QtWidgets.QTableWidgetItem(f"{byte:02X}")
                hi.setTextAlignment(Qt.AlignCenter)
                t.setItem(r, self._REP_HEX_FIRST + i, hi)
                asc = chr(byte) if 32 <= byte < 127 else "."
                ai = QtWidgets.QTableWidgetItem(asc)
                ai.setTextAlignment(Qt.AlignCenter)
                t.setItem(r, self._REP_ASC_FIRST + i, ai)

    def _rep_refresh_resp_tree_s(self, data, pkt, state):
        tree = state['resp_tree']
        tree.clear()
        layer = pkt
        while layer and layer.name != "NoPayload":
            node = QTreeWidgetItem(tree, [self._layer_summary(layer)])
            if layer.name == "Raw":
                load = getattr(layer, 'load', b'')
                QTreeWidgetItem(node, [f"Hex: {load.hex()}"])
                try:
                    text = load.decode('utf-8', errors='replace')
                    if any(32 <= ord(c) < 127 for c in text):
                        preview = text[:200].replace('\r\n', ' ↵ ').replace('\n', ' ↵ ')
                        QTreeWidgetItem(node, [f"Text: {preview}"])
                except Exception:
                    pass
            else:
                for fname, fval in layer.fields.items():
                    QTreeWidgetItem(node, [self._format_field(layer.name, fname, fval)])
            layer = layer.payload if layer.payload else None
        tree.expandAll()

    # ------------------------------------------------------------------
    # Intruder
    # ------------------------------------------------------------------

    # Column layout reuses the same constants as the capture hex grid
    _INTR_OFF      = 0
    _INTR_HEX_FIRST = 1
    _INTR_HEX_LAST  = 16
    _INTR_GAP      = 17
    _INTR_ASC_FIRST = 18
    _INTR_ASC_LAST  = 33

    def _make_intr_subtab(self, label="Tab"):
        """Build an Intruder sub-tab widget; return (widget, state_dict)."""
        from PyQt5 import QtCore as _QC

        w = QtWidgets.QWidget()
        vbox = QtWidgets.QVBoxLayout(w)
        vbox.setContentsMargins(4, 4, 4, 4)
        vbox.setSpacing(4)

        # Per-tab load buttons
        load_bar = QtWidgets.QHBoxLayout()
        load_bar.setSpacing(6)
        load_cap_btn = QtWidgets.QPushButton("Load from Capture")
        load_rep_btn = QtWidgets.QPushButton("Load from Repeater")
        load_bar.addWidget(load_cap_btn)
        load_bar.addWidget(load_rep_btn)
        load_bar.addStretch()
        vbox.addLayout(load_bar)

        # Info bar
        info_bar = QtWidgets.QLabel("")
        info_bar.setStyleSheet(
            "background:#2b2b2b; color:#c8c8c8; padding:2px 6px; "
            "font-family:monospace; font-size:10pt; border-bottom:1px solid #444;")
        info_bar.setFixedHeight(22)
        info_bar.hide()
        vbox.addWidget(info_bar)

        # Main splitter: left (hex + detail) | right (payload + results)
        hsplit = QtWidgets.QSplitter(_QC.Qt.Horizontal)

        # Left panel
        left_w = QtWidgets.QWidget()
        left_vb = QtWidgets.QVBoxLayout(left_w)
        left_vb.setContentsMargins(0, 0, 0, 0)
        left_vb.setSpacing(4)

        pos_bar = QtWidgets.QHBoxLayout()
        pos_bar.setSpacing(4)
        mark_btn = QtWidgets.QPushButton("Mark Mode")
        mark_btn.setCheckable(True)
        mark_btn.setToolTip("When active, clicking hex cells marks/unmarks them as payload positions")
        pos_bar.addWidget(mark_btn)
        pos_bar.addWidget(QtWidgets.QLabel("Position:"))
        pos_combo = QtWidgets.QComboBox()
        pos_combo.addItem("Position 1")
        pos_combo.setMinimumWidth(100)
        pos_bar.addWidget(pos_combo)
        add_pos_btn = QtWidgets.QPushButton("+")
        add_pos_btn.setMaximumWidth(28)
        add_pos_btn.setToolTip("Add a new position")
        pos_bar.addWidget(add_pos_btn)
        clear_pos_btn = QtWidgets.QPushButton("Clear")
        clear_pos_btn.setToolTip("Clear current position marks")
        pos_bar.addWidget(clear_pos_btn)
        clear_all_btn = QtWidgets.QPushButton("Clear All")
        pos_bar.addWidget(clear_all_btn)
        pos_bar.addStretch()
        left_vb.addLayout(pos_bar)

        left_vs = QtWidgets.QSplitter(_QC.Qt.Vertical)
        hex_table = QtWidgets.QTableWidget()
        hex_table.setColumnCount(34)
        hex_table.setRowCount(0)
        hex_table.setShowGrid(False)
        hex_table.horizontalHeader().setVisible(False)
        hex_table.verticalHeader().setVisible(False)
        hex_table.setFont(QtGui.QFont("Monospace", 10))
        hex_table.setWordWrap(False)
        left_vs.addWidget(hex_table)

        detail_tree = QtWidgets.QTreeWidget()
        detail_tree.setColumnCount(1)
        detail_tree.headerItem().setText(0, "Packet Detail")
        detail_tree.header().setVisible(False)
        left_vs.addWidget(detail_tree)

        left_vs.setSizes([300, 200])
        left_vb.addWidget(left_vs)
        hsplit.addWidget(left_w)

        # Right panel
        right_vs = QtWidgets.QSplitter(_QC.Qt.Vertical)

        # Payload group
        payload_group = QtWidgets.QGroupBox("Payload")
        pg_layout = QtWidgets.QVBoxLayout(payload_group)
        ptype_bar = QtWidgets.QHBoxLayout()
        ptype_bar.addWidget(QtWidgets.QLabel("Type:"))
        payload_type = QtWidgets.QComboBox()
        payload_type.addItems(["Simple List", "Byte Range", "Number Range", "From File"])
        ptype_bar.addWidget(payload_type)
        ptype_bar.addStretch()
        pg_layout.addLayout(ptype_bar)

        payload_stack = QtWidgets.QStackedWidget()

        p0 = QtWidgets.QWidget()
        p0v = QtWidgets.QVBoxLayout(p0)
        p0v.setContentsMargins(0, 0, 0, 0)
        p0v.addWidget(QtWidgets.QLabel("One item per line  (hex: 'ff 00 41'  or  ASCII text):"))
        payload_list = QtWidgets.QPlainTextEdit()
        payload_list.setFont(QtGui.QFont("Monospace", 10))
        payload_list.setPlaceholderText("admin\npassword\n00 00 00 00\nff ff ff ff")
        p0v.addWidget(payload_list)
        payload_stack.addWidget(p0)

        p1 = QtWidgets.QWidget()
        p1f = QtWidgets.QFormLayout(p1)
        byte_from = QtWidgets.QLineEdit("00")
        byte_to = QtWidgets.QLineEdit("FF")
        byte_step = QtWidgets.QLineEdit("01")
        p1f.addRow("From (hex):", byte_from)
        p1f.addRow("To (hex):", byte_to)
        p1f.addRow("Step (hex):", byte_step)
        payload_stack.addWidget(p1)

        p2 = QtWidgets.QWidget()
        p2f = QtWidgets.QFormLayout(p2)
        num_from = QtWidgets.QLineEdit("0")
        num_to = QtWidgets.QLineEdit("255")
        num_step = QtWidgets.QLineEdit("1")
        num_fmt = QtWidgets.QComboBox()
        num_fmt.addItems(["Decimal (1 byte)", "Hex (1 byte)", "Big-endian 2 bytes", "Big-endian 4 bytes"])
        p2f.addRow("From:", num_from)
        p2f.addRow("To:", num_to)
        p2f.addRow("Step:", num_step)
        p2f.addRow("Format:", num_fmt)
        payload_stack.addWidget(p2)

        p3 = QtWidgets.QWidget()
        p3v = QtWidgets.QVBoxLayout(p3)
        p3v.setContentsMargins(0, 0, 0, 0)
        fh = QtWidgets.QHBoxLayout()
        file_path = QtWidgets.QLineEdit()
        file_path.setPlaceholderText("Path to wordlist…")
        file_btn = QtWidgets.QPushButton("Browse…")
        fh.addWidget(file_path)
        fh.addWidget(file_btn)
        p3v.addLayout(fh)
        p3v.addWidget(QtWidgets.QLabel("One payload per line.  Lines starting with # are ignored."))
        p3v.addStretch()
        payload_stack.addWidget(p3)

        pg_layout.addWidget(payload_stack)
        right_vs.addWidget(payload_group)

        # Results
        res_w = QtWidgets.QWidget()
        rv = QtWidgets.QVBoxLayout(res_w)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.setSpacing(2)
        res_hdr = QtWidgets.QHBoxLayout()
        res_hdr.addWidget(QtWidgets.QLabel("Results"))
        progress_lbl = QtWidgets.QLabel("")
        progress_lbl.setStyleSheet("color: #888;")
        res_hdr.addWidget(progress_lbl)
        res_hdr.addStretch()
        clear_res_btn = QtWidgets.QPushButton("Clear")
        res_hdr.addWidget(clear_res_btn)
        rv.addLayout(res_hdr)

        results_table = QtWidgets.QTableWidget()
        results_table.setColumnCount(5)
        results_table.setRowCount(0)
        results_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        results_table.setSortingEnabled(False)
        results_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        for col, title in enumerate(["#", "Payload(s)", "Status", "Resp Size", "Resp Time (ms)"]):
            results_table.setHorizontalHeaderItem(col, QtWidgets.QTableWidgetItem(title))
        results_table.horizontalHeader().setStretchLastSection(False)
        results_table.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.Stretch)
        results_table.setColumnWidth(0, 45)
        results_table.setColumnWidth(2, 90)
        results_table.setColumnWidth(3, 90)
        results_table.setColumnWidth(4, 100)
        rv.addWidget(results_table)

        right_vs.addWidget(res_w)
        right_vs.setSizes([280, 380])
        hsplit.addWidget(right_vs)
        hsplit.setSizes([700, 500])
        vbox.addWidget(hsplit, stretch=1)

        state = {
            'widget':       w,
            'hex_table':    hex_table,
            'detail_tree':  detail_tree,
            'info_bar':     info_bar,
            'mark_btn':     mark_btn,
            'pos_combo':    pos_combo,
            'payload_type': payload_type,
            'payload_stack': payload_stack,
            'payload_list': payload_list,
            'byte_from': byte_from, 'byte_to': byte_to, 'byte_step': byte_step,
            'num_from': num_from, 'num_to': num_to, 'num_step': num_step,
            'num_fmt': num_fmt,
            'file_path': file_path,
            'results_table': results_table,
            'progress_lbl': progress_lbl,
            'base_bytes':   None,
            'positions':    {},
        }

        # Wire per-tab signals
        payload_type.currentIndexChanged.connect(payload_stack.setCurrentIndex)
        clear_res_btn.clicked.connect(lambda: results_table.setRowCount(0))
        add_pos_btn.clicked.connect(lambda checked=False, s=state: self._intr_add_position_s(s))
        clear_pos_btn.clicked.connect(lambda checked=False, s=state: self._intr_clear_position_s(s))
        clear_all_btn.clicked.connect(lambda checked=False, s=state: self._intr_clear_all_s(s))
        hex_table.cellClicked.connect(lambda r, c, s=state: self._intr_hex_clicked_s(r, c, s))
        load_cap_btn.clicked.connect(lambda checked=False, s=state: self._intr_load_from_capture_s(s))
        load_rep_btn.clicked.connect(lambda checked=False, s=state: self._intr_load_from_repeater_s(s))
        file_btn.clicked.connect(lambda checked=False, s=state: self._intr_browse_file_s(s))
        results_table.installEventFilter(self)
        return w, state

    def _intr_add_tab(self, label=None):
        if label is None:
            label = f"Tab {self.intr_inner_tabs.count() + 1}"
        w, state = self._make_intr_subtab(label)
        idx = self.intr_inner_tabs.addTab(w, label)
        self._intr_tabs.append(state)
        self.intr_inner_tabs.setCurrentIndex(idx)
        return state

    def _intr_close_tab(self, index):
        if self.intr_inner_tabs.count() <= 1:
            return
        self._intr_tabs.pop(index)
        self.intr_inner_tabs.removeTab(index)

    def _intr_current(self):
        idx = self.intr_inner_tabs.currentIndex()
        if 0 <= idx < len(self._intr_tabs):
            return self._intr_tabs[idx]
        return None

    def _intr_fill_table_s(self, data, state):
        """Populate a specific tab's hex_table from raw bytes."""
        t = state['hex_table']
        t.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        t.setRowCount(0)
        n_rows = (len(data) + 15) // 16
        t.setRowCount(n_rows)
        t.setColumnWidth(self._INTR_OFF, 48)
        for c in range(self._INTR_HEX_FIRST, self._INTR_HEX_LAST + 1):
            t.setColumnWidth(c, 26)
        t.setColumnWidth(self._INTR_GAP, 10)
        for c in range(self._INTR_ASC_FIRST, self._INTR_ASC_LAST + 1):
            t.setColumnWidth(c, 13)
        for r in range(n_rows):
            t.setRowHeight(r, 18)
            chunk = data[r * 16:(r + 1) * 16]
            off_item = QtWidgets.QTableWidgetItem(f"{r * 16:04x}")
            off_item.setForeground(QColor(0x99, 0x99, 0x99))
            t.setItem(r, self._INTR_OFF, off_item)
            for i, byte in enumerate(chunk):
                hi = QtWidgets.QTableWidgetItem(f"{byte:02X}")
                hi.setTextAlignment(Qt.AlignCenter)
                t.setItem(r, self._INTR_HEX_FIRST + i, hi)
                ai = QtWidgets.QTableWidgetItem(chr(byte) if 32 <= byte < 127 else ".")
                ai.setTextAlignment(Qt.AlignCenter)
                t.setItem(r, self._INTR_ASC_FIRST + i, ai)
        self._intr_recolor_positions_s(state)

    def _intr_recolor_positions_s(self, state):
        """Repaint hex/ascii cells for a specific tab."""
        t = state['hex_table']
        positions = state['positions']
        for r in range(t.rowCount()):
            for c in range(self._INTR_HEX_FIRST, self._INTR_ASC_LAST + 1):
                item = t.item(r, c)
                if item:
                    item.setBackground(QtGui.QBrush())
                    item.setForeground(QColor(0, 0, 0))
        for pos_num, byte_indices in positions.items():
            color = self._intr_pos_colors[(pos_num - 1) % len(self._intr_pos_colors)]
            for byte_idx in byte_indices:
                r, i = divmod(byte_idx, 16)
                if r >= t.rowCount():
                    continue
                for col in (self._INTR_HEX_FIRST + i, self._INTR_ASC_FIRST + i):
                    item = t.item(r, col)
                    if item:
                        item.setBackground(color)
                        item.setForeground(QColor(0, 0, 0))

    def _intr_hex_clicked_s(self, row, col, state):
        if not state['mark_btn'].isChecked():
            return
        if col in (self._INTR_OFF, self._INTR_GAP):
            return
        if self._INTR_HEX_FIRST <= col <= self._INTR_HEX_LAST:
            byte_idx = row * 16 + (col - self._INTR_HEX_FIRST)
        elif self._INTR_ASC_FIRST <= col <= self._INTR_ASC_LAST:
            byte_idx = row * 16 + (col - self._INTR_ASC_FIRST)
        else:
            return
        if state['base_bytes'] is None or byte_idx >= len(state['base_bytes']):
            return
        pos_num = state['pos_combo'].currentIndex() + 1
        positions = state['positions']
        if pos_num not in positions:
            positions[pos_num] = set()
        if byte_idx in positions[pos_num]:
            positions[pos_num].discard(byte_idx)
        else:
            positions[pos_num].add(byte_idx)
        self._intr_recolor_positions_s(state)

    def _intr_add_position_s(self, state):
        n = state['pos_combo'].count() + 1
        state['pos_combo'].addItem(f"Position {n}")
        state['pos_combo'].setCurrentIndex(n - 1)

    def _intr_clear_position_s(self, state):
        pos_num = state['pos_combo'].currentIndex() + 1
        state['positions'].pop(pos_num, None)
        self._intr_recolor_positions_s(state)

    def _intr_clear_all_s(self, state):
        state['positions'].clear()
        self._intr_recolor_positions_s(state)

    def _intr_load_bytes_s(self, data, pkt, state):
        state['base_bytes'] = data
        state['positions'].clear()
        self._intr_fill_table_s(data, state)
        tree = state['detail_tree']
        tree.clear()
        layer = pkt
        while layer and layer.name != "NoPayload":
            node = QTreeWidgetItem(tree, [self._layer_summary(layer)])
            if layer.name != "Raw":
                for fname, fval in layer.fields.items():
                    QTreeWidgetItem(node, [self._format_field(layer.name, fname, fval)])
            layer = layer.payload if layer.payload else None
        tree.expandAll()
        # Update info bar
        try:
            from protocol_parser import get_protocol, packet_src, packet_dst, packet_len
            proto = get_protocol(pkt)
            src = packet_src(pkt)
            dst = packet_dst(pkt)
            length = packet_len(pkt)
            state['info_bar'].setText(f"  {src} → {dst}   {proto}   {length} bytes")
            state['info_bar'].show()
        except Exception:
            state['info_bar'].hide()
        self.intr_status_lbl.setText(f"Loaded  {len(data)} bytes")

    def _intr_load_from_capture_s(self, state):
        rows = sorted({item.row() for item in self.filter_table.selectedItems()})
        if not rows or rows[0] >= len(self.packet_list):
            QtWidgets.QMessageBox.information(self, "Intruder", "Select a packet in the Capture tab first.")
            return
        pkt = self.packet_list[rows[0]]
        self._intr_load_bytes_s(bytes(pkt), pkt, state)
        self._goto_tab(self.tab_intruder)

    def _intr_load_from_repeater_s(self, state):
        rep_s = self._rep_current()
        if rep_s is None or rep_s['pkt'] is None:
            QtWidgets.QMessageBox.information(self, "Intruder", "No packet loaded in the Repeater.")
            return
        raw = self._rep_read_bytes(rep_s)
        try:
            pkt = IP(raw) if rep_s['pkt'].haslayer(IP) else Ether(raw)
        except Exception:
            pkt = rep_s['pkt']
        self._intr_load_bytes_s(raw, pkt, state)

    def _intr_browse_file_s(self, state):
        path, _ = QFileDialog.getOpenFileName(self, "Open Wordlist", "", "Text files (*.txt);;All files (*)")
        if path:
            state['file_path'].setText(path)

    # ── Payload generation ────────────────────────────────────────────────

    def _intr_payloads_for_position_s(self, state):
        """Return a list of bytes objects for the currently configured payload (per-tab)."""
        ptype = state['payload_type'].currentIndex()

        if ptype == 0:  # Simple List
            items = []
            for line in state['payload_list'].toPlainText().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    tokens = line.split()
                    b = bytes(int(t, 16) for t in tokens)
                    items.append(b)
                except ValueError:
                    items.append(line.encode('latin-1', errors='replace'))
            return items

        elif ptype == 1:  # Byte Range
            try:
                lo   = int(state['byte_from'].text(), 16)
                hi   = int(state['byte_to'].text(), 16)
                step = int(state['byte_step'].text(), 16) or 1
            except ValueError:
                return []
            return [bytes([v]) for v in range(lo, hi + 1, step)]

        elif ptype == 2:  # Number Range
            try:
                lo   = int(state['num_from'].text())
                hi   = int(state['num_to'].text())
                step = int(state['num_step'].text()) or 1
            except ValueError:
                return []
            fmt_idx = state['num_fmt'].currentIndex()
            result = []
            for v in range(lo, hi + 1, step):
                if fmt_idx == 0:   result.append(bytes([v & 0xFF]))
                elif fmt_idx == 1: result.append(bytes([v & 0xFF]))
                elif fmt_idx == 2: result.append(v.to_bytes(2, 'big'))
                else:              result.append(v.to_bytes(4, 'big'))
            return result

        else:  # From File
            path = state['file_path'].text().strip()
            if not path:
                return []
            try:
                with open(path, 'r', errors='replace') as f:
                    lines = f.readlines()
                return [l.rstrip('\n').encode('latin-1', errors='replace')
                        for l in lines if l.strip() and not l.startswith('#')]
            except Exception as e:
                QtWidgets.QMessageBox.warning(self, "Intruder", f"Cannot read file: {e}")
                return []

    def _intr_apply_payload_s(self, base, position_payloads, positions):
        """Apply {pos_num: payload_bytes} to base bytes; positions is the state['positions'] dict."""
        result = bytearray(base)
        for pos_num in sorted(position_payloads.keys(), reverse=True):
            payload = position_payloads[pos_num]
            indices = sorted(positions.get(pos_num, []), reverse=True)
            if not indices:
                continue
            ranges = []
            start = indices[-1]
            end = indices[-1]
            for idx in reversed(indices[:-1]):
                if idx == end + 1:
                    end = idx
                else:
                    ranges.append((start, end))
                    start = idx
                    end = idx
            ranges.append((start, end))
            for i, (rs, re) in enumerate(ranges):
                p = payload if i == len(ranges) - 1 else payload[:1]
                result[rs:re + 1] = p
        return bytes(result)

    # ── Attack execution ──────────────────────────────────────────────────

    def _intr_start(self):
        s = self._intr_current()
        if s is None:
            return
        if s['base_bytes'] is None:
            QtWidgets.QMessageBox.information(self, "Intruder", "Load a packet first.")
            return
        if not any(s['positions'].values()):
            QtWidgets.QMessageBox.information(self, "Intruder",
                "Mark at least one payload position.\n\nEnable Mark Mode and click hex cells.")
            return

        payloads = self._intr_payloads_for_position_s(s)
        if not payloads:
            QtWidgets.QMessageBox.information(self, "Intruder", "No payloads configured.")
            return

        attack = self.intr_attack_combo.currentText()
        active_positions = sorted(p for p, v in s['positions'].items() if v)

        requests = []
        if attack == "Sniper":
            for pos_num in active_positions:
                for p in payloads:
                    requests.append({pos_num: p})
        elif attack == "Battering Ram":
            for p in payloads:
                requests.append({pos_num: p for pos_num in active_positions})
        else:  # Cluster Bomb
            import itertools
            all_lists = [payloads] * len(active_positions)
            for combo in itertools.product(*all_lists):
                requests.append({pos_num: p for pos_num, p in zip(active_positions, combo)})

        s['results_table'].setRowCount(0)
        self._intr_stop_flag = False
        self.intr_start_btn.setEnabled(False)
        self.intr_stop_btn.setEnabled(True)
        self.intr_status_lbl.setText(f"Running  0 / {len(requests)}")
        s['progress_lbl'].setText(f"0 / {len(requests)}")

        base = s['base_bytes']
        positions_snapshot = {k: set(v) for k, v in s['positions'].items()}

        def _attack_thread():
            import socket as _socket
            import time as _time2
            for i, pos_payloads in enumerate(requests):
                if self._intr_stop_flag:
                    break
                payload_label = "  |  ".join(pos_payloads[p].hex() for p in sorted(pos_payloads))
                try:
                    raw = self._intr_apply_payload_s(base, pos_payloads, positions_snapshot)
                    _ver = (raw[0] >> 4) if raw else 4
                    pkt = IPv6(raw) if _ver == 6 else IP(raw)
                    t0 = _time2.time()
                    if pkt.haslayer(TCP):
                        dst_ip = (pkt[IP].dst if pkt.haslayer(IP) else
                                  pkt[IPv6].dst if pkt.haslayer(IPv6) else None)
                        dst_port = pkt[TCP].dport
                        tcp_payload = bytes(pkt[TCP].payload) if pkt[TCP].payload and pkt[TCP].payload.name != "NoPayload" else b''
                        if dst_port == 443 or not tcp_payload:
                            resp = sr1(pkt, timeout=3, verbose=False)
                            resp_bytes = bytes(resp) if resp else None
                        else:
                            with _socket.create_connection((dst_ip, dst_port), timeout=5) as _sock:
                                _sock.sendall(tcp_payload)
                                chunks = []
                                _sock.settimeout(2)
                                try:
                                    while True:
                                        chunk = _sock.recv(4096)
                                        if not chunk:
                                            break
                                        chunks.append(chunk)
                                except _socket.timeout:
                                    pass
                            resp_bytes = b''.join(chunks)
                    else:
                        resp = sr1(pkt, timeout=3, verbose=False)
                        resp_bytes = bytes(resp) if resp else None

                    elapsed_ms = int((_time2.time() - t0) * 1000)
                    status = "OK" if resp_bytes else "No response"
                    resp_size = len(resp_bytes) if resp_bytes else 0
                except Exception as exc:
                    elapsed_ms = 0
                    status = f"Error: {exc}"
                    resp_size = 0
                    resp_bytes = None

                self._intr_result_ready.emit({
                    '_state':    s,
                    'num':       i + 1,
                    'total':     len(requests),
                    'payloads':  payload_label,
                    'status':    status,
                    'resp_size': resp_size,
                    'resp_ms':   elapsed_ms,
                    'resp_bytes': resp_bytes,
                })

            self._intr_result_ready.emit({'_done': True, '_state': s, 'total': len(requests)})

        threading.Thread(target=_attack_thread, daemon=True).start()

    def _intr_stop(self):
        self._intr_stop_flag = True

    def _intr_show_result(self, result):
        s = result.get('_state')
        if result.get('_done'):
            self.intr_start_btn.setEnabled(True)
            self.intr_stop_btn.setEnabled(False)
            total = result['total']
            self.intr_status_lbl.setText(f"Done  {total} / {total}")
            if s:
                s['progress_lbl'].setText(f"{total} / {total}")
            return

        if s is None:
            return
        t = s['results_table']
        row = t.rowCount()
        t.insertRow(row)
        t.setRowHeight(row, 18)

        vals = [str(result['num']), result['payloads'], result['status'],
                str(result['resp_size']), str(result['resp_ms'])]
        status = result['status']
        if status == "OK":
            row_color = QColor(0xc8, 0xf0, 0xc8)
        elif status == "No response":
            row_color = QColor(0xff, 0xf0, 0xb0)
        else:
            row_color = QColor(0xff, 0xcc, 0xcc)

        for c, text in enumerate(vals):
            item = QtWidgets.QTableWidgetItem(text)
            item.setBackground(row_color)
            item.setForeground(QColor(0, 0, 0))
            if result.get('resp_bytes'):
                item.setData(Qt.UserRole, result['resp_bytes'])
            t.setItem(row, c, item)

        num = result['num']
        total = result['total']
        self.intr_status_lbl.setText(f"Running  {num} / {total}")
        s['progress_lbl'].setText(f"{num} / {total}")

    def _intr_result_context_menu(self, global_pos, results_table):
        rows = sorted({item.row() for item in results_table.selectedItems()})
        if not rows:
            return
        item = results_table.item(rows[0], 0)
        resp_bytes = item.data(Qt.UserRole) if item else None

        menu = QMenu(self)
        if resp_bytes:
            a = menu.addAction("Send response to Repeater")
            a.triggered.connect(lambda: self._intr_resp_to_repeater(resp_bytes))
        a = menu.addAction("Clear results")
        a.triggered.connect(lambda: results_table.setRowCount(0))
        menu.exec_(global_pos)

    def _intr_resp_to_repeater(self, resp_bytes):
        """Load an Intruder response into the current Repeater tab."""
        try:
            pkt = IP(resp_bytes)
        except Exception:
            pkt = Ether(resp_bytes)
        s = self._rep_current()
        if s is None:
            return
        s['pkt'] = pkt
        self._rep_fill_table(resp_bytes)
        self._rep_refresh_tree(resp_bytes)
        self._goto_tab(self.tab_repeater)

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # Crypto tab
    # ------------------------------------------------------------------

    def _crypto_input_fmt_changed(self, new_index):
        """Re-encode the input content when the format selector changes."""
        text = self.crypto_input.toPlainText().strip()
        if not text:
            self._crypto_input_fmt_prev = new_index
            return
        old_fmts = ["Text", "Hex", "Base64"]
        old_fmt = old_fmts[self._crypto_input_fmt_prev]
        try:
            import base64 as _b64
            if old_fmt == "Hex":
                raw = bytes.fromhex(text.replace(' ', '').replace('\n', ''))
            elif old_fmt == "Base64":
                raw = _b64.b64decode(text)
            else:
                raw = text.encode('utf-8', errors='replace')
        except Exception:
            # Can't parse — just update the index and leave the text alone
            self._crypto_input_fmt_prev = new_index
            return
        self._crypto_input_fmt_prev = new_index
        # Block signals to avoid recursion, then set text in new format
        self.crypto_input.blockSignals(True)
        self._crypto_set_input_bytes(raw)
        self.crypto_input.blockSignals(False)

    def _crypto_output_fmt_changed(self, _new_index):
        """Re-display the last output bytes in the newly selected format."""
        if self._crypto_last_bytes is not None:
            self._crypto_set_output_bytes(self._crypto_last_bytes)

    def _crypto_get_input_bytes(self):
        """Parse the crypto input area based on the selected format. Returns bytes or None."""
        text = self.crypto_input.toPlainText().strip()
        if not text:
            self.crypto_status.setText("No input.")
            return None
        fmt = self.crypto_input_fmt.currentText()
        try:
            if fmt == "Hex":
                return bytes.fromhex(text.replace(' ', '').replace('\n', ''))
            elif fmt == "Base64":
                import base64 as _b64
                return _b64.b64decode(text)
            else:  # Text
                return text.encode('utf-8', errors='replace')
        except Exception as e:
            self.crypto_status.setText(f"Input parse error: {e}")
            return None

    def _crypto_set_output_bytes(self, data):
        """Display bytes in the output area according to the selected output format."""
        self._crypto_last_bytes = data
        fmt = self.crypto_output_fmt.currentText()
        if fmt == "Hex":
            text = ' '.join(f'{b:02x}' for b in data)
        elif fmt == "Base64":
            import base64 as _b64
            text = _b64.b64encode(data).decode()
        else:  # Text
            text = data.decode('utf-8', errors='replace')
        self.crypto_output.setPlainText(text)

    def _crypto_process(self, direction):
        """direction: 'forward' = encrypt/encode/hash  |  'reverse' = decrypt/decode."""
        import hashlib, hmac as _hmac, base64 as _b64
        from urllib.parse import quote, unquote

        raw = self._crypto_get_input_bytes()
        if raw is None:
            return

        algo = self.crypto_algo.currentText()
        key_str = self.crypto_key.text().strip().replace(' ', '')
        iv_str  = self.crypto_iv.text().strip().replace(' ', '')

        try:
            key = bytes.fromhex(key_str) if key_str else b''
            iv  = bytes.fromhex(iv_str)  if iv_str  else b''
        except ValueError as e:
            self.crypto_status.setText(f"Key/IV parse error: {e}")
            return

        try:
            result = self._crypto_do(algo, direction, raw, key, iv)
        except Exception as e:
            self.crypto_status.setText(f"Error: {e}")
            return

        self._crypto_set_output_bytes(result)
        self.crypto_status.setText(f"OK  —  {len(result)} bytes output")

    def _crypto_do(self, algo, direction, data, key, iv):
        """Dispatch crypto operation. Returns result bytes. Raises on error."""
        import hashlib, hmac as _hmac, base64 as _b64
        from urllib.parse import quote, unquote

        # ── Encoding ──────────────────────────────────────────────────────
        if algo == "Base64":
            return _b64.b64encode(data) if direction == 'forward' else _b64.b64decode(data)

        if algo == "Hex":
            if direction == 'forward':
                return data.hex().encode()
            else:
                return bytes.fromhex(data.decode().replace(' ', ''))

        if algo == "URL":
            if direction == 'forward':
                return quote(data.decode('latin-1', errors='replace'), safe='').encode()
            else:
                return unquote(data.decode('latin-1', errors='replace')).encode('latin-1', errors='replace')

        # ── Hashing (forward only) ────────────────────────────────────────
        if algo == "MD5":
            return hashlib.md5(data).digest()
        if algo == "SHA-1":
            return hashlib.sha1(data).digest()
        if algo == "SHA-256":
            return hashlib.sha256(data).digest()
        if algo == "SHA-512":
            return hashlib.sha512(data).digest()
        if algo == "SHA3-256":
            return hashlib.sha3_256(data).digest()
        if algo == "HMAC-SHA256":
            if not key:
                raise ValueError("HMAC-SHA256 requires a key")
            return _hmac.new(key, data, hashlib.sha256).digest()
        if algo == "HMAC-SHA512":
            if not key:
                raise ValueError("HMAC-SHA512 requires a key")
            return _hmac.new(key, data, hashlib.sha512).digest()

        # ── XOR ───────────────────────────────────────────────────────────
        if algo == "XOR":
            if not key:
                raise ValueError("XOR requires a key")
            return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

        # ── RC4 ───────────────────────────────────────────────────────────
        if algo == "RC4":
            if not key:
                raise ValueError("RC4 requires a key")
            S = list(range(256))
            j = 0
            for i in range(256):
                j = (j + S[i] + key[i % len(key)]) % 256
                S[i], S[j] = S[j], S[i]
            out = []
            i = j = 0
            for byte in data:
                i = (i + 1) % 256
                j = (j + S[i]) % 256
                S[i], S[j] = S[j], S[i]
                out.append(byte ^ S[(S[i] + S[j]) % 256])
            return bytes(out)

        # ── AES ───────────────────────────────────────────────────────────
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as _pad
        from cryptography.hazmat.backends import default_backend

        if algo.startswith("AES-"):
            bits = int(algo.split('-')[1])
            expected_key = bits // 8
            if len(key) != expected_key:
                raise ValueError(f"{algo} requires a {expected_key}-byte key, got {len(key)}")

            mode_str = algo.split('-')[2]  # CBC / ECB / CTR / GCM

            if mode_str == "CBC":
                if len(iv) != 16:
                    raise ValueError("AES-CBC requires a 16-byte IV")
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                if direction == 'forward':
                    padder = _pad.PKCS7(128).padder()
                    padded = padder.update(data) + padder.finalize()
                    enc = cipher.encryptor()
                    return enc.update(padded) + enc.finalize()
                else:
                    dec = cipher.decryptor()
                    padded = dec.update(data) + dec.finalize()
                    unpadder = _pad.PKCS7(128).unpadder()
                    return unpadder.update(padded) + unpadder.finalize()

            elif mode_str == "ECB":
                cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
                if direction == 'forward':
                    padder = _pad.PKCS7(128).padder()
                    padded = padder.update(data) + padder.finalize()
                    enc = cipher.encryptor()
                    return enc.update(padded) + enc.finalize()
                else:
                    dec = cipher.decryptor()
                    padded = dec.update(data) + dec.finalize()
                    unpadder = _pad.PKCS7(128).unpadder()
                    return unpadder.update(padded) + unpadder.finalize()

            elif mode_str == "CTR":
                if len(iv) != 16:
                    raise ValueError("AES-CTR requires a 16-byte nonce/counter")
                cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
                op = cipher.encryptor() if direction == 'forward' else cipher.decryptor()
                return op.update(data) + op.finalize()

            elif mode_str == "GCM":
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                nonce = iv if iv else b'\x00' * 12
                if len(nonce) not in (12, 16):
                    raise ValueError("AES-GCM nonce should be 12 bytes")
                aesgcm = AESGCM(key)
                if direction == 'forward':
                    return nonce + aesgcm.encrypt(nonce, data, None)
                else:
                    # Expect nonce prepended to ciphertext
                    nonce_len = len(iv) if iv else 12
                    n, ct = data[:nonce_len], data[nonce_len:]
                    return aesgcm.decrypt(n, ct, None)

        # ── 3DES-CBC ──────────────────────────────────────────────────────
        if algo == "3DES-CBC":
            from cryptography.hazmat.primitives.ciphers import algorithms as _alg
            if len(key) not in (16, 24):
                raise ValueError("3DES-CBC requires a 16 or 24-byte key")
            if len(iv) != 8:
                raise ValueError("3DES-CBC requires an 8-byte IV")
            cipher = Cipher(_alg.TripleDES(key), modes.CBC(iv), backend=default_backend())
            if direction == 'forward':
                padder = _pad.PKCS7(64).padder()
                padded = padder.update(data) + padder.finalize()
                enc = cipher.encryptor()
                return enc.update(padded) + enc.finalize()
            else:
                dec = cipher.decryptor()
                padded = dec.update(data) + dec.finalize()
                unpadder = _pad.PKCS7(64).unpadder()
                return unpadder.update(padded) + unpadder.finalize()

        # ── ChaCha20-Poly1305 ─────────────────────────────────────────────
        if algo == "ChaCha20-Poly1305":
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            if len(key) != 32:
                raise ValueError("ChaCha20-Poly1305 requires a 32-byte key")
            nonce = iv if iv else b'\x00' * 12
            if len(nonce) != 12:
                raise ValueError("ChaCha20-Poly1305 requires a 12-byte nonce")
            chacha = ChaCha20Poly1305(key)
            if direction == 'forward':
                return nonce + chacha.encrypt(nonce, data, None)
            else:
                nonce_len = len(iv) if iv else 12
                n, ct = data[:nonce_len], data[nonce_len:]
                return chacha.decrypt(n, ct, None)

        raise ValueError(f"Unknown algorithm: {algo}")

    def _crypto_load_from_capture(self):
        rows = sorted({item.row() for item in self.filter_table.selectedItems()})
        if not rows or rows[0] >= len(self.packet_list):
            QtWidgets.QMessageBox.information(self, "Crypto", "Select a packet in the Capture tab first.")
            return
        pkt = self.packet_list[rows[0]]
        # Load the payload (Raw layer) if present, else whole packet bytes
        if pkt.haslayer(Raw):
            data = bytes(pkt[Raw].load)
        else:
            data = bytes(pkt)
        self._crypto_set_input_bytes(data)
        self._goto_tab(self.tab_crypto)

    def _crypto_load_from_repeater(self):
        s = self._rep_current()
        if s is None or s['pkt'] is None:
            QtWidgets.QMessageBox.information(self, "Crypto", "No packet loaded in the Repeater.")
            return
        data = self._rep_read_bytes(s)
        self._crypto_set_input_bytes(data)
        self._goto_tab(self.tab_crypto)

    def _crypto_set_input_bytes(self, data):
        """Load bytes into the input area using the current input format."""
        fmt = self.crypto_input_fmt.currentText()
        if fmt == "Hex":
            self.crypto_input.setPlainText(' '.join(f'{b:02x}' for b in data))
        elif fmt == "Base64":
            import base64 as _b64
            self.crypto_input.setPlainText(_b64.b64encode(data).decode())
        else:
            self.crypto_input.setPlainText(data.decode('utf-8', errors='replace'))

    def _crypto_clear(self):
        self.crypto_input.clear()
        self.crypto_output.clear()
        self.crypto_status.setText("")
        self._crypto_last_bytes = None

    def _crypto_send_to_repeater(self):
        if not self._crypto_last_bytes:
            QtWidgets.QMessageBox.information(self, "Crypto", "No output to send.")
            return
        s = self._rep_current()
        if s is None:
            return
        try:
            pkt = IP(self._crypto_last_bytes)
        except Exception:
            try:
                pkt = Ether(self._crypto_last_bytes)
            except Exception:
                pkt = None
        s['pkt'] = pkt
        self._rep_fill_table(self._crypto_last_bytes)
        if pkt:
            self._rep_refresh_tree(self._crypto_last_bytes)
        self._goto_tab(self.tab_repeater)

    def _crypto_copy_output(self):
        text = self.crypto_output.toPlainText()
        if text:
            QtWidgets.QApplication.clipboard().setText(text)
            self.crypto_status.setText("Copied to clipboard.")

    # ------------------------------------------------------------------
    # Packet Diff / Compare
    # ------------------------------------------------------------------

    # Fields that are auto-computed and expected to differ between packets
    _AUTO_FIELDS = {
        'IP':   {'chksum', 'id'},
        'TCP':  {'chksum', 'seq', 'ack'},
        'UDP':  {'chksum'},
        'ICMP': {'chksum', 'id', 'seq'},
        'ICMPv6': {'cksum'},
        'IPv6': set(),
    }

    def _diff_classify_bytes(self, pkt_a, pkt_b):
        """Return (auto_positions, diff_positions) as sets of byte indices.

        auto_positions  — bytes that differ AND belong to auto-computed fields
        diff_positions  — bytes that differ AND are NOT auto-computed
        """
        ba = bytes(pkt_a)
        bb = bytes(pkt_b)
        max_len = max(len(ba), len(bb))
        # pad shorter packet
        ba_padded = ba + b'\x00' * (max_len - len(ba))
        bb_padded = bb + b'\x00' * (max_len - len(bb))

        # collect auto-field byte ranges from both packets
        auto_ranges = set()
        for pkt, pkt_bytes in [(pkt_a, ba), (pkt_b, bb)]:
            layer = pkt
            while layer and layer.name != "NoPayload":
                layer_name = layer.name
                auto_fnames = self._AUTO_FIELDS.get(layer_name, set())
                if auto_fnames:
                    try:
                        franges = self._field_ranges(layer, pkt_bytes)
                        for fname in auto_fnames:
                            if fname in franges:
                                s, e = franges[fname]
                                auto_ranges.update(range(s, e))
                    except Exception:
                        pass
                layer = layer.payload if layer.payload else None

        auto_positions = set()
        diff_positions = set()
        for i in range(max_len):
            if ba_padded[i] != bb_padded[i]:
                if i in auto_ranges:
                    auto_positions.add(i)
                else:
                    diff_positions.add(i)

        return auto_positions, diff_positions

    def _diff_collect_fields(self, pkt_a, pkt_b):
        """Yield (layer_name, field_name, val_a, val_b, is_auto) for every
        field that differs between the two packets."""
        ba = bytes(pkt_a)
        bb = bytes(pkt_b)

        # walk both packets layer-by-layer in parallel
        layer_a = pkt_a
        layer_b = pkt_b
        while layer_a and layer_a.name != "NoPayload":
            layer_name = layer_a.name
            auto_fnames = self._AUTO_FIELDS.get(layer_name, set())

            # gather field names present in either layer
            fields_a = dict(layer_a.fields)
            layer_b_match = None
            tmp = layer_b
            while tmp and tmp.name != "NoPayload":
                if tmp.name == layer_name:
                    layer_b_match = tmp
                    break
                tmp = tmp.payload if tmp.payload else None

            fields_b = dict(layer_b_match.fields) if layer_b_match else {}
            all_fields = list(fields_a.keys()) + [k for k in fields_b if k not in fields_a]

            for fname in all_fields:
                va = fields_a.get(fname)
                vb = fields_b.get(fname)
                if va != vb:
                    is_auto = fname in auto_fnames
                    yield (layer_name, fname, va, vb, is_auto)

            layer_a = layer_a.payload if layer_a.payload else None

    def _show_packet_diff(self, row_a, row_b):
        from PyQt5.QtWidgets import (
            QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTabWidget,
            QWidget, QTableWidget, QTableWidgetItem, QHeaderView,
            QSplitter, QScrollBar, QPushButton, QSizePolicy,
        )
        from PyQt5.QtCore import QTimer

        pkt_a = self.packet_list[row_a]
        pkt_b = self.packet_list[row_b]
        ba = bytes(pkt_a)
        bb = bytes(pkt_b)

        auto_pos, diff_pos = self._diff_classify_bytes(pkt_a, pkt_b)
        field_diffs = list(self._diff_collect_fields(pkt_a, pkt_b))

        meaningful = [f for f in field_diffs if not f[4]]
        auto_only  = [f for f in field_diffs if f[4]]

        C_DIFF = QColor(0xff, 0xb3, 0x00, 180)   # amber — meaningful diff
        C_AUTO = QColor(0x88, 0x88, 0x88, 130)   # gray  — auto-computed noise
        C_ADD  = QColor(0x40, 0xc0, 0x60, 160)   # green — bytes only in longer pkt

        dlg = QDialog(self)
        dlg.setWindowTitle(f"Packet Diff  —  #{row_a + 1} vs #{row_b + 1}")
        dlg.setMinimumSize(960, 640)
        dlg.setAttribute(Qt.WA_DeleteOnClose)
        dlg_layout = QVBoxLayout(dlg)
        dlg_layout.setSpacing(6)

        # ── Summary banner ─────────────────────────────────────────────
        total_diff = len(diff_pos) + len(auto_pos)
        len_note = ""
        if len(ba) != len(bb):
            len_note = f"  ·  lengths differ ({len(ba)} vs {len(bb)} bytes)"
        summary_text = (
            f"  Packet #{row_a + 1} vs #{row_b + 1}"
            f"  ·  ⚠ {len(meaningful)} meaningful difference{'s' if len(meaningful) != 1 else ''}"
            f"  ·  {len(diff_pos)} payload byte{'s' if len(diff_pos) != 1 else ''} differ"
            f"  ·  {len(auto_only)} auto-computed field{'s' if len(auto_only) != 1 else ''} ignored"
            f"{len_note}"
        )
        banner = QLabel(summary_text)
        banner.setStyleSheet(
            "background:#2a2a2a;color:#f0c060;padding:6px 10px;"
            "font-weight:bold;border-radius:4px;font-size:12px;"
        )
        banner.setWordWrap(True)
        dlg_layout.addWidget(banner)

        tabs = QTabWidget()
        dlg_layout.addWidget(tabs)

        # ── Tab 1: Field Diff ──────────────────────────────────────────
        tab_fields = QWidget()
        fl = QVBoxLayout(tab_fields)
        fl.setContentsMargins(4, 4, 4, 4)

        ftbl = QTableWidget(0, 5)
        ftbl.setHorizontalHeaderLabels(["Layer", "Field", f"Packet #{row_a+1}", f"Packet #{row_b+1}", "Note"])
        ftbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        ftbl.horizontalHeader().setStretchLastSection(True)
        ftbl.setEditTriggers(QTableWidget.NoEditTriggers)
        ftbl.setSelectionBehavior(QTableWidget.SelectRows)
        ftbl.setAlternatingRowColors(False)
        ftbl.verticalHeader().setVisible(False)

        def _add_field_row(layer, field, va, vb, is_auto):
            r = ftbl.rowCount()
            ftbl.insertRow(r)
            items = [
                QTableWidgetItem(layer),
                QTableWidgetItem(field),
                QTableWidgetItem(str(va) if va is not None else "—"),
                QTableWidgetItem(str(vb) if vb is not None else "—"),
                QTableWidgetItem("auto-computed" if is_auto else "different"),
            ]
            bg = C_AUTO if is_auto else C_DIFF
            for it in items:
                it.setBackground(bg)
                it.setForeground(QColor(0xee, 0xee, 0xee) if is_auto else QColor(0x11, 0x11, 0x11))
                ftbl.setItem(r, items.index(it), it)

        # meaningful diffs first, auto-fields at the bottom
        for layer, field, va, vb, is_auto in sorted(field_diffs, key=lambda x: x[4]):
            _add_field_row(layer, field, va, vb, is_auto)

        if ftbl.rowCount() == 0:
            no_diff = QTableWidgetItem("No field differences found — packets are identical")
            ftbl.insertRow(0)
            ftbl.setItem(0, 0, no_diff)
            ftbl.setSpan(0, 0, 1, 5)

        fl.addWidget(ftbl)

        legend_row = QHBoxLayout()
        for color, text in [(C_DIFF, "Meaningful difference"), (C_AUTO, "Auto-computed (noise)")]:
            swatch = QLabel("   ")
            swatch.setStyleSheet(f"background:rgba({color.red()},{color.green()},{color.blue()},200);border-radius:3px;")
            lbl = QLabel(text)
            lbl.setStyleSheet("color:#cccccc;font-size:11px;")
            legend_row.addWidget(swatch)
            legend_row.addWidget(lbl)
            legend_row.addSpacing(16)
        legend_row.addStretch()
        fl.addLayout(legend_row)
        tabs.addTab(tab_fields, "Field Diff")

        # ── Tab 2: Hex Diff ────────────────────────────────────────────
        tab_hex = QWidget()
        hl = QVBoxLayout(tab_hex)
        hl.setContentsMargins(4, 4, 4, 4)

        COLS = 34  # offset(1) + 16 hex + gap(1) + 16 ascii
        HEX_COLS  = list(range(1, 17))
        ASCII_COLS = list(range(18, 34))

        def _make_hex_grid(label_text):
            grp = QWidget()
            grp_l = QVBoxLayout(grp)
            grp_l.setContentsMargins(0, 0, 0, 0)
            grp_l.setSpacing(2)
            lbl = QLabel(label_text)
            lbl.setStyleSheet("color:#aaaaaa;font-size:11px;font-weight:bold;padding:2px 0;")
            grp_l.addWidget(lbl)
            tbl = QTableWidget(0, COLS)
            tbl.setEditTriggers(QTableWidget.NoEditTriggers)
            tbl.setSelectionMode(QTableWidget.NoSelection)
            tbl.verticalHeader().setVisible(False)
            tbl.setShowGrid(False)
            # column headers
            hdrs = ["Offset"] + [f"{i:X}" for i in range(16)] + [""] + [chr(0x20 + i) if 0x20 + i < 0x7f else "." for i in range(16)]
            tbl.setHorizontalHeaderLabels(hdrs)
            tbl.horizontalHeader().setDefaultSectionSize(22)
            tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
            tbl.horizontalHeader().setSectionResizeMode(17, QHeaderView.Fixed)
            tbl.horizontalHeader().resizeSection(17, 8)
            tbl.setFont(QtGui.QFont("Monospace", 9))
            tbl.setStyleSheet("QTableWidget{background:#1e1e1e;color:#dddddd;}")
            grp_l.addWidget(tbl)
            return grp, tbl

        splitter = QSplitter(Qt.Horizontal)
        grp_a, tbl_a = _make_hex_grid(f"Packet #{row_a + 1}  ({len(ba)} bytes)")
        grp_b, tbl_b = _make_hex_grid(f"Packet #{row_b + 1}  ({len(bb)} bytes)")
        splitter.addWidget(grp_a)
        splitter.addWidget(grp_b)
        splitter.setSizes([480, 480])
        hl.addWidget(splitter)

        # sync scrollbars
        def _sync_scroll_a(val):
            tbl_b.verticalScrollBar().setValue(val)
        def _sync_scroll_b(val):
            tbl_a.verticalScrollBar().setValue(val)
        tbl_a.verticalScrollBar().valueChanged.connect(_sync_scroll_a)
        tbl_b.verticalScrollBar().valueChanged.connect(_sync_scroll_b)

        def _fill_hex_table(tbl, data, diff_set, auto_set, other_len):
            max_len = max(len(data), other_len)
            n_rows = (max_len + 15) // 16
            tbl.setRowCount(n_rows)
            tbl.setRowHeight
            for row_i in range(n_rows):
                tbl.setRowHeight(row_i, 18)
                offset = row_i * 16
                # offset cell
                off_item = QTableWidgetItem(f"{offset:04X}")
                off_item.setForeground(QColor(0x88, 0x88, 0x88))
                tbl.setItem(row_i, 0, off_item)
                # gap cell
                tbl.setItem(row_i, 17, QTableWidgetItem(""))

                for col_i in range(16):
                    byte_pos = offset + col_i
                    hex_col   = HEX_COLS[col_i]
                    ascii_col = ASCII_COLS[col_i]

                    if byte_pos < len(data):
                        b = data[byte_pos]
                        hex_text   = f"{b:02X}"
                        ascii_text = chr(b) if 0x20 <= b < 0x7f else "."
                    elif byte_pos < max_len:
                        hex_text   = "--"
                        ascii_text = " "
                    else:
                        hex_text   = ""
                        ascii_text = ""

                    for col, text in [(hex_col, hex_text), (ascii_col, ascii_text)]:
                        it = QTableWidgetItem(text)
                        it.setTextAlignment(Qt.AlignCenter)
                        if byte_pos in diff_set:
                            it.setBackground(C_DIFF)
                            it.setForeground(QColor(0x11, 0x11, 0x11))
                        elif byte_pos in auto_set:
                            it.setBackground(C_AUTO)
                            it.setForeground(QColor(0xee, 0xee, 0xee))
                        elif byte_pos >= len(data) and byte_pos < max_len:
                            it.setBackground(C_ADD)
                        tbl.setItem(row_i, col, it)

        _fill_hex_table(tbl_a, ba, diff_pos, auto_pos, len(bb))
        _fill_hex_table(tbl_b, bb, diff_pos, auto_pos, len(ba))

        # hex legend
        hex_legend = QHBoxLayout()
        for color, text in [
            (C_DIFF, "Meaningful diff"),
            (C_AUTO, "Auto-computed field"),
            (C_ADD,  "Extra bytes (length mismatch)"),
        ]:
            sw = QLabel("   ")
            sw.setStyleSheet(f"background:rgba({color.red()},{color.green()},{color.blue()},200);border-radius:3px;")
            lb = QLabel(text)
            lb.setStyleSheet("color:#cccccc;font-size:11px;")
            hex_legend.addWidget(sw)
            hex_legend.addWidget(lb)
            hex_legend.addSpacing(16)
        hex_legend.addStretch()
        hl.addLayout(hex_legend)

        tabs.addTab(tab_hex, "Hex Diff")

        # ── Close button ───────────────────────────────────────────────
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        btn_row.addWidget(close_btn)
        dlg_layout.addLayout(btn_row)

        dlg.show()

    # ------------------------------------------------------------------
    # Proxy tab — HTTP / DNS / Conversations
    # ------------------------------------------------------------------

    # ── Scapy HTTP layer (loaded once) ────────────────────────────────
    try:
        from scapy.layers.http import HTTP as _HTTP, HTTPRequest as _HTTPRequest, HTTPResponse as _HTTPResponse
        _SCAPY_HTTP = True
    except ImportError:
        _SCAPY_HTTP = False

    def _proxy_ingest(self, pkt, t):
        """Called for every new captured packet; routes to the right parser."""
        from scapy.layers.dns import DNS, DNSQR, DNSRR
        from scapy.layers.inet import TCP, UDP, IP
        from scapy.packet import Raw

        # ── 802.11 WiFi ───────────────────────────────────────────────
        try:
            from scapy.layers.dot11 import Dot11
            if pkt.haslayer(Dot11):
                self._proxy_parse_dot11(pkt, t)
                return
        except ImportError:
            pass

        # ── Bluetooth ─────────────────────────────────────────────────
        try:
            from scapy.layers.bluetooth import HCI_Hdr
            _btle_cls = None
            try:
                from scapy.layers.bluetooth4LE import BTLE
                _btle_cls = BTLE
            except ImportError:
                pass
            if pkt.haslayer(HCI_Hdr) or (_btle_cls and pkt.haslayer(_btle_cls)):
                self._proxy_parse_bluetooth(pkt, t)
                return
        except ImportError:
            pass

        # ── HTTP ──────────────────────────────────────────────────────
        if self._SCAPY_HTTP and pkt.haslayer(self._HTTPRequest):
            self._proxy_parse_http_request(pkt, t)
            return
        if self._SCAPY_HTTP and pkt.haslayer(self._HTTPResponse):
            self._proxy_parse_http_response(pkt, t)
            return

        # Fallback: detect HTTP by port + Raw payload starts with method/HTTP
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            if any(payload.startswith(m) for m in
                   (b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ',
                    b'OPTIONS ', b'PATCH ', b'CONNECT ')):
                self._proxy_parse_http_manual(pkt, t, is_request=True)
                return
            if payload.startswith(b'HTTP/'):
                self._proxy_parse_http_manual(pkt, t, is_request=False)
                return

        # ── DNS ───────────────────────────────────────────────────────
        if pkt.haslayer(DNS):
            self._proxy_parse_dns(pkt, t)
            return

        # ── SMB (TCP port 445) ────────────────────────────────────────
        if pkt.haslayer(TCP):
            if pkt[TCP].dport == 445 or pkt[TCP].sport == 445:
                self._insp_parse_smb(pkt, t)
                if pkt.haslayer(Raw):
                    self._proxy_parse_conv(pkt, t)
                return

        # ── TLS Handshake (TCP port 443 / common TLS ports) ───────────
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            tcp_p = pkt[TCP]
            tls_ports = {443, 8443, 993, 995, 465, 636, 8883}
            if tcp_p.dport in tls_ports or tcp_p.sport in tls_ports:
                raw = bytes(pkt[Raw].load)
                if raw and raw[0] == 0x16:
                    self._insp_parse_tls_handshake(pkt, t)

        # ── FTP credentials (TCP port 21) ─────────────────────────────
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            if pkt[TCP].dport == 21:
                try:
                    line = bytes(pkt[Raw].load).decode(errors='replace').strip()
                    src2 = pkt[IP].src if pkt.haslayer(IP) else '?'
                    dst2 = pkt[IP].dst if pkt.haslayer(IP) else '?'
                    if line.upper().startswith('USER '):
                        self._ftp_pending_user = (src2, dst2, line[5:].strip(), t)
                    elif line.upper().startswith('PASS ') and hasattr(self, '_ftp_pending_user'):
                        user_src, user_dst, username, user_t = self._ftp_pending_user
                        if user_src == src2 and user_dst == dst2:
                            self._insp_add_credential(
                                "FTP", src2, dst2, username, line[5:].strip(), t,
                                f"USER {username}\nPASS {line[5:].strip()}")
                        del self._ftp_pending_user
                except Exception:
                    pass

        # ── Telnet (TCP port 23) ──────────────────────────────────────
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            if pkt[TCP].dport == 23 or pkt[TCP].sport == 23:
                self._proxy_parse_telnet(pkt, t)
                return

        # ── MySQL (3306) / PostgreSQL (5432) / MSSQL (1433) ─────────
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            tcp_p = pkt[TCP]
            if tcp_p.dport in (3306, 5432, 1433) or tcp_p.sport in (3306, 5432, 1433):
                self._insp_parse_sql(pkt, t)
                self._proxy_parse_conv(pkt, t)
                return

        # ── Conversations (TCP + UDP with payload) ────────────────────
        if (pkt.haslayer(TCP) or pkt.haslayer(UDP)) and pkt.haslayer(Raw):
            self._proxy_parse_conv(pkt, t)

    # ── HTTP helpers ──────────────────────────────────────────────────

    def _proxy_stream_key(self, pkt):
        from scapy.layers.inet import TCP, UDP, IP
        from scapy.layers.inet6 import IPv6
        src = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else "?")
        dst = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else "?")
        if pkt.haslayer(TCP):
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif pkt.haslayer(UDP):
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        else:
            sport, dport = 0, 0
        # canonical: lower port side is "client"
        if (src, sport) <= (dst, dport):
            return (src, sport, dst, dport)
        return (dst, dport, src, sport)

    def _proxy_parse_http_request(self, pkt, t):
        from scapy.layers.inet import IP
        hr = pkt[self._HTTPRequest]
        method = (hr.Method or b'').decode(errors='replace')
        host   = (hr.Host   or b'').decode(errors='replace')
        path   = (hr.Path   or b'/').decode(errors='replace')
        # Find or create stream entry
        key = self._proxy_stream_key(pkt)
        entry = {
            'time': t, 'method': method, 'host': host, 'path': path,
            'status': '—', 'length': '—',
            'req_raw': bytes(hr), 'resp_raw': b'',
            'req_headers': self._http_parse_headers(bytes(hr)),
            'resp_headers': {},
            'req_body': bytes(hr.payload) if hr.payload else b'',
            'resp_body': b'',
            'stream_key': key,
        }
        self._proxy_http_entries.append(entry)
        self._proxy_http_add_row(entry, len(self._proxy_http_entries) - 1)
        # Extract HTTP Basic / Digest credentials
        auth_hdr = entry['req_headers'].get('authorization', '')
        if not auth_hdr:
            auth_hdr = entry['req_headers'].get('Authorization', '')
        if auth_hdr:
            self._insp_extract_http_auth(auth_hdr, host, entry.get('stream_key', ('?','?','?','?')), t)

    def _insp_extract_http_auth(self, auth_hdr, host, stream_key, t):
        import base64
        src = stream_key[0] if len(stream_key) >= 1 else '?'
        dst = stream_key[2] if len(stream_key) >= 3 else '?'
        if auth_hdr.lower().startswith('basic '):
            try:
                decoded = base64.b64decode(auth_hdr[6:]).decode(errors='replace')
                if ':' in decoded:
                    username, password = decoded.split(':', 1)
                    self._insp_add_credential(
                        "HTTP Basic", src, f"{host}({dst})",
                        username, password, t,
                        f"Authorization header: {auth_hdr[:80]}")
            except Exception:
                pass
        elif auth_hdr.lower().startswith('digest '):
            # Extract username= from Digest header
            import re
            m = re.search(r'username="([^"]+)"', auth_hdr, re.IGNORECASE)
            username = m.group(1) if m else '?'
            self._insp_add_credential(
                "HTTP Digest", src, f"{host}({dst})",
                username, auth_hdr[:120], t,
                f"Authorization header: {auth_hdr[:200]}")

    def _proxy_parse_http_response(self, pkt, t):
        hr = pkt[self._HTTPResponse]
        status = str(getattr(hr, 'Status_Code', b'?') or b'?')
        if isinstance(status, bytes):
            status = status.decode(errors='replace')
        reason = (getattr(hr, 'Reason_Phrase', b'') or b'').decode(errors='replace')
        body   = bytes(hr.payload) if hr.payload else b''
        key    = self._proxy_stream_key(pkt)
        # Match to most recent unmatched request on same stream
        for entry in reversed(self._proxy_http_entries):
            if entry.get('stream_key') == key and entry['status'] == '—':
                entry['status']       = f"{status} {reason}".strip()
                entry['length']       = str(len(body))
                entry['resp_raw']     = bytes(hr)
                entry['resp_headers'] = self._http_parse_headers(bytes(hr))
                entry['resp_body']    = body
                # refresh row
                idx = self._proxy_http_entries.index(entry)
                self._proxy_http_refresh_row(entry, idx)
                return
        # orphan response — create standalone entry
        entry = {
            'time': t, 'method': '←', 'host': '?', 'path': '',
            'status': f"{status} {reason}".strip(),
            'length': str(len(body)),
            'req_raw': b'', 'resp_raw': bytes(hr),
            'req_headers': {}, 'resp_headers': self._http_parse_headers(bytes(hr)),
            'req_body': b'', 'resp_body': body,
            'stream_key': key,
        }
        self._proxy_http_entries.append(entry)
        self._proxy_http_add_row(entry, len(self._proxy_http_entries) - 1)

    def _proxy_parse_http_manual(self, pkt, t, is_request):
        """Fallback HTTP parser when scapy-http layer is absent or not triggered."""
        from scapy.layers.inet import TCP, IP
        from scapy.packet import Raw
        raw = bytes(pkt[Raw].load)
        key = self._proxy_stream_key(pkt)
        try:
            header_part = raw.split(b'\r\n\r\n', 1)
            headers_raw = header_part[0]
            body        = header_part[1] if len(header_part) > 1 else b''
            lines       = headers_raw.split(b'\r\n')
            first_line  = lines[0].decode(errors='replace')
        except Exception:
            return

        if is_request:
            parts  = first_line.split(' ', 2)
            method = parts[0] if parts else 'GET'
            path   = parts[1] if len(parts) > 1 else '/'
            host_hdr = b''
            for ln in lines[1:]:
                if ln.lower().startswith(b'host:'):
                    host_hdr = ln[5:].strip()
                    break
            host = host_hdr.decode(errors='replace')
            entry = {
                'time': t, 'method': method, 'host': host, 'path': path,
                'status': '—', 'length': '—',
                'req_raw': raw, 'resp_raw': b'',
                'req_headers': self._http_parse_headers(raw),
                'resp_headers': {},
                'req_body': body, 'resp_body': b'',
                'stream_key': key,
            }
            self._proxy_http_entries.append(entry)
            self._proxy_http_add_row(entry, len(self._proxy_http_entries) - 1)
            auth_hdr = entry['req_headers'].get('authorization', entry['req_headers'].get('Authorization', ''))
            if auth_hdr:
                self._insp_extract_http_auth(auth_hdr, host, key, t)
        else:
            parts  = first_line.split(' ', 2)
            status = f"{parts[1]} {parts[2]}".strip() if len(parts) >= 3 else first_line
            for entry in reversed(self._proxy_http_entries):
                if entry.get('stream_key') == key and entry['status'] == '—':
                    entry['status']       = status
                    entry['length']       = str(len(body))
                    entry['resp_raw']     = raw
                    entry['resp_headers'] = self._http_parse_headers(raw)
                    entry['resp_body']    = body
                    idx = self._proxy_http_entries.index(entry)
                    self._proxy_http_refresh_row(entry, idx)
                    return

    @staticmethod
    def _http_parse_headers(raw_bytes):
        """Return dict of header_name → value from raw HTTP bytes."""
        headers = {}
        try:
            header_section = raw_bytes.split(b'\r\n\r\n', 1)[0]
            lines = header_section.split(b'\r\n')
            for line in lines[1:]:  # skip request/status line
                if b':' in line:
                    k, _, v = line.partition(b':')
                    headers[k.strip().decode(errors='replace')] = v.strip().decode(errors='replace')
        except Exception:
            pass
        return headers

    def _proxy_http_add_row(self, entry, idx):
        flt = self.proxy_filter_edit.text().strip().lower()
        visible = self._proxy_http_matches(entry, flt)
        r = self.http_table.rowCount()
        self.http_table.insertRow(r)
        self._proxy_http_set_row(r, entry, idx)
        self.http_table.setRowHidden(r, not visible)

    def _proxy_http_refresh_row(self, entry, idx):
        # Find the row that corresponds to idx (row tag stored in col 0 UserRole)
        for r in range(self.http_table.rowCount()):
            it = self.http_table.item(r, 0)
            if it and it.data(Qt.UserRole) == idx:
                self._proxy_http_set_row(r, entry, idx)
                return

    def _proxy_http_set_row(self, r, entry, idx):
        status = entry['status']
        # color coding
        if status.startswith('2'):
            row_color = QColor(0x26, 0x46, 0x26)
        elif status.startswith('3'):
            row_color = QColor(0x26, 0x36, 0x46)
        elif status.startswith('4'):
            row_color = QColor(0x46, 0x26, 0x26)
        elif status.startswith('5'):
            row_color = QColor(0x46, 0x30, 0x10)
        elif status == '—':
            row_color = QColor(0x2a, 0x2a, 0x2a)
        else:
            row_color = QColor(0x28, 0x28, 0x28)

        vals = [str(idx + 1), f"{entry['time']:.3f}", entry['method'],
                entry['host'], entry['path'], status, entry['length']]
        for c, v in enumerate(vals):
            it = QtWidgets.QTableWidgetItem(v)
            it.setBackground(row_color)
            it.setForeground(QColor(0xdd, 0xdd, 0xdd))
            if c == 0:
                it.setData(Qt.UserRole, idx)
            self.http_table.setItem(r, c, it)

    def _proxy_http_matches(self, entry, flt):
        if not flt:
            return True
        haystack = f"{entry['method']} {entry['host']} {entry['path']} {entry['status']}".lower()
        return flt in haystack

    @staticmethod
    def _decompress_body(body: bytes, headers: dict) -> bytes:
        """Decompress body according to Content-Encoding header."""
        if not body:
            return body
        enc = headers.get('Content-Encoding', '').strip().lower()
        try:
            if enc == 'gzip':
                import gzip
                return gzip.decompress(body)
            if enc == 'deflate':
                import zlib
                try:
                    return zlib.decompress(body)
                except zlib.error:
                    return zlib.decompress(body, -zlib.MAX_WBITS)
            if enc in ('br', 'brotli'):
                import brotli
                return brotli.decompress(body)
            if enc == 'zstd':
                import zstandard
                return zstandard.ZstdDecompressor().decompress(body)
        except Exception:
            pass
        return body

    def _proxy_http_row_selected(self, row):
        if row < 0:
            return
        it = self.http_table.item(row, 0)
        if not it:
            return
        idx = it.data(Qt.UserRole)
        if idx is None or idx >= len(self._proxy_http_entries):
            return
        entry = self._proxy_http_entries[idx]

        # Request panels
        self._fill_header_table(self.http_req_headers, entry['req_headers'])
        body = self._decompress_body(entry['req_body'], entry['req_headers'])
        self.http_req_body.setPlainText(
            body.decode(errors='replace') if body else '')
        if entry['req_raw']:
            header_section = entry['req_raw'].split(b'\r\n\r\n', 1)[0]
            req_raw = header_section.decode(errors='replace') + '\r\n\r\n' + (
                body.decode(errors='replace') if body else '')
        else:
            req_raw = ''
        self.http_req_raw.setPlainText(req_raw)

        # Response panels
        self._fill_header_table(self.http_resp_headers, entry['resp_headers'])
        rbody = self._decompress_body(entry['resp_body'], entry['resp_headers'])
        self.http_resp_body.setPlainText(
            rbody.decode(errors='replace') if rbody else '')
        # Raw: keep headers verbatim, replace body with decompressed text
        if entry['resp_raw']:
            header_section = entry['resp_raw'].split(b'\r\n\r\n', 1)[0]
            resp_raw = header_section.decode(errors='replace') + '\r\n\r\n' + (
                rbody.decode(errors='replace') if rbody else '')
        else:
            resp_raw = ''
        self.http_resp_raw.setPlainText(resp_raw)

    @staticmethod
    def _fill_header_table(tbl, headers):
        tbl.setRowCount(0)
        for k, v in headers.items():
            r = tbl.rowCount()
            tbl.insertRow(r)
            tbl.setItem(r, 0, QtWidgets.QTableWidgetItem(k))
            tbl.setItem(r, 1, QtWidgets.QTableWidgetItem(v))

    # ── DNS helpers ───────────────────────────────────────────────────

    def _proxy_parse_dns(self, pkt, t):
        from scapy.layers.dns import DNS, DNSQR, DNSRR
        from scapy.layers.inet import IP, UDP
        dns = pkt[DNS]
        server = ''
        if pkt.haslayer(IP):
            server = pkt[IP].src if dns.qr else pkt[IP].dst
        elif pkt.haslayer(IPv6):
            server = pkt[IPv6].src if dns.qr else pkt[IPv6].dst

        if dns.qr == 0:  # query
            for i in range(dns.qdcount):
                try:
                    qr = dns.qd
                    idx = 0
                    while qr and idx < i:
                        qr = qr.payload
                        idx += 1
                    if not qr or not hasattr(qr, 'qname'):
                        break
                    qname = qr.qname.decode(errors='replace').rstrip('.')
                    qtype = qr.get_field('qtype').i2repr(qr, qr.qtype) if hasattr(qr, 'qtype') else '?'
                    entry = {
                        'time': t, 'qtype': qtype, 'name': qname,
                        'response': '—', 'ttl': '—', 'server': server,
                        'txid': dns.id, 'detail': pkt.show(dump=True),
                    }
                    self._proxy_dns_entries.append(entry)
                    self._proxy_dns_add_row(entry, len(self._proxy_dns_entries) - 1)
                except Exception:
                    pass
        else:  # response — match by txid
            answers = []
            try:
                rr = dns.an
                while rr and rr.name != b'\x00':
                    rdata = ''
                    if hasattr(rr, 'rdata'):
                        rdata = str(rr.rdata)
                    ttl = str(rr.ttl) if hasattr(rr, 'ttl') else '—'
                    answers.append((rdata, ttl))
                    rr = rr.payload
            except Exception:
                pass

            resp_str = ', '.join(a[0] for a in answers) if answers else '(no answer)'
            ttl_str  = answers[0][1] if answers else '—'

            for entry in reversed(self._proxy_dns_entries):
                if entry['txid'] == dns.id and entry['response'] == '—':
                    entry['response'] = resp_str
                    entry['ttl']      = ttl_str
                    entry['detail']   = pkt.show(dump=True)
                    idx = self._proxy_dns_entries.index(entry)
                    self._proxy_dns_refresh_row(entry, idx)
                    return

    def _proxy_dns_add_row(self, entry, idx):
        flt = self.proxy_filter_edit.text().strip().lower()
        visible = self._proxy_dns_matches(entry, flt)
        r = self.dns_table.rowCount()
        self.dns_table.insertRow(r)
        self._proxy_dns_set_row(r, entry, idx)
        self.dns_table.setRowHidden(r, not visible)

    def _proxy_dns_refresh_row(self, entry, idx):
        for r in range(self.dns_table.rowCount()):
            it = self.dns_table.item(r, 0)
            if it and it.data(Qt.UserRole) == idx:
                self._proxy_dns_set_row(r, entry, idx)
                return

    def _proxy_dns_set_row(self, r, entry, idx):
        vals = [str(idx + 1), f"{entry['time']:.3f}", entry['qtype'],
                entry['name'], entry['response'], entry['ttl'], entry['server']]
        resolved = entry['response'] != '—'
        bg = QColor(0x26, 0x40, 0x26) if resolved else QColor(0x28, 0x28, 0x28)
        for c, v in enumerate(vals):
            it = QtWidgets.QTableWidgetItem(v)
            it.setBackground(bg)
            it.setForeground(QColor(0xdd, 0xdd, 0xdd))
            if c == 0:
                it.setData(Qt.UserRole, idx)
            self.dns_table.setItem(r, c, it)

    def _proxy_dns_matches(self, entry, flt):
        if not flt:
            return True
        return flt in f"{entry['name']} {entry['qtype']} {entry['response']}".lower()

    def _proxy_dns_row_selected(self, row):
        if row < 0:
            return
        it = self.dns_table.item(row, 0)
        if not it:
            return
        idx = it.data(Qt.UserRole)
        if idx is None or idx >= len(self._proxy_dns_entries):
            return
        self.dns_detail.setPlainText(self._proxy_dns_entries[idx]['detail'])

    # ── Telnet helpers ────────────────────────────────────────────────

    @staticmethod
    def _telnet_strip_iac(data: bytes) -> bytes:
        """Strip Telnet IAC command sequences, returning only user-visible text."""
        out = bytearray()
        i = 0
        while i < len(data):
            b = data[i]
            if b == 0xFF:            # IAC
                i += 1
                if i >= len(data):
                    break
                cmd = data[i]
                if cmd in (0xFB, 0xFC, 0xFD, 0xFE):  # WILL/WONT/DO/DONT — 1 option byte
                    i += 2
                elif cmd == 0xFF:    # escaped 0xFF literal
                    out.append(0xFF)
                    i += 1
                else:
                    i += 1           # SB/SE/NOP/etc — skip
            else:
                out.append(b)
                i += 1
        return bytes(out)

    @staticmethod
    def _telnet_to_text(raw: bytes) -> str:
        """Strip IAC and render as printable text."""
        clean = SniffTool._telnet_strip_iac(raw)
        return ''.join(
            chr(b) if (0x20 <= b < 0x7f or b in (0x09, 0x0a, 0x0d)) else f'[{b:02x}]'
            for b in clean
        )

    def _proxy_parse_telnet(self, pkt, t):
        from scapy.layers.inet import TCP, IP
        from scapy.layers.inet6 import IPv6
        from scapy.packet import Raw

        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            return
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return

        src = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src
        dst = pkt[IP].dst if pkt.haslayer(IP) else pkt[IPv6].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        payload = bytes(pkt[Raw].load)
        if not payload:
            return

        # Canonical key: client always has the high ephemeral port
        if dport == 23:
            client, server = f"{src}:{sport}", f"{dst}:{dport}"
            direction = 'c2s'
        else:
            client, server = f"{dst}:{dport}", f"{src}:{sport}"
            direction = 's2c'

        key = (client, server)
        if key not in self._telnet_map:
            session = {
                'time': t, 'client': client, 'server': server,
                'bytes': 0, 'pkts': 0,
                'c2s_raw': b'', 's2c_raw': b'',
            }
            self._telnet_map[key] = session
            self._telnet_sessions.append(session)
            self._telnet_add_row(session, len(self._telnet_sessions) - 1)
            # Auto-switch Inspector tab to Telnet/FTP view
            if self.insp_tabs.currentIndex() == 0 and not self._proxy_http_entries:
                self.insp_tabs.setCurrentIndex(5)
        else:
            session = self._telnet_map[key]

        session['bytes'] += len(payload)
        session['pkts']  += 1
        if direction == 'c2s':
            session['c2s_raw'] += payload
        else:
            session['s2c_raw'] += payload

        idx = self._telnet_sessions.index(session)
        self._telnet_refresh_row(session, idx)

    def _telnet_add_row(self, session, idx):
        r = self.telnet_table.rowCount()
        self.telnet_table.insertRow(r)
        self._telnet_set_row(r, session, idx)

    def _telnet_refresh_row(self, session, idx):
        for r in range(self.telnet_table.rowCount()):
            it = self.telnet_table.item(r, 0)
            if it and it.data(Qt.UserRole) == idx:
                self._telnet_set_row(r, session, idx)
                # If this row is currently selected, live-update the detail panes
                if self.telnet_table.currentRow() == r:
                    self._proxy_telnet_row_selected(r)
                return

    def _telnet_set_row(self, r, session, idx):
        vals = [str(idx + 1), f"{session['time']:.3f}",
                session['client'], session['server'],
                str(session['bytes']), str(session['pkts'])]
        bg = QColor(0x1e, 0x30, 0x3e)
        for c, v in enumerate(vals):
            it = QtWidgets.QTableWidgetItem(v)
            it.setBackground(bg)
            it.setForeground(QColor(0xdd, 0xdd, 0xdd))
            if c == 0:
                it.setData(Qt.UserRole, idx)
            self.telnet_table.setItem(r, c, it)

    def _proxy_telnet_row_selected(self, row):
        if row < 0:
            return
        it = self.telnet_table.item(row, 0)
        if not it:
            return
        idx = it.data(Qt.UserRole)
        if idx is None or idx >= len(self._telnet_sessions):
            return
        session = self._telnet_sessions[idx]

        c2s_text = self._telnet_to_text(session['c2s_raw'])
        s2c_text = self._telnet_to_text(session['s2c_raw'])

        # Combined view: interleave lines with direction markers
        combined_lines = []
        if c2s_text.strip():
            for line in c2s_text.splitlines():
                if line.strip():
                    combined_lines.append(f'> {line}')
        if s2c_text.strip():
            for line in s2c_text.splitlines():
                combined_lines.append(f'  {line}')
        self.telnet_combined.setPlainText('\n'.join(combined_lines))
        self.telnet_client_view.setPlainText(c2s_text)
        self.telnet_server_view.setPlainText(s2c_text)

        # Raw hex dump of combined stream
        raw_all = session['c2s_raw'] + session['s2c_raw']
        hex_lines = []
        for i in range(0, len(raw_all), 16):
            chunk = raw_all[i:i+16]
            hex_part  = ' '.join(f'{b:02x}' for b in chunk)
            text_part = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
            hex_lines.append(f'{i:04x}  {hex_part:<47}  {text_part}')
        self.telnet_raw_view.setPlainText('\n'.join(hex_lines))

    # ── 802.11 WiFi helpers ───────────────────────────────────────────

    def _proxy_parse_dot11(self, pkt, t):
        from protocol_parser import dot11_ssid, dot11_signal, get_protocol
        try:
            from scapy.layers.dot11 import Dot11, RadioTap
        except ImportError:
            return
        if not pkt.haslayer(Dot11):
            return

        d = pkt[Dot11]
        proto   = get_protocol(pkt)
        src     = d.addr2 or "—"
        dst     = d.addr1 or "—"
        bssid   = d.addr3 or "—"
        ssid    = dot11_ssid(pkt)
        sig     = dot11_signal(pkt)
        sig_str = f"{sig} dBm" if sig is not None else "—"

        idx = len(self._wifi_frames)
        self._wifi_frames.append(pkt)

        r = self.wifi_table.rowCount()
        self.wifi_table.insertRow(r)
        bg = QColor(0x1e, 0x2a, 0x1e)
        for c, v in enumerate([str(idx + 1), f"{t:.3f}", proto, src, dst, bssid, ssid, sig_str]):
            it = QtWidgets.QTableWidgetItem(v)
            it.setBackground(bg)
            it.setForeground(QColor(0xdd, 0xdd, 0xdd))
            if c == 0:
                it.setData(Qt.UserRole, idx)
            self.wifi_table.setItem(r, c, it)
        self.wifi_table.scrollToBottom()

        # (WiFi/BT are shown in Capture tab inner tabs, not Inspector)

    def _proxy_wifi_row_selected(self, row):
        if row < 0 or row >= self.wifi_table.rowCount():
            return
        it = self.wifi_table.item(row, 0)
        if not it:
            return
        idx = it.data(Qt.UserRole)
        if idx is None or idx >= len(self._wifi_frames):
            return
        pkt = self._wifi_frames[idx]
        try:
            lines = [pkt.show(dump=True)]
        except Exception:
            lines = [pkt.summary()]
        raw = bytes(pkt)
        hex_lines = []
        for i in range(0, len(raw), 16):
            chunk = raw[i:i+16]
            hex_part  = ' '.join(f'{b:02x}' for b in chunk)
            text_part = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
            hex_lines.append(f'{i:04x}  {hex_part:<47}  {text_part}')
        self.wifi_detail.setPlainText('\n'.join(lines) + '\n\n' + '\n'.join(hex_lines))

    # ── Bluetooth helpers ─────────────────────────────────────────────

    def _proxy_parse_bluetooth(self, pkt, t):
        from protocol_parser import get_protocol, bt_info
        proto   = get_protocol(pkt)
        src     = "—"
        dst     = "—"
        try:
            from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV
            if pkt.haslayer(BTLE_ADV):
                adv = pkt[BTLE_ADV]
                src = getattr(adv, 'AdvA', '—') or '—'
        except ImportError:
            pass
        info = bt_info(pkt)

        idx = len(self._bt_events)
        self._bt_events.append(pkt)

        r = self.bt_table.rowCount()
        self.bt_table.insertRow(r)
        bg = QColor(0x1a, 0x1a, 0x2e)
        for c, v in enumerate([str(idx + 1), f"{t:.3f}", proto, src, dst, info]):
            it = QtWidgets.QTableWidgetItem(v)
            it.setBackground(bg)
            it.setForeground(QColor(0xdd, 0xdd, 0xdd))
            if c == 0:
                it.setData(Qt.UserRole, idx)
            self.bt_table.setItem(r, c, it)
        self.bt_table.scrollToBottom()

        pass  # BT shown in Capture tab inner tabs

    def _proxy_bt_row_selected(self, row):
        if row < 0 or row >= self.bt_table.rowCount():
            return
        it = self.bt_table.item(row, 0)
        if not it:
            return
        idx = it.data(Qt.UserRole)
        if idx is None or idx >= len(self._bt_events):
            return
        pkt = self._bt_events[idx]
        try:
            detail = pkt.show(dump=True)
        except Exception:
            detail = pkt.summary()
        raw = bytes(pkt)
        hex_lines = []
        for i in range(0, len(raw), 16):
            chunk = raw[i:i+16]
            hex_part  = ' '.join(f'{b:02x}' for b in chunk)
            text_part = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
            hex_lines.append(f'{i:04x}  {hex_part:<47}  {text_part}')
        self.bt_detail.setPlainText(detail + '\n\n' + '\n'.join(hex_lines))

    # ── Interface discovery ───────────────────────────────────────────

    @staticmethod
    def _discover_extra_interfaces():
        """Return special interfaces not reported by netifaces (BT HCI, usbmon)."""
        import os
        ifaces = []
        # Bluetooth HCI (Linux)
        bt_path = '/sys/class/bluetooth'
        if os.path.isdir(bt_path):
            for name in sorted(os.listdir(bt_path)):
                ifaces.append(name)
        # usbmon (USB packet capture)
        for i in range(8):
            if os.path.exists(f'/dev/usbmon{i}'):
                ifaces.append(f'usbmon{i}')
        return ifaces

    def _on_iface_changed(self, iface):
        """Auto-switch to Sniff mode for non-IP interfaces (BT/WiFi monitor/USB)."""
        _non_ip = iface.startswith('hci') or iface.startswith('usbmon')
        if _non_ip and hasattr(self, 'mode_combo'):
            # Force sniff mode (last index) since NFQUEUE doesn't support these
            sniff_idx = self.mode_combo.count() - 1
            if self.mode_combo.currentIndex() != sniff_idx:
                self.mode_combo.setCurrentIndex(sniff_idx)

    # ── Conversations helpers ─────────────────────────────────────────

    def _proxy_parse_conv(self, pkt, t):
        from scapy.layers.inet import TCP, UDP, IP
        from scapy.layers.inet6 import IPv6
        from scapy.packet import Raw

        key = self._proxy_stream_key(pkt)
        proto_name = 'TCP' if pkt.haslayer(TCP) else 'UDP'
        payload = bytes(pkt[Raw].load)

        src_ip = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else '?')
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else '?')
        sport  = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport
        dport  = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport

        # canonical client = initiator (lower endpoint key)
        if (src_ip, sport) <= (dst_ip, dport):
            client = f"{src_ip}:{sport}"
            server = f"{dst_ip}:{dport}"
            direction = 'a2b'
        else:
            client = f"{dst_ip}:{dport}"
            server = f"{src_ip}:{sport}"
            direction = 'b2a'

        if key not in self._proxy_conv_map:
            conv = {
                'proto': proto_name, 'client': client, 'server': server,
                'pkts': 0, 'bytes': 0, 'start': t,
                'stream_a2b': b'', 'stream_b2a': b'',
                'key': key,
            }
            self._proxy_conv_map[key] = conv
            self._proxy_conv_list.append(conv)
            idx = len(self._proxy_conv_list) - 1
            self._proxy_conv_add_row(conv, idx)
        else:
            conv = self._proxy_conv_map[key]
            idx  = self._proxy_conv_list.index(conv)

        conv['pkts']  += 1
        conv['bytes'] += len(payload)
        conv[f'stream_{direction}'] += payload
        self._proxy_conv_refresh_row(conv, idx)

    def _proxy_conv_add_row(self, conv, idx):
        flt = self.proxy_filter_edit.text().strip().lower()
        visible = self._proxy_conv_matches(conv, flt)
        r = self.conv_table.rowCount()
        self.conv_table.insertRow(r)
        self._proxy_conv_set_row(r, conv, idx)
        self.conv_table.setRowHidden(r, not visible)

    def _proxy_conv_refresh_row(self, conv, idx):
        for r in range(self.conv_table.rowCount()):
            it = self.conv_table.item(r, 0)
            if it and it.data(Qt.UserRole) == idx:
                self._proxy_conv_set_row(r, conv, idx)
                return

    def _proxy_conv_set_row(self, r, conv, idx):
        vals = [str(idx + 1), conv['proto'], conv['client'], conv['server'],
                str(conv['pkts']), str(conv['bytes']), f"{conv['start']:.3f}"]
        bg = QColor(0x26, 0x2e, 0x46) if conv['proto'] == 'TCP' else QColor(0x30, 0x2a, 0x1e)
        for c, v in enumerate(vals):
            it = QtWidgets.QTableWidgetItem(v)
            it.setBackground(bg)
            it.setForeground(QColor(0xdd, 0xdd, 0xdd))
            if c == 0:
                it.setData(Qt.UserRole, idx)
            self.conv_table.setItem(r, c, it)

    def _proxy_conv_matches(self, conv, flt):
        if not flt:
            return True
        return flt in f"{conv['proto']} {conv['client']} {conv['server']}".lower()

    def _proxy_conv_row_selected(self, row):
        if row < 0:
            return
        it = self.conv_table.item(row, 0)
        if not it:
            return
        idx = it.data(Qt.UserRole)
        if idx is None or idx >= len(self._proxy_conv_list):
            return
        conv = self._proxy_conv_list[idx]
        a2b = conv['stream_a2b']
        b2a = conv['stream_b2a']
        combined = a2b + b2a  # simplistic interleave

        # Text view — printable chars, replace non-printable with dot
        def _to_text(data):
            return ''.join(chr(b) if 0x20 <= b < 0x7f or b in (0x09, 0x0a, 0x0d) else '.' for b in data)

        # Hex dump
        def _to_hexdump(data):
            lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_part  = ' '.join(f'{b:02x}' for b in chunk)
                text_part = _to_text(chunk)
                lines.append(f'{i:04x}  {hex_part:<47}  {text_part}')
            return '\n'.join(lines)

        self.conv_stream_text.setPlainText(_to_text(combined))
        self.conv_stream_hex.setPlainText(_to_hexdump(combined))
        self.conv_stream_atob.setPlainText(_to_text(a2b))
        self.conv_stream_btoa.setPlainText(_to_text(b2a))

    # ── Inspector control ──────────────────────────────────────────────

    def _insp_tab_changed(self, index):
        self._proxy_apply_filter(self.proxy_filter_edit.text())

    def _proxy_clear(self):
        self._proxy_http_entries.clear()
        self._proxy_dns_entries.clear()
        self._proxy_conv_map.clear()
        self._proxy_conv_list.clear()
        self._telnet_sessions.clear()
        self._telnet_map.clear()
        self._tls_hs_entries.clear()
        self._creds_entries.clear()
        self._smb_entries.clear()
        self._sql_entries.clear()
        self.http_table.setRowCount(0)
        self.dns_table.setRowCount(0)
        self.conv_table.setRowCount(0)
        self.telnet_table.setRowCount(0)
        self.tls_hs_table.setRowCount(0)
        self.creds_table.setRowCount(0)
        self.smb_table.setRowCount(0)
        self.sql_table.setRowCount(0)
        self.http_req_raw.clear()
        self.http_resp_raw.clear()
        self.http_req_headers.setRowCount(0)
        self.http_resp_headers.setRowCount(0)
        self.http_req_body.clear()
        self.http_resp_body.clear()
        self.dns_detail.clear()
        self.conv_stream_text.clear()
        self.conv_stream_hex.clear()
        self.conv_stream_atob.clear()
        self.conv_stream_btoa.clear()
        self.telnet_combined.clear()
        self.telnet_client_view.clear()
        self.telnet_server_view.clear()
        self.telnet_raw_view.clear()
        self.tls_hs_detail.clear()
        self.creds_detail.clear()
        self.smb_detail.clear()
        self.sql_detail.clear()

    def _proxy_apply_filter(self, text):
        flt = text.strip().lower()
        idx = self.insp_tabs.currentIndex()
        if idx == 0:  # HTTP
            for r in range(self.http_table.rowCount()):
                it = self.http_table.item(r, 0)
                if it:
                    entry = self._proxy_http_entries[it.data(Qt.UserRole)]
                    self.http_table.setRowHidden(r, not self._proxy_http_matches(entry, flt))
        elif idx == 1:  # DNS
            for r in range(self.dns_table.rowCount()):
                it = self.dns_table.item(r, 0)
                if it:
                    entry = self._proxy_dns_entries[it.data(Qt.UserRole)]
                    self.dns_table.setRowHidden(r, not self._proxy_dns_matches(entry, flt))
        elif idx == 2:  # Streams
            for r in range(self.conv_table.rowCount()):
                it = self.conv_table.item(r, 0)
                if it:
                    conv = self._proxy_conv_list[it.data(Qt.UserRole)]
                    self.conv_table.setRowHidden(r, not self._proxy_conv_matches(conv, flt))
        elif idx == 3:  # TLS Handshakes
            for r in range(self.tls_hs_table.rowCount()):
                self.tls_hs_table.setRowHidden(r, bool(flt and not self._insp_tls_hs_matches(r, flt)))
        elif idx == 4:  # Credentials
            for r in range(self.creds_table.rowCount()):
                self.creds_table.setRowHidden(r, bool(flt and not self._insp_creds_matches(r, flt)))
        elif idx == 5:  # Telnet / FTP
            for r in range(self.telnet_table.rowCount()):
                it = self.telnet_table.item(r, 0)
                if it:
                    session = self._telnet_sessions[it.data(Qt.UserRole)]
                    visible = not flt or flt in f"{session['client']} {session['server']}".lower()
                    self.telnet_table.setRowHidden(r, not visible)
        elif idx == 6:  # SMB
            for r in range(self.smb_table.rowCount()):
                self.smb_table.setRowHidden(r, bool(flt and not self._insp_smb_matches(r, flt)))
        elif idx == 7:  # SQL
            for r in range(self.sql_table.rowCount()):
                it = self.sql_table.item(r, 0)
                if it:
                    entry = self._sql_entries[it.data(Qt.UserRole)]
                    self.sql_table.setRowHidden(r, bool(flt and not self._insp_sql_matches(entry, flt)))

    # ------------------------------------------------------------------
    # Inspector — TLS Handshakes sub-tab
    # ------------------------------------------------------------------

    def _insp_parse_tls_handshake(self, pkt, t):
        """Extract TLS ClientHello / ServerHello metadata from a TCP packet."""
        try:
            from scapy.layers.inet import TCP as _TCP
            if not pkt.haslayer(_TCP):
                return
            tcp = pkt[_TCP]
            data = bytes(tcp.payload)
            if len(data) < 6:
                return
            # TLS record: type(1) ver(2) length(2) | handshake type(1) ...
            if data[0] != 0x16:   # not Handshake record type
                return
            hs_type = data[5]
            if hs_type not in (0x01, 0x02):   # ClientHello or ServerHello only
                return

            src = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else "?")
            dst = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else "?")
            tls_ver_raw = (data[1] << 8) | data[2]
            _VER = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
            tls_ver = _VER.get(tls_ver_raw, f"0x{tls_ver_raw:04x}")

            sni = ""
            cipher = ""
            detail_lines = []

            if hs_type == 0x01:   # ClientHello
                detail_lines.append("Type: ClientHello")
                detail_lines.append(f"Record version: {tls_ver}")
                # ClientHello body starts at offset 9
                # layout: legacy_version(2) random(32) session_id_len(1) session_id(var)
                #         cipher_suites_len(2) cipher_suites(var) compression(var) extensions(var)
                pos = 9
                if pos + 2 > len(data): return
                ch_ver_raw = (data[pos] << 8) | data[pos+1]
                detail_lines.append(f"Hello version: {_VER.get(ch_ver_raw, f'0x{ch_ver_raw:04x}')}")
                pos += 2 + 32  # skip random
                if pos >= len(data): return
                sid_len = data[pos]; pos += 1 + sid_len
                if pos + 2 > len(data): return
                cs_len = (data[pos] << 8) | data[pos+1]; pos += 2
                # collect first few cipher suite names
                _CS = {0x002f: "TLS_RSA_AES128_CBC_SHA", 0x0035: "TLS_RSA_AES256_CBC_SHA",
                       0xc02b: "TLS_ECDHE_ECDSA_AES128_GCM_SHA256",
                       0xc02c: "TLS_ECDHE_ECDSA_AES256_GCM_SHA384",
                       0xc02f: "TLS_ECDHE_RSA_AES128_GCM_SHA256",
                       0xc030: "TLS_ECDHE_RSA_AES256_GCM_SHA384",
                       0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
                       0x1303: "TLS_CHACHA20_POLY1305_SHA256"}
                cs_vals = []
                for i in range(0, min(cs_len, len(data) - pos), 2):
                    v = (data[pos+i] << 8) | data[pos+i+1]
                    cs_vals.append(_CS.get(v, f"0x{v:04x}"))
                cipher = cs_vals[0] if cs_vals else ""
                detail_lines.append("Cipher suites offered: " + ", ".join(cs_vals[:8]))
                pos += cs_len
                if pos >= len(data): pos = len(data)
                comp_len = data[pos] if pos < len(data) else 0; pos += 1 + comp_len
                if pos + 2 > len(data): pass
                else:
                    ext_total = (data[pos] << 8) | data[pos+1]; pos += 2
                    ext_end = pos + ext_total
                    detail_lines.append("Extensions:")
                    while pos + 4 <= min(ext_end, len(data)):
                        ext_type = (data[pos] << 8) | data[pos+1]
                        ext_len  = (data[pos+2] << 8) | data[pos+3]
                        pos += 4
                        ext_data = data[pos:pos+ext_len]; pos += ext_len
                        if ext_type == 0x0000:  # SNI
                            if len(ext_data) >= 5:
                                name_len = (ext_data[3] << 8) | ext_data[4]
                                sni = ext_data[5:5+name_len].decode(errors='replace')
                            detail_lines.append(f"  SNI: {sni}")
                        elif ext_type == 0x002b:  # supported_versions
                            detail_lines.append(f"  supported_versions ({ext_len}B)")
                        elif ext_type == 0x000d:  # signature_algorithms
                            detail_lines.append(f"  signature_algorithms ({ext_len}B)")
                        else:
                            _EXT = {0x0010: "ALPN", 0x0017: "extended_master_secret",
                                    0x0023: "session_ticket", 0xff01: "renegotiation_info"}
                            detail_lines.append(f"  {_EXT.get(ext_type, f'type 0x{ext_type:04x}')} ({ext_len}B)")

            else:  # ServerHello
                detail_lines.append("Type: ServerHello")
                detail_lines.append(f"Record version: {tls_ver}")
                pos = 9
                if pos + 2 > len(data): return
                sh_ver_raw = (data[pos] << 8) | data[pos+1]
                detail_lines.append(f"Hello version: {_VER.get(sh_ver_raw, f'0x{sh_ver_raw:04x}')}")
                pos += 2 + 32  # skip random
                if pos >= len(data): return
                sid_len = data[pos]; pos += 1 + sid_len
                if pos + 2 > len(data): return
                cs_val = (data[pos] << 8) | data[pos+1]
                _CS2 = {0x002f: "TLS_RSA_AES128_CBC_SHA", 0x0035: "TLS_RSA_AES256_CBC_SHA",
                        0xc02b: "TLS_ECDHE_ECDSA_AES128_GCM_SHA256",
                        0xc02f: "TLS_ECDHE_RSA_AES128_GCM_SHA256",
                        0xc030: "TLS_ECDHE_RSA_AES256_GCM_SHA384",
                        0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
                        0x1303: "TLS_CHACHA20_POLY1305_SHA256"}
                cipher = _CS2.get(cs_val, f"0x{cs_val:04x}")
                detail_lines.append(f"Selected cipher: {cipher}")

            entry = {
                'time': t, 'client': src, 'server': dst,
                'sni': sni, 'version': tls_ver, 'cipher': cipher,
                'cert_cn': '', 'type': 'ClientHello' if hs_type == 0x01 else 'ServerHello',
                'detail': '\n'.join(detail_lines),
            }
            self._tls_hs_entries.append(entry)
            self._insp_tls_hs_add_row(entry, len(self._tls_hs_entries) - 1)
        except Exception:
            pass

    def _insp_tls_hs_add_row(self, entry, idx):
        flt = self.proxy_filter_edit.text().strip().lower()
        r = self.tls_hs_table.rowCount()
        self.tls_hs_table.insertRow(r)
        t_str = f"{entry['time']:.3f}" if isinstance(entry['time'], float) else str(entry['time'])
        vals = [str(idx+1), t_str, entry['client'], entry['server'],
                entry['sni'], entry['version'], entry['cipher'], entry['cert_cn']]
        for c, v in enumerate(vals):
            item = QTableWidgetItem(v)
            item.setData(Qt.UserRole, idx)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self.tls_hs_table.setItem(r, c, item)
        if flt and not self._insp_tls_hs_matches(r, flt):
            self.tls_hs_table.setRowHidden(r, True)

    def _insp_tls_hs_matches(self, row, flt):
        for c in range(self.tls_hs_table.columnCount()):
            it = self.tls_hs_table.item(row, c)
            if it and flt in it.text().lower():
                return True
        return False

    def _insp_tls_hs_row_selected(self, row):
        if row < 0: return
        it = self.tls_hs_table.item(row, 0)
        if not it: return
        idx = it.data(Qt.UserRole)
        if idx is None or idx >= len(self._tls_hs_entries): return
        entry = self._tls_hs_entries[idx]
        self.tls_hs_detail.setPlainText(entry.get('detail', ''))

    # ------------------------------------------------------------------
    # Inspector — Credentials sub-tab
    # ------------------------------------------------------------------

    def _insp_add_credential(self, proto, src, dst, username, secret, t, detail=''):
        """Add a credential record to the Credentials sub-tab."""
        entry = {
            'time': t, 'proto': proto, 'src': src, 'dst': dst,
            'username': username, 'secret': secret, 'detail': detail,
        }
        self._creds_entries.append(entry)
        r = self.creds_table.rowCount()
        self.creds_table.insertRow(r)
        t_str = f"{t:.3f}" if isinstance(t, float) else str(t)
        vals = [str(len(self._creds_entries)), t_str, proto, src, dst, username, secret]
        for c, v in enumerate(vals):
            item = QTableWidgetItem(v)
            item.setData(Qt.UserRole, len(self._creds_entries) - 1)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self.creds_table.setItem(r, c, item)

    def _insp_creds_matches(self, row, flt):
        for c in range(self.creds_table.columnCount()):
            it = self.creds_table.item(row, c)
            if it and flt in it.text().lower():
                return True
        return False

    def _insp_creds_row_selected(self, row):
        if row < 0: return
        it = self.creds_table.item(row, 0)
        if not it: return
        idx = it.data(Qt.UserRole)
        if idx is None or idx >= len(self._creds_entries): return
        entry = self._creds_entries[idx]
        lines = [
            f"Protocol : {entry['proto']}",
            f"Source   : {entry['src']}",
            f"Dest     : {entry['dst']}",
            f"Username : {entry['username']}",
            f"Secret   : {entry['secret']}",
        ]
        if entry.get('detail'):
            lines += ['', 'Detail:', entry['detail']]
        self.creds_detail.setPlainText('\n'.join(lines))

    def _insp_creds_copy(self):
        text = self.creds_detail.toPlainText()
        if text:
            QtWidgets.QApplication.clipboard().setText(text)

    # ------------------------------------------------------------------
    # Inspector — SMB sub-tab
    # ------------------------------------------------------------------

    _SMB2_COMMANDS = {
        0x0000: "NEGOTIATE", 0x0001: "SESSION_SETUP", 0x0002: "LOGOFF",
        0x0003: "TREE_CONNECT", 0x0004: "TREE_DISCONNECT", 0x0005: "CREATE",
        0x0006: "CLOSE", 0x0007: "FLUSH", 0x0008: "READ", 0x0009: "WRITE",
        0x000a: "LOCK", 0x000b: "IOCTL", 0x000c: "CANCEL",
        0x000d: "ECHO", 0x000e: "QUERY_DIRECTORY", 0x000f: "CHANGE_NOTIFY",
        0x0010: "QUERY_INFO", 0x0011: "SET_INFO", 0x0012: "OPLOCK_BREAK",
    }

    def _insp_parse_smb(self, pkt, t):
        """Parse SMB2 packets from TCP port 445."""
        try:
            from scapy.layers.inet import TCP as _TCP
            if not pkt.haslayer(_TCP): return
            tcp = pkt[_TCP]
            if tcp.dport != 445 and tcp.sport != 445: return
            data = bytes(tcp.payload)
            # SMB2 starts with 4-byte NetBIOS length + \xfeSMB protocol id
            if len(data) < 8: return
            offset = 4  # skip NetBIOS
            if data[offset:offset+4] != b'\xfeSMB': return

            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "?"

            # SMB2 header: signature(4) struct_size(2) credit_charge(2) status(4)
            # command(2) credits(2) flags(4) chain_offset(4) message_id(8) ...
            cmd_offset = offset + 12
            if cmd_offset + 2 > len(data): return
            cmd = (data[cmd_offset+1] << 8) | data[cmd_offset]
            cmd_name = self._SMB2_COMMANDS.get(cmd, f"CMD_0x{cmd:04x}")

            status_offset = offset + 8
            status_val = int.from_bytes(data[status_offset:status_offset+4], 'little') if status_offset+4 <= len(data) else 0
            status_str = "SUCCESS" if status_val == 0 else f"0x{status_val:08x}"

            flags_offset = offset + 16
            flags = int.from_bytes(data[flags_offset:flags_offset+4], 'little') if flags_offset+4 <= len(data) else 0
            is_response = bool(flags & 0x00000001)
            direction = "Response" if is_response else "Request"

            detail_lines = [
                f"Command  : {cmd_name} ({direction})",
                f"Status   : {status_str}",
                f"Client   : {src}",
                f"Server   : {dst}",
                f"Flags    : 0x{flags:08x}",
            ]

            # Attempt to extract file/share name for some commands
            file_share = ""
            if cmd == 0x0003:  # TREE_CONNECT
                # request: path at fixed offset after header
                tc_offset = offset + 64 + 4  # SMB2 header is 64 bytes, then StructureSize(2)+Reserved(2)
                if tc_offset + 4 <= len(data) and not is_response:
                    path_offset = int.from_bytes(data[offset+64+2:offset+64+4], 'little')
                    path_len    = int.from_bytes(data[offset+64+4:offset+64+6], 'little')
                    try:
                        abs_path_off = offset + path_offset
                        file_share = data[abs_path_off:abs_path_off+path_len].decode('utf-16-le', errors='replace')
                        detail_lines.append(f"Share    : {file_share}")
                    except Exception:
                        pass

            # NTLM in SESSION_SETUP
            username = ""
            if cmd == 0x0001 and not is_response:  # SESSION_SETUP request
                # Security buffer may contain NTLM NEGOTIATE or AUTHENTICATE blob
                sec_offset_field = offset + 64 + 12
                if sec_offset_field + 4 <= len(data):
                    sec_blob_off = int.from_bytes(data[sec_offset_field:sec_offset_field+2], 'little')
                    sec_blob_len = int.from_bytes(data[sec_offset_field+2:sec_offset_field+4], 'little') if sec_offset_field+4 <= len(data) else 0
                    abs_blob = offset + sec_blob_off
                    blob = data[abs_blob:abs_blob+sec_blob_len]
                    if b'NTLMSSP\x00' in blob:
                        ntlm_start = blob.index(b'NTLMSSP\x00')
                        ntlm_blob = blob[ntlm_start:]
                        if len(ntlm_blob) > 12:
                            msg_type = int.from_bytes(ntlm_blob[8:12], 'little')
                            detail_lines.append(f"NTLM Msg : Type {msg_type}")
                            if msg_type == 3 and len(ntlm_blob) > 44:  # AUTHENTICATE
                                # Domain, Username, Workstation fields
                                try:
                                    uname_len = int.from_bytes(ntlm_blob[28:30], 'little')
                                    uname_off = int.from_bytes(ntlm_blob[32:36], 'little')
                                    username = ntlm_blob[uname_off:uname_off+uname_len].decode('utf-16-le', errors='replace')
                                    detail_lines.append(f"Username : {username}")
                                    nt_len = int.from_bytes(ntlm_blob[20:22], 'little')
                                    nt_off  = int.from_bytes(ntlm_blob[24:28], 'little')
                                    nt_hash = ntlm_blob[nt_off:nt_off+nt_len].hex()
                                    detail_lines.append(f"NTHash   : {nt_hash[:64]}{'…' if len(nt_hash)>64 else ''}")
                                    if username:
                                        self._insp_add_credential(
                                            "SMB NTLM", src, dst, username,
                                            f"NTHash:{nt_hash[:32]}", t,
                                            '\n'.join(detail_lines))
                                except Exception:
                                    pass

            entry = {
                'time': t, 'client': src if not is_response else dst,
                'server': dst if not is_response else src,
                'command': cmd_name, 'status': status_str,
                'file_share': file_share, 'user': username,
                'detail': '\n'.join(detail_lines),
            }
            self._smb_entries.append(entry)
            r = self.smb_table.rowCount()
            self.smb_table.insertRow(r)
            t_str = f"{t:.3f}" if isinstance(t, float) else str(t)
            vals = [str(len(self._smb_entries)), t_str,
                    entry['client'], entry['server'], cmd_name, status_str,
                    file_share, username]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                item.setData(Qt.UserRole, len(self._smb_entries) - 1)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.smb_table.setItem(r, c, item)
        except Exception:
            pass

    def _insp_smb_matches(self, row, flt):
        for c in range(self.smb_table.columnCount()):
            it = self.smb_table.item(row, c)
            if it and flt in it.text().lower():
                return True
        return False

    def _insp_smb_row_selected(self, row):
        if row < 0: return
        it = self.smb_table.item(row, 0)
        if not it: return
        idx = it.data(Qt.UserRole)
        if idx is None or idx >= len(self._smb_entries): return
        self.smb_detail.setPlainText(self._smb_entries[idx].get('detail', ''))

    # ------------------------------------------------------------------
    # Inspector — SQL sub-tab (MySQL port 3306, PostgreSQL port 5432)
    # ------------------------------------------------------------------

    _MYSQL_COMMANDS = {
        0x00: "COM_SLEEP",    0x01: "COM_QUIT",       0x02: "COM_INIT_DB",
        0x03: "COM_QUERY",    0x04: "COM_FIELD_LIST",  0x05: "COM_CREATE_DB",
        0x06: "COM_DROP_DB",  0x07: "COM_REFRESH",     0x08: "COM_SHUTDOWN",
        0x09: "COM_STATISTICS", 0x0a: "COM_PROCESS_INFO", 0x0d: "COM_DEBUG",
        0x0e: "COM_PING",     0x11: "COM_CHANGE_USER", 0x16: "COM_STMT_PREPARE",
        0x17: "COM_STMT_EXECUTE", 0x19: "COM_STMT_CLOSE", 0x1c: "COM_RESET_CONNECTION",
    }

    def _insp_parse_sql(self, pkt, t):
        from scapy.layers.inet import TCP, IP
        from scapy.packet import Raw
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        raw = bytes(pkt[Raw].load)
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if dport == 3306 or sport == 3306:
            self._insp_parse_mysql(pkt, t, raw, src, dst, sport, dport)
        elif dport == 5432 or sport == 5432:
            self._insp_parse_pgsql(pkt, t, raw, src, dst, sport, dport)
        elif dport == 1433 or sport == 1433:
            self._insp_parse_mssql(pkt, t, raw, src, dst, sport, dport)

    def _insp_parse_mysql(self, pkt, t, raw, src, dst, sport, dport):
        if len(raw) < 5:
            return
        payload_len = int.from_bytes(raw[0:3], 'little')
        seq = raw[3]
        if len(raw) < 4 + payload_len or payload_len == 0:
            return
        payload = raw[4:4 + payload_len]

        if dport != 3306:
            return

        cmd_byte = payload[0]

        # Auth handshake response (seq==1): extract username
        if seq == 1 and len(payload) > 36 and cmd_byte not in self._MYSQL_COMMANDS:
            try:
                username_start = 32  # capabilities(4)+max_packet(4)+charset(1)+reserved(23)
                null_pos = payload.find(b'\x00', username_start)
                if null_pos > username_start:
                    username = payload[username_start:null_pos].decode('utf-8', errors='replace')
                    if username and username.isprintable() and len(username) < 64:
                        client = f"{src}:{sport}"
                        server = f"{dst}:{dport}"
                        self._insp_add_credential(
                            "MySQL", client, server, username, "<auth hash>", t,
                            f"MySQL login from {client} to {server}\nUsername: {username}")
            except Exception:
                pass
            return

        if cmd_byte not in self._MYSQL_COMMANDS:
            return
        cmd_name = self._MYSQL_COMMANDS[cmd_byte]

        if cmd_byte == 0x0e:  # COM_PING — skip, no useful query
            return

        query = ''
        if cmd_byte == 0x03:  # COM_QUERY
            query = payload[1:].decode('utf-8', errors='replace').strip()
        elif cmd_byte == 0x02:  # COM_INIT_DB
            query = 'USE ' + payload[1:].decode('utf-8', errors='replace').strip()
        elif cmd_byte == 0x11:  # COM_CHANGE_USER
            null_pos = payload.find(b'\x00', 1)
            if null_pos > 1:
                query = 'CHANGE USER ' + payload[1:null_pos].decode('utf-8', errors='replace')
        elif cmd_byte == 0x16:  # COM_STMT_PREPARE
            query = payload[1:].decode('utf-8', errors='replace').strip()
        else:
            query = f"[{cmd_name}]"

        if not query:
            return

        entry = {
            'time': t,
            'client': f"{src}:{sport}",
            'server': f"{dst}:{dport}",
            'proto': 'MySQL',
            'command': cmd_name,
            'query': query,
            'detail': (
                f"Protocol : MySQL\n"
                f"Client   : {src}:{sport}\n"
                f"Server   : {dst}:{dport}\n"
                f"Command  : {cmd_name}\n"
                f"Seq#     : {seq}\n\n"
                f"{query}"
            ),
        }
        self._sql_entries.append(entry)
        self._insp_sql_add_row(entry)

    def _insp_parse_pgsql(self, pkt, t, raw, src, dst, sport, dport):
        if dport != 5432:
            return

        # Startup message: length(4) + protocol_version(4) + params — no type byte
        if len(raw) >= 8:
            proto_ver = int.from_bytes(raw[4:8], 'big')
            if proto_ver == 196608:  # 0x00030000 = protocol v3
                try:
                    msg_len = int.from_bytes(raw[0:4], 'big')
                    params_raw = raw[8:msg_len]
                    parts = params_raw.split(b'\x00')
                    params = {}
                    for i in range(0, len(parts) - 1, 2):
                        k = parts[i].decode('utf-8', errors='replace')
                        v = parts[i + 1].decode('utf-8', errors='replace') if i + 1 < len(parts) else ''
                        if k and v:
                            params[k] = v
                    if 'user' in params:
                        username = params['user']
                        database = params.get('database', params.get('dbname', '?'))
                        client = f"{src}:{sport}"
                        server = f"{dst}:{dport}"
                        detail_lines = [f"PostgreSQL startup from {client} to {server}"]
                        for k, v in params.items():
                            detail_lines.append(f"  {k}: {v}")
                        self._insp_add_credential(
                            "PostgreSQL", client, server, username,
                            f"database={database}", t, '\n'.join(detail_lines))
                except Exception:
                    pass
                return

        # Regular frontend messages: type(1) + length(4) + data
        i = 0
        while i < len(raw):
            if i + 5 > len(raw):
                break
            msg_type = raw[i:i + 1]
            msg_len = int.from_bytes(raw[i + 1:i + 5], 'big')
            if msg_len < 4 or i + 1 + msg_len > len(raw):
                break
            msg_data = raw[i + 5:i + 1 + msg_len]

            if msg_type == b'Q':  # Simple Query
                query = msg_data.rstrip(b'\x00').decode('utf-8', errors='replace').strip()
                if query:
                    entry = {
                        'time': t,
                        'client': f"{src}:{sport}",
                        'server': f"{dst}:{dport}",
                        'proto': 'PostgreSQL',
                        'command': 'Query',
                        'query': query,
                        'detail': (
                            f"Protocol : PostgreSQL\n"
                            f"Client   : {src}:{sport}\n"
                            f"Server   : {dst}:{dport}\n"
                            f"Command  : Simple Query\n\n"
                            f"{query}"
                        ),
                    }
                    self._sql_entries.append(entry)
                    self._insp_sql_add_row(entry)

            elif msg_type == b'P':  # Parse (prepared statement)
                null1 = msg_data.find(b'\x00')
                if null1 >= 0:
                    stmt_name = msg_data[:null1].decode('utf-8', errors='replace')
                    null2 = msg_data.find(b'\x00', null1 + 1)
                    end = null2 if null2 > 0 else len(msg_data)
                    query = msg_data[null1 + 1:end].decode('utf-8', errors='replace').strip()
                    if query:
                        stmt_label = stmt_name if stmt_name else '(unnamed)'
                        entry = {
                            'time': t,
                            'client': f"{src}:{sport}",
                            'server': f"{dst}:{dport}",
                            'proto': 'PostgreSQL',
                            'command': 'Parse (prepared)',
                            'query': query,
                            'detail': (
                                f"Protocol : PostgreSQL\n"
                                f"Client   : {src}:{sport}\n"
                                f"Server   : {dst}:{dport}\n"
                                f"Command  : Parse (Prepared Statement)\n"
                                f"Stmt     : {stmt_label}\n\n"
                                f"{query}"
                            ),
                        }
                        self._sql_entries.append(entry)
                        self._insp_sql_add_row(entry)

            i += 1 + msg_len

    # TDS packet type constants
    _TDS_TYPES = {
        0x01: "SQL Batch",    0x02: "Pre-Login (legacy)", 0x03: "RPC Request",
        0x06: "Attention",    0x07: "Bulk Load",           0x0e: "Transaction Manager",
        0x10: "TDS7 Login",   0x11: "SSPI",                0x12: "Pre-Login",
        0xff: "Response",
    }

    def _insp_parse_mssql(self, pkt, t, raw, src, dst, sport, dport):
        """Parse MSSQL TDS wire protocol. Handles SQL Batch and TDS7 Login."""
        if dport != 1433:
            return
        if len(raw) < 8:
            return

        pkt_type = raw[0]
        pkt_len = int.from_bytes(raw[2:4], 'big')
        if pkt_len < 8 or len(raw) < pkt_len:
            return

        data = raw[8:pkt_len]
        type_name = self._TDS_TYPES.get(pkt_type, f"0x{pkt_type:02x}")

        if pkt_type == 0x01:  # SQL Batch — UTF-16LE query
            try:
                query = data.decode('utf-16-le', errors='replace').strip()
            except Exception:
                return
            if not query:
                return
            entry = {
                'time': t,
                'client': f"{src}:{sport}",
                'server': f"{dst}:{dport}",
                'proto': 'MSSQL',
                'command': 'SQL Batch',
                'query': query,
                'detail': (
                    f"Protocol : MSSQL (TDS)\n"
                    f"Client   : {src}:{sport}\n"
                    f"Server   : {dst}:{dport}\n"
                    f"Command  : SQL Batch\n\n"
                    f"{query}"
                ),
            }
            self._sql_entries.append(entry)
            self._insp_sql_add_row(entry)

        elif pkt_type == 0x03:  # RPC Request — stored procedure call
            try:
                # Proc name: 2-byte length (chars) + UTF-16LE string
                if len(data) < 2:
                    return
                name_len = int.from_bytes(data[0:2], 'little')
                if name_len > 0 and len(data) >= 2 + name_len * 2:
                    proc_name = data[2:2 + name_len * 2].decode('utf-16-le', errors='replace')
                else:
                    proc_name = '(unknown)'
                entry = {
                    'time': t,
                    'client': f"{src}:{sport}",
                    'server': f"{dst}:{dport}",
                    'proto': 'MSSQL',
                    'command': 'RPC Request',
                    'query': f"EXEC {proc_name}",
                    'detail': (
                        f"Protocol : MSSQL (TDS)\n"
                        f"Client   : {src}:{sport}\n"
                        f"Server   : {dst}:{dport}\n"
                        f"Command  : RPC Request\n"
                        f"Procedure: {proc_name}"
                    ),
                }
                self._sql_entries.append(entry)
                self._insp_sql_add_row(entry)
            except Exception:
                pass

        elif pkt_type == 0x10:  # TDS7 Login — extract username + deobfuscate password
            try:
                # Login7 fixed header layout (offsets into `data`):
                # 36-37  ibHostName,  38-39  cchHostName
                # 40-41  ibUserName,  42-43  cchUserName
                # 44-45  ibPassword,  46-47  cchPassword
                if len(data) < 48:
                    return
                uname_off = int.from_bytes(data[40:42], 'little')
                uname_len = int.from_bytes(data[42:44], 'little')
                pword_off = int.from_bytes(data[44:46], 'little')
                pword_len = int.from_bytes(data[46:48], 'little')

                if uname_len == 0 or uname_off + uname_len * 2 > len(data):
                    return
                username = data[uname_off:uname_off + uname_len * 2].decode('utf-16-le', errors='replace')
                if not username or not username.isprintable():
                    return

                # TDS password obfuscation: swap nibbles then XOR 0xA5 (per-byte).
                # Reversible: XOR 0xA5 then swap nibbles.
                password = ''
                if pword_len > 0 and pword_off + pword_len * 2 <= len(data):
                    raw_pw = bytearray(data[pword_off:pword_off + pword_len * 2])
                    deobf = bytearray(len(raw_pw))
                    for i, b in enumerate(raw_pw):
                        b ^= 0xA5
                        deobf[i] = ((b & 0x0F) << 4) | ((b >> 4) & 0x0F)
                    password = deobf.decode('utf-16-le', errors='replace')

                client = f"{src}:{sport}"
                server = f"{dst}:{dport}"
                secret = password if password else "<no password>"
                detail = (
                    f"MSSQL login from {client} to {server}\n"
                    f"Username : {username}\n"
                    f"Password : {secret}\n\n"
                    f"Note: password is XOR-obfuscated in TDS, not hashed — "
                    f"plaintext recovered from wire."
                )
                self._insp_add_credential("MSSQL", client, server, username, secret, t, detail)
            except Exception:
                pass

    def _insp_sql_add_row(self, entry):
        r = self.sql_table.rowCount()
        self.sql_table.insertRow(r)
        t_str = f"{entry['time']:.3f}" if isinstance(entry['time'], float) else str(entry['time'])
        vals = [
            str(len(self._sql_entries)),
            t_str,
            entry['client'],
            entry['server'],
            entry['proto'],
            entry['command'],
            entry['query'][:120],
        ]
        idx = len(self._sql_entries) - 1
        for c, v in enumerate(vals):
            item = QTableWidgetItem(v)
            item.setData(Qt.UserRole, idx)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self.sql_table.setItem(r, c, item)
        flt = self.proxy_filter_edit.text().strip().lower()
        if flt and not self._insp_sql_matches(entry, flt):
            self.sql_table.setRowHidden(r, True)

    def _insp_sql_row_selected(self, row):
        if row < 0:
            return
        it = self.sql_table.item(row, 0)
        if not it:
            return
        idx = it.data(Qt.UserRole)
        if idx is None or idx >= len(self._sql_entries):
            return
        self.sql_detail.setPlainText(self._sql_entries[idx].get('detail', ''))

    def _insp_sql_matches(self, entry, flt):
        text = ' '.join([
            entry.get('client', ''), entry.get('server', ''),
            entry.get('proto', ''), entry.get('command', ''),
            entry.get('query', ''),
        ]).lower()
        return flt in text

    def _insp_sql_copy(self):
        text = self.sql_detail.toPlainText()
        if text:
            QtWidgets.QApplication.clipboard().setText(text)

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def _show_statistics(self, ip_version):
        import collections
        from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout,
            QTabWidget, QLabel, QPushButton, QTableWidget,
            QTableWidgetItem, QHeaderView, QSizePolicy)
        from PyQt5.QtGui import QFont
        from PyQt5.QtCore import Qt

        ver_layer = IP if ip_version == 4 else IPv6
        title = f"IPv{ip_version} Statistics"

        # Collect matching packets with their timestamps
        pairs = []
        for pkt, t in zip(self.packet_list,
                          self.time_list if self.time_list else [0.0] * len(self.packet_list)):
            if ip_version == 4 and pkt.haslayer(IP) and not pkt.haslayer(IPv6):
                pairs.append((pkt, t))
            elif ip_version == 6 and pkt.haslayer(IPv6):
                pairs.append((pkt, t))

        if not pairs:
            QtWidgets.QMessageBox.information(
                self, title, f"No IPv{ip_version} packets in the current capture.")
            return

        total_pkts  = len(pairs)
        total_bytes = sum(len(bytes(p)) for p, _ in pairs)
        t_start     = pairs[0][1]
        t_end       = pairs[-1][1]
        duration    = t_end - t_start

        # ── Aggregate data ────────────────────────────────────────────────
        proto_pkts   = collections.Counter()
        proto_bytes  = collections.Counter()
        src_pkts     = collections.Counter()
        src_bytes    = collections.Counter()
        dst_pkts     = collections.Counter()
        dst_bytes    = collections.Counter()
        conv_pkts    = collections.Counter()
        conv_bytes   = collections.Counter()
        size_buckets = [
            ("0 – 64",     0,    64),
            ("65 – 128",   65,   128),
            ("129 – 256",  129,  256),
            ("257 – 512",  257,  512),
            ("513 – 1024", 513,  1024),
            ("1025 +",     1025, 10**9),
        ]
        bucket_pkts  = collections.OrderedDict((lbl, 0) for lbl, _, _ in size_buckets)

        for pkt, _ in pairs:
            proto = get_protocol(pkt)
            size  = len(bytes(pkt))
            proto_pkts[proto]  += 1
            proto_bytes[proto] += size
            if pkt.haslayer(ver_layer):
                src = pkt[ver_layer].src
                dst = pkt[ver_layer].dst
                src_pkts[src]  += 1;  src_bytes[src]  += size
                dst_pkts[dst]  += 1;  dst_bytes[dst]  += size
                key = tuple(sorted([src, dst]))
                conv_pkts[key]  += 1; conv_bytes[key]  += size
            for lbl, lo, hi in size_buckets:
                if lo <= size <= hi:
                    bucket_pkts[lbl] += 1
                    break

        # ── Helper: build a sortable QTableWidget ─────────────────────────
        mono = QFont("Monospace", 10)

        def make_table(headers):
            t = QTableWidget()
            t.setColumnCount(len(headers))
            t.setRowCount(0)
            t.setEditTriggers(QTableWidget.NoEditTriggers)
            t.setSelectionBehavior(QTableWidget.SelectRows)
            t.setSortingEnabled(True)
            t.setFont(mono)
            t.verticalHeader().setVisible(False)
            t.horizontalHeader().setStretchLastSection(True)
            for i, h in enumerate(headers):
                t.setHorizontalHeaderItem(i, QTableWidgetItem(h))
            return t

        def num_item(val):
            it = QTableWidgetItem()
            it.setData(Qt.DisplayRole, val)
            return it

        def bar_item(count, total):
            """Text progress bar cell + percentage."""
            pct = count / total * 100 if total else 0
            filled = int(pct / 5)          # 20 chars = 100 %
            bar = '█' * filled + '░' * (20 - filled)
            it = QTableWidgetItem(f"{bar}  {pct:.1f} %")
            it.setData(Qt.UserRole, pct)   # numeric value for sorting
            return it

        def human_bytes(n):
            for unit in ('B', 'KB', 'MB', 'GB'):
                if n < 1024:
                    return f"{n:.0f} {unit}"
                n /= 1024
            return f"{n:.1f} TB"

        # ── Dialog shell ──────────────────────────────────────────────────
        dlg = QDialog(self)
        dlg.setWindowTitle(title)
        dlg.resize(900, 620)
        dlg.setModal(False)
        root = QVBoxLayout(dlg)
        root.setSpacing(6)

        # Summary banner
        if duration > 0:
            rate_pps = f"{total_pkts / duration:.1f} pkt/s"
            rate_bps = f"{total_bytes * 8 / duration / 1000:.1f} kbit/s"
        else:
            rate_pps = rate_bps = "—"

        banner = QLabel(
            f"  <b>{total_pkts:,}</b> packets  ·  "
            f"<b>{human_bytes(total_bytes)}</b>  ·  "
            f"Duration <b>{duration:.3f} s</b>  ·  "
            f"Avg <b>{rate_pps}</b>  /  <b>{rate_bps}</b>"
        )
        banner.setStyleSheet(
            "background:#1e1e1e; color:#d4d4d4; padding:6px 10px; font-size:11pt;")
        root.addWidget(banner)

        tabs = QTabWidget()
        root.addWidget(tabs, stretch=1)

        # ── Tab 1: Protocol Distribution ──────────────────────────────────
        pt = make_table(["Protocol", "Packets", "% Packets", "Bytes", "% Bytes"])
        pt.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        for proto, cnt in proto_pkts.most_common():
            r = pt.rowCount(); pt.insertRow(r); pt.setRowHeight(r, 20)
            pt.setItem(r, 0, QTableWidgetItem(proto))
            pt.setItem(r, 1, num_item(cnt))
            pt.setItem(r, 2, bar_item(cnt, total_pkts))
            bc = proto_bytes[proto]
            pt.setItem(r, 3, num_item(bc))
            pt.setItem(r, 4, bar_item(bc, total_bytes))
        tabs.addTab(pt, "Protocols")

        # ── Tab 2: Top Sources ────────────────────────────────────────────
        st = make_table(["Source Address", "Packets", "% Packets", "Bytes"])
        st.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        for src, cnt in src_pkts.most_common(200):
            r = st.rowCount(); st.insertRow(r); st.setRowHeight(r, 20)
            st.setItem(r, 0, QTableWidgetItem(src))
            st.setItem(r, 1, num_item(cnt))
            st.setItem(r, 2, bar_item(cnt, total_pkts))
            st.setItem(r, 3, num_item(src_bytes[src]))
        tabs.addTab(st, "Top Sources")

        # ── Tab 3: Top Destinations ───────────────────────────────────────
        dt = make_table(["Destination Address", "Packets", "% Packets", "Bytes"])
        dt.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        for dst, cnt in dst_pkts.most_common(200):
            r = dt.rowCount(); dt.insertRow(r); dt.setRowHeight(r, 20)
            dt.setItem(r, 0, QTableWidgetItem(dst))
            dt.setItem(r, 1, num_item(cnt))
            dt.setItem(r, 2, bar_item(cnt, total_pkts))
            dt.setItem(r, 3, num_item(dst_bytes[dst]))
        tabs.addTab(dt, "Top Destinations")

        # ── Tab 4: Conversations ──────────────────────────────────────────
        ct = make_table(["Address A", "Address B", "Packets", "Bytes", "Avg Size"])
        ct.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        ct.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        for (a, b), cnt in conv_pkts.most_common(200):
            r = ct.rowCount(); ct.insertRow(r); ct.setRowHeight(r, 20)
            ct.setItem(r, 0, QTableWidgetItem(a))
            ct.setItem(r, 1, QTableWidgetItem(b))
            ct.setItem(r, 2, num_item(cnt))
            bc = conv_bytes[(a, b)]
            ct.setItem(r, 3, num_item(bc))
            ct.setItem(r, 4, num_item(bc // cnt if cnt else 0))
        tabs.addTab(ct, "Conversations")

        # ── Tab 5: Packet Size Distribution ──────────────────────────────
        szt = make_table(["Size Range (bytes)", "Packets", "% Packets"])
        szt.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        for lbl, cnt in bucket_pkts.items():
            r = szt.rowCount(); szt.insertRow(r); szt.setRowHeight(r, 20)
            szt.setItem(r, 0, QTableWidgetItem(lbl))
            szt.setItem(r, 1, num_item(cnt))
            szt.setItem(r, 2, bar_item(cnt, total_pkts))
        tabs.addTab(szt, "Packet Sizes")

        # Close button
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.close)
        btn_row.addWidget(close_btn)
        root.addLayout(btn_row)

        dlg.show()

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def _session_key(self, pkt):
        """Return a canonical (proto, endpoint_a, endpoint_b) tuple or None."""
        if pkt.haslayer(TCP):
            proto = "TCP"
            layer = pkt[TCP]
        elif pkt.haslayer(UDP):
            proto = "UDP"
            layer = pkt[UDP]
        else:
            return None

        if pkt.haslayer(IP):
            a = f"{pkt[IP].src}:{layer.sport}"
            b = f"{pkt[IP].dst}:{layer.dport}"
        elif pkt.haslayer(IPv6):
            a = f"{pkt[IPv6].src}:{layer.sport}"
            b = f"{pkt[IPv6].dst}:{layer.dport}"
        else:
            return None

        # Canonical order so A→B and B→A map to the same session
        return (proto, min(a, b), max(a, b))

    def _refresh_sessions(self):
        """Rebuild the sessions table from the current packet list."""
        self._sessions = {}
        for idx, pkt in enumerate(self.packet_list):
            key = self._session_key(pkt)
            if key is None:
                continue
            t = self.time_list[idx] if idx < len(self.time_list) else 0.0
            if key not in self._sessions:
                self._sessions[key] = {
                    'proto':      key[0],
                    'src':        key[1],
                    'dst':        key[2],
                    'packets':    [],
                    'start_time': t,
                    'end_time':   t,
                }
            s = self._sessions[key]
            s['packets'].append(pkt)
            s['end_time'] = t

        self._session_keys = list(self._sessions.keys())

        self.sessions_table.blockSignals(True)
        self.sessions_table.setRowCount(0)
        for key in self._session_keys:
            s = self._sessions[key]
            row = self.sessions_table.rowCount()
            self.sessions_table.insertRow(row)
            total_bytes = sum(len(bytes(p)) for p in s['packets'])
            duration = s['end_time'] - s['start_time']
            for col, text in enumerate([
                s['proto'],
                s['src'],
                s['dst'],
                str(len(s['packets'])),
                str(total_bytes),
                f"{duration:.3f}s",
            ]):
                item = QtWidgets.QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.sessions_table.setItem(row, col, item)
        self.sessions_table.blockSignals(False)

    def _show_session_stream(self, row, col):
        if row >= len(self._session_keys):
            return
        self._render_stream(self._sessions[self._session_keys[row]])

    def _follow_stream(self):
        selected_rows = sorted({item.row() for item in self.sessions_table.selectedItems()})
        if selected_rows:
            self._show_session_stream(selected_rows[0], 0)

    def _render_stream(self, sess):
        """Render a session's packets into the stream_view widget."""
        mode = self.streamModeCombo.currentText()
        src = sess['src']
        lines = []
        for pkt in sess['packets']:
            # Determine direction relative to the canonical src endpoint
            try:
                if pkt.haslayer(IP):
                    sport = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport
                    pkt_src = f"{pkt[IP].src}:{sport}"
                elif pkt.haslayer(IPv6):
                    sport = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport
                    pkt_src = f"{pkt[IPv6].src}:{sport}"
                else:
                    pkt_src = ""
            except Exception:
                pkt_src = ""

            arrow = "-->" if pkt_src == src else "<--"
            raw = bytes(pkt)
            lines.append(f"[ {arrow}  {len(raw)} bytes ]")

            if mode == "ASCII only":
                lines.append(''.join(chr(b) if 32 <= b < 127 else '.' for b in raw))
            elif mode == "Raw Hex":
                lines.append(raw.hex())
            else:   # Hex + ASCII
                for i in range(0, len(raw), 16):
                    chunk = raw[i:i + 16]
                    hex_part = ' '.join(f'{b:02X}' for b in chunk)
                    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                    lines.append(f"  {i:04x}  {hex_part:<47}  {ascii_part}")
            lines.append("")

        self.stream_view.setPlainText('\n'.join(lines))

    # ------------------------------------------------------------------
    # Attack tab
    # ------------------------------------------------------------------

    def _atk_populate_ifaces(self):
        """Fill all attack interface combos with available interfaces."""
        try:
            import netifaces
        except ImportError:
            import netifaces2 as netifaces
        ifaces = netifaces.interfaces()
        for combo in (self.atk_arp_iface, self.atk_dns_iface, self.atk_deauth_iface):
            combo.clear()
            for iface in ifaces:
                combo.addItem(iface)

    def _atk_log(self, name, msg):
        """Append a message to the named attack log widget (thread-safe)."""
        widget = getattr(self, f"atk_log_{name}", None)
        if widget is None:
            return
        QMetaObject.invokeMethod(
            widget, "appendPlainText",
            Qt.QueuedConnection,
            Q_ARG("QString", msg),
        )

    def _atk_set_running(self, name, running: bool):
        """Toggle Start/Stop button state for a given attack."""
        start = getattr(self, f"atk_{name}_start", None)
        stop  = getattr(self, f"atk_{name}_stop",  None)
        if start:
            start.setEnabled(not running)
        if stop:
            stop.setEnabled(running)

    def _atk_start(self, name):
        import threading
        if name in self._atk_threads:
            t, ev = self._atk_threads[name]
            if t.is_alive():
                return   # already running

        stop_ev = threading.Event()
        log_cb  = lambda msg: self._atk_log(name, msg)
        widget  = getattr(self, f"atk_log_{name}", None)
        if widget:
            widget.clear()

        if name == "arp":
            target  = self.atk_arp_target.text().strip()
            gateway = self.atk_arp_gateway.text().strip()
            iface   = self.atk_arp_iface.currentText()
            if not target or not gateway:
                QtWidgets.QMessageBox.warning(self, "ARP Spoof", "Enter Target IP and Gateway IP.")
                return
            if self.atk_arp_ipfwd.isChecked() and sys.platform != "win32":
                try:
                    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                        f.write('1\n')
                    log_cb("[ARP] IP forwarding enabled")
                except Exception as e:
                    log_cb(f"[ARP] Could not enable IP forwarding: {e}")
            fn = lambda: _atk_engine.arp_spoof(target, gateway, iface, stop_ev, log_cb)

        elif name == "dns":
            iface    = self.atk_dns_iface.currentText()
            spoof_map = {}
            for r in range(self.atk_dns_table.rowCount()):
                domain_item = self.atk_dns_table.item(r, 0)
                ip_item     = self.atk_dns_table.item(r, 1)
                if domain_item and ip_item:
                    d = domain_item.text().strip()
                    i = ip_item.text().strip()
                    if d and i:
                        spoof_map[d] = i
            if not spoof_map:
                QtWidgets.QMessageBox.warning(self, "DNS Spoof", "Add at least one Domain → Fake IP mapping.")
                return
            fn = lambda: _atk_engine.dns_spoof(iface, spoof_map, stop_ev, log_cb)

        elif name == "deauth":
            iface  = self.atk_deauth_iface.currentText()
            bssid  = self.atk_deauth_bssid.text().strip()
            client = self.atk_deauth_client.text().strip()
            reason = self.atk_deauth_reason.value()
            if not bssid:
                QtWidgets.QMessageBox.warning(self, "Deauth", "Enter the BSSID (AP MAC address).")
                return
            fn = lambda: _atk_engine.deauth(iface, bssid, client, reason, stop_ev, log_cb)

        elif name == "dhs":
            iface = self.atk_dhs_iface.currentText()
            fn = lambda: _atk_engine.dhcp_starvation(iface, stop_ev, log_cb)

        elif name == "rd":
            iface      = self.atk_rd_iface.currentText()
            server_ip  = self.atk_rd_server_ip.text().strip()
            router_ip  = self.atk_rd_router.text().strip()
            dns_ip     = self.atk_rd_dns.text().strip()
            mask       = self.atk_rd_mask.text().strip()
            pool_start = self.atk_rd_pool_start.text().strip()
            pool_end   = self.atk_rd_pool_end.text().strip()
            lease      = self.atk_rd_lease.value()
            missing = [f for f, v in [("Server IP", server_ip), ("Router", router_ip),
                                       ("DNS", dns_ip), ("Pool Start", pool_start),
                                       ("Pool End", pool_end)] if not v]
            if missing:
                QtWidgets.QMessageBox.warning(self, "Rogue DHCP",
                    f"Fill in: {', '.join(missing)}")
                return
            fn = lambda: _atk_engine.rogue_dhcp(
                iface, server_ip, mask, router_ip, dns_ip,
                pool_start, pool_end, lease, stop_ev, log_cb)

        elif name == "ll":
            our_ip = self.atk_ll_our_ip.text().strip()
            if not our_ip:
                QtWidgets.QMessageBox.warning(self, "LLMNR/NBT-NS", "Enter our IP address.")
                return
            names_raw = self.atk_ll_names.text().strip()
            target_names = [n.strip() for n in names_raw.split(",") if n.strip()]
            fn = lambda: _atk_engine.llmnr_nbtns_poison(our_ip, target_names, stop_ev, log_cb)

        else:
            return

        import threading
        t = threading.Thread(target=fn, daemon=True)
        self._atk_threads[name] = (t, stop_ev)
        self._atk_set_running(name, True)
        t.start()

    def _atk_stop(self, name):
        entry = self._atk_threads.get(name)
        if entry:
            _, stop_ev = entry
            stop_ev.set()
        self._atk_set_running(name, False)

    def _atk_dns_add_row(self):
        r = self.atk_dns_table.rowCount()
        self.atk_dns_table.insertRow(r)
        self.atk_dns_table.setItem(r, 0, QtWidgets.QTableWidgetItem(""))
        self.atk_dns_table.setItem(r, 1, QtWidgets.QTableWidgetItem(""))

    def _atk_dns_del_row(self):
        row = self.atk_dns_table.currentRow()
        if row >= 0:
            self.atk_dns_table.removeRow(row)

    def _atk_autofill_ip(self, iface_name):
        """Auto-fill Server IP, Router, and DNS fields from the selected interface."""
        try:
            import netifaces
        except ImportError:
            import netifaces2 as netifaces
        try:
            addrs = netifaces.ifaddresses(iface_name)
            ipv4_list = addrs.get(netifaces.AF_INET, [])
            if ipv4_list:
                our_ip = ipv4_list[0]['addr']
                if not self.atk_rd_server_ip.text():
                    self.atk_rd_server_ip.setText(our_ip)
                if not self.atk_rd_router.text():
                    self.atk_rd_router.setText(our_ip)
                if not self.atk_rd_dns.text():
                    self.atk_rd_dns.setText(our_ip)
                if not self.atk_ll_our_ip.text():
                    self.atk_ll_our_ip.setText(our_ip)
        except Exception:
            pass


def _http_split(buf: bytes) -> list:
    """Split a raw HTTP stream buffer into complete message bytes.
    Returns a list of complete messages (each including headers + body).
    Incomplete trailing data is left in the caller's buffer."""
    messages = []
    while buf:
        # Need at least the headers
        sep = buf.find(b'\r\n\r\n')
        if sep == -1:
            break
        header_end = sep + 4
        headers_raw = buf[:sep]
        # Determine body length
        content_length = 0
        chunked = False
        for line in headers_raw.split(b'\r\n')[1:]:
            low = line.lower().strip()
            if low.startswith(b'content-length:'):
                try:
                    content_length = int(low.split(b':', 1)[1].strip())
                except ValueError:
                    content_length = 0
            elif low.startswith(b'transfer-encoding:') and b'chunked' in low:
                chunked = True

        if chunked:
            # Chunked: look for terminal 0\r\n\r\n
            end_marker = b'0\r\n\r\n'
            end = buf.find(end_marker, header_end)
            if end == -1:
                break
            end += len(end_marker)
        else:
            end = header_end + content_length
            if len(buf) < end:
                break

        messages.append(buf[:end])
        buf = buf[end:]
    return messages


def _is_printable(data: bytes, threshold: float = 0.75) -> bool:
    """Return True if >= threshold fraction of bytes are printable ASCII."""
    if not data:
        return True
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return (printable / len(data)) >= threshold


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    tool = SniffTool()
    qtmodern.styles.dark(app)
    moderntool = qtmodern.windows.ModernWindow(tool)
    moderntool.showMaximized()
    app.exec_()
