import re
import sys
import time as _time

from PyQt5 import QtWidgets, QtGui
from PyQt5.QtWidgets import QTreeWidgetItem, QMenu, QAction, QFileDialog
from PyQt5.QtCore import QEvent, pyqtSlot, Qt
from PyQt5.QtGui import QColor

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
from ca_manager import CAManager
from tls_proxy import TLSProxy

if sys.platform != "win32":
    from p_firewall import flush, tls_intercept, tls_flush


# Wireshark-inspired protocol row colors
_PROTO_COLORS = {
    "HTTP":     QColor(0xe4, 0xfd, 0xe1),
    "HTTPS":    QColor(0xc8, 0xf0, 0xc8),
    "DNS":      QColor(0xd0, 0xe8, 0xff),
    "TCP":      QColor(0xe7, 0xe6, 0xff),
    "UDP":      QColor(0xda, 0xff, 0xda),
    "ICMP":     QColor(0xff, 0xf7, 0xb5),
    "ARP":      QColor(0xff, 0xed, 0xd7),
    "SSH":      QColor(0xd0, 0xff, 0xff),
    "FTP":      QColor(0xff, 0xe4, 0xc8),
    "SMB":      QColor(0xff, 0xd0, 0xd0),
    "Unknown":  QColor(0xf0, 0xf0, 0xf0),
}


class SniffTool(QtWidgets.QMainWindow, qt_ui.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.statusBar().setStyleSheet("border :3px solid black;")
        self.c = CoreClass(self)
        self.setupUi(self)
        self.t = None
        self.running_info.setText("Ready to sniff")
        self.packet_list = []
        self.time_list = []        # parallel to packet_list: capture time offset per packet
        self.auto_down_scroll = True
        self.initial_time = 0.0
        self.debugmode = False
        self._active_filter = ""
        self.rep_loaded_packet = None   # packet currently loaded in Repeater
        self._sessions = {}             # session key -> session dict
        self._session_keys = []         # ordered list of session keys for table lookup

        # TLS interception
        self._ca = CAManager()
        self._tls_proxy = TLSProxy(self._ca, parent=self)
        self._tls_proxy.data_intercepted.connect(self._on_tls_data)
        self._tls_intercept_rows = []   # list of (hostname, direction, data) stored per row

        self.interface_2.addItem("Any...")
        self.interface_2.addItems(netifaces.interfaces())

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
        self.detail_tree_widget.itemChanged.connect(self.updateFilterTable)

        # TLS signals
        self.tls_gen_ca_btn.clicked.connect(self._tls_gen_ca)
        self.tls_export_ca_btn.clicked.connect(self._tls_export_ca)
        self.tls_start_btn.clicked.connect(self._tls_start)
        self.tls_stop_btn.clicked.connect(self._tls_stop)
        self.tls_table.cellClicked.connect(self._tls_show_row)
        self._update_ca_status()

        # Repeater signals
        self.rep_loadButton.clicked.connect(self._repeater_load)
        self.rep_sendButton.clicked.connect(self._repeater_send)

        # Sessions signals
        self.refreshSessionsButton.clicked.connect(self._refresh_sessions)
        self.sessions_table.cellClicked.connect(self._show_session_stream)
        self.followStreamButton.clicked.connect(self._follow_stream)

        # Menu signals
        self.actionOpen.triggered.connect(self.load_pcap)
        self.actionSave.triggered.connect(self.save_pcap)
        self.actionSave_as.triggered.connect(self.save_pcap)

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
            menu = QMenu()
            resend_action = QAction("Resend", self)
            resend_action.triggered.connect(self.onResendMenuClicked)
            menu.addAction(resend_action)
            menu.exec_(event.globalPos())
            return True
        return super().eventFilter(source, event)

    def onResendMenuClicked(self):
        selected_rows = {item.row() for item in self.filter_table.selectedItems()}
        for row in selected_rows:
            send(self.packet_list[row])

    # ------------------------------------------------------------------
    # Capture control
    # ------------------------------------------------------------------

    def sniff_button_event(self):
        self.sniffButton.setEnabled(False)
        self.haltButton.setEnabled(True)
        selected_interface = str(self.interface_2.currentText())
        if self.mode_combo.currentIndex() == 0:
            if sys.platform == "win32":
                target = lambda: self.c.run_windivert(selected_interface)
            else:
                target = lambda: self.c.run(selected_interface)
        else:
            target = lambda: self.c.run_sniff(selected_interface)
        self.t = threading.Thread(target=target, daemon=True)
        self.t.start()

    def stop_button_event(self):
        self.sniffButton.setEnabled(True)
        self.haltButton.setEnabled(False)
        self.c.stop()

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

    def deb_break_button_event(self):
        self.deb_breakButton.setEnabled(False)
        self.deb_nextButton.setEnabled(True)
        self.deb_continueButton.setEnabled(True)
        self.debugmode = True

    def deb_next_button_event(self):
        self.c.debug_step()

    def deb_continue_button_event(self):
        self.deb_breakButton.setEnabled(True)
        self.deb_nextButton.setEnabled(False)
        self.deb_continueButton.setEnabled(False)
        self.debugmode = False
        self.c.debug_step()

    # ------------------------------------------------------------------
    # View helpers
    # ------------------------------------------------------------------

    def clear_view(self):
        self.filter_table.clearContents()
        self.filter_table.setRowCount(0)
        self.detail_tree_widget.clear()
        self.hexdump_hex1.clear()
        self.hexdump_ascii.clear()
        self.hexdump_row.clear()
        self.packet_list = []
        self.time_list = []
        self.c.packet_counter = 0
        self.c.myturn = 0
        self.initial_time = 0.0
        self._active_filter = ""
        self.filterText.clear()
        self.filterText.setStyleSheet("")

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

    def show_packet(self, row, col):
        self.detail_tree_widget.clear()
        if row >= len(self.packet_list):
            return
        pkt = self.packet_list[row]
        pkt_bytes = bytes(pkt)
        t = self.time_list[row] if row < len(self.time_list) else 0.0

        # ── Frame summary ──────────────────────────────────────────────
        frame_node = QTreeWidgetItem(self.detail_tree_widget,
            [f"Frame {row + 1}: {len(pkt_bytes)} bytes captured"])
        QTreeWidgetItem(frame_node, [f"Frame Number: {row + 1}"])
        QTreeWidgetItem(frame_node, [f"Capture Time: {t:.6f} seconds"])
        QTreeWidgetItem(frame_node, [f"Frame Length: {len(pkt_bytes)} bytes ({len(pkt_bytes) * 8} bits)"])

        # ── Protocol layers ────────────────────────────────────────────
        layer = pkt
        while layer and layer.name != "NoPayload":
            if layer.name == "Raw":
                load = getattr(layer, 'load', b'')
                raw_node = QTreeWidgetItem(self.detail_tree_widget,
                    [f"Data  ({len(load)} bytes)"])
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
                for fname, fval in layer.fields.items():
                    QTreeWidgetItem(node, [self._format_field(layer.name, fname, fval)])

            layer = layer.payload if layer.payload else None

        self.detail_tree_widget.expandAll()

    # ------------------------------------------------------------------
    # Hex dump
    # ------------------------------------------------------------------

    def show_hex_packet(self, row, col):
        self.hexdump_row.clear()
        self.hexdump_hex1.clear()
        self.hexdump_ascii.clear()
        if row >= len(self.packet_list):
            return
        pkt = self.packet_list[row]
        x = bytes(pkt)
        mono = "QListWidget::item { font-family: monospace; font-size: 11px; }"
        self.hexdump_row.setStyleSheet(mono)
        self.hexdump_hex1.setStyleSheet(mono)
        self.hexdump_ascii.setStyleSheet(mono)
        for i in range(0, len(x), 16):
            chunk = x[i:i + 16]
            hex_str = " ".join(f"{b:02X}" for b in chunk)
            hex_str += "   " * (16 - len(chunk))    # pad short last row
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            self.hexdump_row.addItem(f"{i:04x}")
            self.hexdump_hex1.addItem(hex_str)
            self.hexdump_ascii.addItem(ascii_str)

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

        proto = get_protocol(spacket)
        t_display = self.time_list[row] if row < len(self.time_list) else 0.0
        color = _PROTO_COLORS.get(proto, _PROTO_COLORS.get(proto.split()[0], None))

        cols = [
            str(round(t_display, 6)),
            packet_src(spacket),
            packet_dst(spacket),
            proto,
            str(packet_len(spacket)),
            spacket.summary(),
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
            self.filter_table.setItem(row, c, item)
        self.filter_table.blockSignals(False)

        # Apply active filter immediately to the new row
        if is_new and self._active_filter:
            hidden = not self._matches_filter(spacket, self._active_filter)
            self.filter_table.setRowHidden(row, hidden)

        if self.auto_down_scroll:
            self.filter_table.scrollToBottom()

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
        if path:
            wrpcap(path, self.packet_list)

    def load_pcap(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open capture", "", "PCAP files (*.pcap *.pcapng);;All files (*)"
        )
        if not path:
            return
        self.clear_view()
        for pkt in rdpcap(path):
            self.push_packets(pkt)


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

    def _tls_start(self):
        if not self._ca.is_ready:
            QtWidgets.QMessageBox.warning(
                self, "No CA",
                "Generate a CA first (and install it as trusted).")
            return
        try:
            intercept_port = int(self.tls_intercept_port.text())
            proxy_port     = int(self.tls_proxy_port.text())
        except ValueError:
            QtWidgets.QMessageBox.warning(self, "Invalid ports", "Ports must be numbers.")
            return

        self._tls_proxy.listen_port = proxy_port
        self._tls_proxy.start()

        if sys.platform != "win32":
            try:
                tls_intercept(intercept_port, proxy_port)
            except Exception as exc:
                QtWidgets.QMessageBox.warning(
                    self, "iptables failed",
                    f"{exc}\n\nProxy is running but traffic is not being redirected.\n"
                    "Make sure you are root and iptables is available.",
                )

        self.tls_proxy_status.setText("Status: Active")
        self.tls_proxy_status.setStyleSheet("color: green; font-weight: bold;")
        self.tls_start_btn.setEnabled(False)
        self.tls_stop_btn.setEnabled(True)

    def _tls_stop(self):
        try:
            intercept_port = int(self.tls_intercept_port.text())
            proxy_port     = int(self.tls_proxy_port.text())
        except ValueError:
            intercept_port, proxy_port = 443, 8443

        self._tls_proxy.stop()

        if sys.platform != "win32":
            try:
                tls_flush(intercept_port, proxy_port)
            except Exception:
                pass

        self.tls_proxy_status.setText("Status: Stopped")
        self.tls_proxy_status.setStyleSheet("")
        self.tls_start_btn.setEnabled(True)
        self.tls_stop_btn.setEnabled(False)

    @pyqtSlot(str, str, bytes)
    def _on_tls_data(self, hostname: str, direction: str, data: bytes):
        """Called (in main thread) for every intercepted TLS chunk."""
        row = self.tls_table.rowCount()
        self.tls_table.insertRow(row)

        preview = self._tls_preview(data)
        for col, text in enumerate([hostname, direction, str(len(data)), preview]):
            item = QtWidgets.QTableWidgetItem(text)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self.tls_table.setItem(row, col, item)

        self._tls_intercept_rows.append((hostname, direction, data))
        self.tls_table.scrollToBottom()

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

    def _repeater_load(self):
        """Load the first selected Capture-tab packet into the Repeater editor."""
        selected_rows = sorted({item.row() for item in self.filter_table.selectedItems()})
        if not selected_rows:
            QtWidgets.QMessageBox.information(
                self, "Repeater", "Select a packet in the Capture tab first.")
            return
        row = selected_rows[0]
        if row >= len(self.packet_list):
            return
        self.rep_loaded_packet = self.packet_list[row]
        pkt_bytes = bytes(self.rep_loaded_packet)
        lines = []
        for i in range(0, len(pkt_bytes), 16):
            chunk = pkt_bytes[i:i + 16]
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'{i:04x}  {hex_part:<47}  {ascii_part}')
        self.rep_edit_area.setPlainText('\n'.join(lines))
        self.rep_response_area.clear()
        self.tabWidget.setCurrentIndex(1)   # switch to Repeater tab

    def _repeater_send(self):
        """Parse the hex dump in the Repeater editor and resend as a raw packet."""
        if self.rep_loaded_packet is None:
            QtWidgets.QMessageBox.information(self, "Repeater", "No packet loaded.")
            return
        text = self.rep_edit_area.toPlainText()
        hex_tokens = []
        for line in text.splitlines():
            # Line format: "0000  XX XX ...  ascii" — skip offset (first 6 chars),
            # take up to the double-space before the ascii column.
            if '  ' not in line:
                continue
            # drop the offset prefix
            body = line[6:] if len(line) > 6 else ''
            # hex section ends at the first double-space
            hex_section = body.split('  ')[0].strip()
            hex_tokens.extend(t for t in hex_section.split() if len(t) == 2)
        try:
            raw = bytes(int(h, 16) for h in hex_tokens)
            if self.rep_loaded_packet.haslayer(IP):
                pkt = IP(raw)
            else:
                pkt = Ether(raw)
            send(pkt, verbose=False)
            self.rep_response_area.setPlainText(
                f"[+] Packet sent  ({len(raw)} bytes)\n\n{pkt.summary()}")
        except Exception as exc:
            self.rep_response_area.setPlainText(f"[-] Send failed: {exc}")

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
