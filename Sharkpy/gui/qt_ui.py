# -*- coding: utf-8 -*-

from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1280, 800)

        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        root_layout = QtWidgets.QVBoxLayout(self.centralwidget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ── Tab Widget ────────────────────────────────────────────────────
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setObjectName("tabWidget")
        self.tabWidget.setDocumentMode(True)
        root_layout.addWidget(self.tabWidget)

        # ═══════════════════════════════════════════════════════════════════
        # TAB 1 — CAPTURE  (Wireshark-style packet list)
        # ═══════════════════════════════════════════════════════════════════
        self.tab_capture = QtWidgets.QWidget()
        self.tab_capture.setObjectName("tab_capture")
        cap_layout = QtWidgets.QVBoxLayout(self.tab_capture)
        cap_layout.setContentsMargins(4, 4, 4, 4)
        cap_layout.setSpacing(4)

        # ── Top toolbar: interface + Sniff / Stop + status ───────────────
        toolbar = QtWidgets.QHBoxLayout()
        toolbar.setSpacing(6)

        self.interface_2 = QtWidgets.QComboBox(self.tab_capture)
        self.interface_2.setObjectName("interface_2")
        self.interface_2.setMinimumWidth(160)
        toolbar.addWidget(self.interface_2)

        self.sniffButton = QtWidgets.QPushButton(self.tab_capture)
        self.sniffButton.setObjectName("sniffButton")
        toolbar.addWidget(self.sniffButton)

        self.haltButton = QtWidgets.QPushButton(self.tab_capture)
        self.haltButton.setObjectName("haltButton")
        toolbar.addWidget(self.haltButton)

        # verticalLayout kept so main.py can append mode_combo dynamically
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        toolbar.addLayout(self.verticalLayout)

        toolbar.addStretch()

        self.label = QtWidgets.QLabel(self.tab_capture)
        self.label.setObjectName("label")
        toolbar.addWidget(self.label)

        self.running_info = QtWidgets.QLabel(self.tab_capture)
        self.running_info.setObjectName("running_info")
        self.running_info.setText("")
        toolbar.addWidget(self.running_info)

        cap_layout.addLayout(toolbar)

        # ── Intercept controls ───────────────────────────────────────────
        intercept_bar = QtWidgets.QHBoxLayout()
        intercept_bar.setSpacing(6)

        self.deb_breakButton = QtWidgets.QPushButton(self.tab_capture)
        self.deb_breakButton.setObjectName("deb_breakButton")
        intercept_bar.addWidget(self.deb_breakButton)

        self.deb_nextButton = QtWidgets.QPushButton(self.tab_capture)
        self.deb_nextButton.setObjectName("deb_nextButton")
        self.deb_nextButton.setCheckable(False)
        intercept_bar.addWidget(self.deb_nextButton)

        self.deb_continueButton = QtWidgets.QPushButton(self.tab_capture)
        self.deb_continueButton.setObjectName("deb_continueButton")
        self.deb_continueButton.setCheckable(False)
        intercept_bar.addWidget(self.deb_continueButton)

        self.checkBox = QtWidgets.QCheckBox(self.tab_capture)
        self.checkBox.setObjectName("checkBox")
        intercept_bar.addWidget(self.checkBox)

        intercept_bar.addStretch()

        intercept_bar.addWidget(QtWidgets.QLabel("Process:"))
        self.proc_combo = QtWidgets.QComboBox(self.tab_capture)
        self.proc_combo.setObjectName("proc_combo")
        self.proc_combo.setMinimumWidth(200)
        self.proc_combo.addItem("All traffic")
        intercept_bar.addWidget(self.proc_combo)

        self.proc_refresh_btn = QtWidgets.QPushButton("↺", self.tab_capture)
        self.proc_refresh_btn.setObjectName("proc_refresh_btn")
        self.proc_refresh_btn.setToolTip("Refresh process list")
        self.proc_refresh_btn.setMaximumWidth(30)
        intercept_bar.addWidget(self.proc_refresh_btn)

        cap_layout.addLayout(intercept_bar)

        # ── Filter bar ───────────────────────────────────────────────────
        filter_bar = QtWidgets.QHBoxLayout()
        filter_bar.setSpacing(4)

        self.filterText = QtWidgets.QLineEdit(self.tab_capture)
        self.filterText.setObjectName("filterText")
        filter_bar.addWidget(self.filterText)

        self.filterButton = QtWidgets.QPushButton(self.tab_capture)
        self.filterButton.setObjectName("filterButton")
        filter_bar.addWidget(self.filterButton)

        self.clearButton = QtWidgets.QPushButton(self.tab_capture)
        self.clearButton.setObjectName("clearButton")
        filter_bar.addWidget(self.clearButton)

        cap_layout.addLayout(filter_bar)

        # ── Main splitter — packet table (top) | detail+hex (bottom) ─────
        cap_vsplit = QtWidgets.QSplitter(QtCore.Qt.Vertical, self.tab_capture)

        self.filter_table = QtWidgets.QTableWidget(cap_vsplit)
        self.filter_table.setObjectName("filter_table")
        self.filter_table.setEnabled(True)
        self.filter_table.setMinimumSize(QtCore.QSize(0, 180))
        self.filter_table.setSizeAdjustPolicy(
            QtWidgets.QAbstractScrollArea.AdjustIgnored)
        self.filter_table.setSelectionMode(
            QtWidgets.QAbstractItemView.ExtendedSelection)
        self.filter_table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectRows)
        self.filter_table.setWordWrap(False)
        self.filter_table.setCornerButtonEnabled(True)
        self.filter_table.setColumnCount(6)
        self.filter_table.setRowCount(0)
        for col, title in enumerate(
                ["Time", "Source", "Destination", "Protocol", "Length", "Info"]):
            self.filter_table.setHorizontalHeaderItem(
                col, QtWidgets.QTableWidgetItem(title))
        self.filter_table.horizontalHeader().setCascadingSectionResizes(False)
        self.filter_table.horizontalHeader().setDefaultSectionSize(150)
        self.filter_table.horizontalHeader().setStretchLastSection(True)
        self.filter_table.verticalHeader().setCascadingSectionResizes(True)
        self.filter_table.verticalHeader().setStretchLastSection(False)
        self.filter_table.setSortingEnabled(True)

        # Bottom: detail tree (left) + hex dump (right)
        cap_hsplit = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        self.detail_tree_widget = QtWidgets.QTreeWidget(cap_hsplit)
        self.detail_tree_widget.setObjectName("detail_tree_widget")
        sp = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding,
                                   QtWidgets.QSizePolicy.Expanding)
        self.detail_tree_widget.setSizePolicy(sp)
        self.detail_tree_widget.setColumnCount(1)
        self.detail_tree_widget.headerItem().setText(0, "1")
        self.detail_tree_widget.header().setVisible(False)

        hex_container = QtWidgets.QWidget(cap_hsplit)
        hex_row_layout = QtWidgets.QHBoxLayout(hex_container)
        hex_row_layout.setContentsMargins(0, 0, 0, 0)
        hex_row_layout.setSpacing(0)

        # 34 columns: 0=offset | 1-16=hex bytes | 17=gap | 18-33=ascii chars
        self.hex_table = QtWidgets.QTableWidget(hex_container)
        self.hex_table.setObjectName("hex_table")
        self.hex_table.setColumnCount(34)
        self.hex_table.setRowCount(0)
        self.hex_table.setShowGrid(False)
        self.hex_table.horizontalHeader().setVisible(False)
        self.hex_table.verticalHeader().setVisible(False)
        self.hex_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.hex_table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        self.hex_table.setFont(QtGui.QFont("Monospace", 10))
        self.hex_table.setWordWrap(False)
        hex_row_layout.addWidget(self.hex_table)

        cap_hsplit.addWidget(self.detail_tree_widget)
        cap_hsplit.addWidget(hex_container)
        cap_hsplit.setSizes([420, 580])

        cap_vsplit.addWidget(self.filter_table)
        cap_vsplit.addWidget(cap_hsplit)
        cap_vsplit.setSizes([420, 260])

        # Wrap packets view + WiFi + Bluetooth in inner tabs
        self.cap_inner_tabs = QtWidgets.QTabWidget()
        self.cap_inner_tabs.setObjectName("cap_inner_tabs")
        self.cap_inner_tabs.setDocumentMode(True)
        self.cap_inner_tabs.addTab(cap_vsplit, "Packets")

        # ── 802.11 WiFi sub-tab ───────────────────────────────────────────
        wifi_cap_page = QtWidgets.QWidget()
        wifi_cap_layout = QtWidgets.QVBoxLayout(wifi_cap_page)
        wifi_cap_layout.setContentsMargins(0, 0, 0, 0)
        wifi_cap_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        self.wifi_table = QtWidgets.QTableWidget(0, 8)
        self.wifi_table.setObjectName("wifi_table")
        self.wifi_table.setHorizontalHeaderLabels(
            ["#", "Time", "Type", "Src MAC", "Dst MAC", "BSSID", "SSID", "Signal"])
        self.wifi_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.wifi_table.horizontalHeader().setSectionResizeMode(
            6, QtWidgets.QHeaderView.Stretch)
        self.wifi_table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
        self.wifi_table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.wifi_table.setAlternatingRowColors(True)
        self.wifi_table.verticalHeader().setVisible(False)
        wifi_cap_splitter.addWidget(self.wifi_table)

        self.wifi_detail = QtWidgets.QPlainTextEdit()
        self.wifi_detail.setObjectName("wifi_detail")
        self.wifi_detail.setReadOnly(True)
        self.wifi_detail.setFont(QtGui.QFont("Monospace", 9))
        self.wifi_detail.setPlaceholderText("Select a frame above…")
        wifi_cap_splitter.addWidget(self.wifi_detail)
        wifi_cap_splitter.setSizes([300, 200])
        wifi_cap_layout.addWidget(wifi_cap_splitter)
        self.cap_inner_tabs.addTab(wifi_cap_page, "802.11 WiFi")

        # ── Bluetooth sub-tab ─────────────────────────────────────────────
        bt_cap_page = QtWidgets.QWidget()
        bt_cap_layout = QtWidgets.QVBoxLayout(bt_cap_page)
        bt_cap_layout.setContentsMargins(0, 0, 0, 0)
        bt_cap_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        self.bt_table = QtWidgets.QTableWidget(0, 6)
        self.bt_table.setObjectName("bt_table")
        self.bt_table.setHorizontalHeaderLabels(
            ["#", "Time", "Protocol", "Source", "Destination", "Info"])
        self.bt_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.bt_table.horizontalHeader().setSectionResizeMode(
            5, QtWidgets.QHeaderView.Stretch)
        self.bt_table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
        self.bt_table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.bt_table.setAlternatingRowColors(True)
        self.bt_table.verticalHeader().setVisible(False)
        bt_cap_splitter.addWidget(self.bt_table)

        self.bt_detail = QtWidgets.QPlainTextEdit()
        self.bt_detail.setObjectName("bt_detail")
        self.bt_detail.setReadOnly(True)
        self.bt_detail.setFont(QtGui.QFont("Monospace", 9))
        self.bt_detail.setPlaceholderText("Select an event above…")
        bt_cap_splitter.addWidget(self.bt_detail)
        bt_cap_splitter.setSizes([300, 200])
        bt_cap_layout.addWidget(bt_cap_splitter)
        self.cap_inner_tabs.addTab(bt_cap_page, "Bluetooth")

        cap_layout.addWidget(self.cap_inner_tabs)
        self.tabWidget.addTab(self.tab_capture, "Capture")

        # ═══════════════════════════════════════════════════════════════════
        # TAB 2 — REPEATER  (edit & resend packets, like Burp Repeater)
        # ═══════════════════════════════════════════════════════════════════
        self.tab_repeater = QtWidgets.QWidget()
        self.tab_repeater.setObjectName("tab_repeater")
        rep_layout = QtWidgets.QVBoxLayout(self.tab_repeater)
        rep_layout.setContentsMargins(4, 4, 4, 4)
        rep_layout.setSpacing(4)

        # ── Outer toolbar ─────────────────────────────────────────────────
        rep_toolbar = QtWidgets.QHBoxLayout()
        rep_toolbar.setSpacing(6)

        self.rep_loadButton = QtWidgets.QPushButton("Load Selected Packet")
        self.rep_loadButton.setObjectName("rep_loadButton")
        rep_toolbar.addWidget(self.rep_loadButton)

        self.rep_new_tab_btn = QtWidgets.QPushButton("+  New Tab")
        self.rep_new_tab_btn.setObjectName("rep_new_tab_btn")
        rep_toolbar.addWidget(self.rep_new_tab_btn)

        rep_toolbar.addStretch()

        # Format toggle (Hex / Ascii / Regex — kept from original Replacer)
        self.pushButton_3 = QtWidgets.QPushButton("Hex")
        self.pushButton_3.setObjectName("pushButton_3")
        rep_toolbar.addWidget(self.pushButton_3)

        self.pushButton_2 = QtWidgets.QPushButton("Ascii")
        self.pushButton_2.setObjectName("pushButton_2")
        rep_toolbar.addWidget(self.pushButton_2)

        self.pushButton = QtWidgets.QPushButton("Regex")
        self.pushButton.setObjectName("pushButton")
        rep_toolbar.addWidget(self.pushButton)

        rep_layout.addLayout(rep_toolbar)

        # ── Inner tab widget — sub-tabs are created at runtime by main.py ─
        self.rep_inner_tabs = QtWidgets.QTabWidget()
        self.rep_inner_tabs.setObjectName("rep_inner_tabs")
        self.rep_inner_tabs.setTabsClosable(True)
        self.rep_inner_tabs.setMovable(True)
        rep_layout.addWidget(self.rep_inner_tabs, stretch=1)

        # ── Auto-Replacer section ────────────────────────────────────────
        replacer_group = QtWidgets.QGroupBox("Auto-Replacer")
        replacer_group.setObjectName("replacer_group")
        rg_layout = QtWidgets.QHBoxLayout(replacer_group)

        search_vbox = QtWidgets.QVBoxLayout()
        search_vbox.addWidget(QtWidgets.QLabel("Search"))
        self.textEdit = QtWidgets.QTextEdit()
        self.textEdit.setObjectName("textEdit")
        self.textEdit.setPlaceholderText("Search...")
        self.textEdit.setMaximumHeight(70)
        search_vbox.addWidget(self.textEdit)
        rg_layout.addLayout(search_vbox)

        replace_vbox = QtWidgets.QVBoxLayout()
        replace_vbox.addWidget(QtWidgets.QLabel("Replace"))
        self.textEdit_2 = QtWidgets.QTextEdit()
        self.textEdit_2.setObjectName("textEdit_2")
        self.textEdit_2.setPlaceholderText("Replace")
        self.textEdit_2.setMaximumHeight(70)
        replace_vbox.addWidget(self.textEdit_2)
        rg_layout.addLayout(replace_vbox)

        opt_vbox = QtWidgets.QVBoxLayout()
        self.outputCheckBox_2 = QtWidgets.QCheckBox("Output")
        self.outputCheckBox_2.setObjectName("outputCheckBox_2")
        self.outputCheckBox_2.setChecked(True)
        opt_vbox.addWidget(self.outputCheckBox_2)

        self.InputCheckBox = QtWidgets.QCheckBox("Input")
        self.InputCheckBox.setObjectName("InputCheckBox")
        self.InputCheckBox.setChecked(True)
        opt_vbox.addWidget(self.InputCheckBox)

        self.forwardCheckBox_3 = QtWidgets.QCheckBox("Forward")
        self.forwardCheckBox_3.setObjectName("forwardCheckBox_3")
        opt_vbox.addWidget(self.forwardCheckBox_3)

        self.corruptButton = QtWidgets.QPushButton("Start Replacer")
        self.corruptButton.setObjectName("corruptButton")
        opt_vbox.addWidget(self.corruptButton)

        self.sCorruptButton = QtWidgets.QPushButton("Stop Replacer")
        self.sCorruptButton.setObjectName("sCorruptButton")
        opt_vbox.addWidget(self.sCorruptButton)

        rg_layout.addLayout(opt_vbox)
        rep_layout.addWidget(replacer_group)

        self.tabWidget.addTab(self.tab_repeater, "Repeater")

        # ═══════════════════════════════════════════════════════════════════
        # TAB 3 — SESSIONS  (TCP/UDP stream tracker)
        # ═══════════════════════════════════════════════════════════════════
        self.tab_sessions = QtWidgets.QWidget()
        self.tab_sessions.setObjectName("tab_sessions")
        sess_layout = QtWidgets.QVBoxLayout(self.tab_sessions)
        sess_layout.setContentsMargins(4, 4, 4, 4)
        sess_layout.setSpacing(4)

        # ── Sessions toolbar ─────────────────────────────────────────────
        sess_toolbar = QtWidgets.QHBoxLayout()
        sess_toolbar.setSpacing(6)

        self.refreshSessionsButton = QtWidgets.QPushButton("Refresh Sessions")
        self.refreshSessionsButton.setObjectName("refreshSessionsButton")
        sess_toolbar.addWidget(self.refreshSessionsButton)

        sess_toolbar.addStretch()

        self.sessionsFilterText = QtWidgets.QLineEdit()
        self.sessionsFilterText.setObjectName("sessionsFilterText")
        self.sessionsFilterText.setPlaceholderText("Filter sessions...")
        self.sessionsFilterText.setMaximumWidth(300)
        sess_toolbar.addWidget(self.sessionsFilterText)

        sess_layout.addLayout(sess_toolbar)

        # ── Horizontal splitter: sessions list | stream view ─────────────
        sess_hsplit = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        self.sessions_table = QtWidgets.QTableWidget(sess_hsplit)
        self.sessions_table.setObjectName("sessions_table")
        self.sessions_table.setColumnCount(6)
        self.sessions_table.setRowCount(0)
        self.sessions_table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectRows)
        self.sessions_table.setSortingEnabled(True)
        for col, title in enumerate(
                ["Protocol", "Source", "Destination", "Packets", "Bytes", "Duration"]):
            self.sessions_table.setHorizontalHeaderItem(
                col, QtWidgets.QTableWidgetItem(title))
        self.sessions_table.horizontalHeader().setStretchLastSection(True)
        self.sessions_table.setMinimumWidth(380)

        stream_widget = QtWidgets.QWidget()
        stream_vbox = QtWidgets.QVBoxLayout(stream_widget)
        stream_vbox.setContentsMargins(0, 0, 0, 0)
        stream_vbox.setSpacing(2)

        stream_hdr = QtWidgets.QHBoxLayout()
        stream_hdr.addWidget(QtWidgets.QLabel("Stream"))
        stream_hdr.addStretch()

        self.streamModeCombo = QtWidgets.QComboBox()
        self.streamModeCombo.setObjectName("streamModeCombo")
        self.streamModeCombo.addItems(["Hex + ASCII", "ASCII only", "Raw Hex"])
        stream_hdr.addWidget(self.streamModeCombo)

        self.followStreamButton = QtWidgets.QPushButton("Follow Stream")
        self.followStreamButton.setObjectName("followStreamButton")
        stream_hdr.addWidget(self.followStreamButton)

        stream_vbox.addLayout(stream_hdr)

        self.stream_view = QtWidgets.QTextEdit()
        self.stream_view.setObjectName("stream_view")
        self.stream_view.setReadOnly(True)
        self.stream_view.setFont(QtGui.QFont("Monospace", 10))
        stream_vbox.addWidget(self.stream_view)

        sess_hsplit.addWidget(self.sessions_table)
        sess_hsplit.addWidget(stream_widget)
        sess_hsplit.setSizes([420, 840])

        sess_layout.addWidget(sess_hsplit)
        self.tabWidget.addTab(self.tab_sessions, "Sessions")

        # ═══════════════════════════════════════════════════════════════════
        # TAB 4 — TLS  (certificate authority + transparent TLS interception)
        # ═══════════════════════════════════════════════════════════════════
        self.tab_tls = QtWidgets.QWidget()
        self.tab_tls.setObjectName("tab_tls")
        tls_layout = QtWidgets.QVBoxLayout(self.tab_tls)
        tls_layout.setContentsMargins(4, 4, 4, 4)
        tls_layout.setSpacing(6)

        # ── CA management group ───────────────────────────────────────────
        ca_group = QtWidgets.QGroupBox("Certificate Authority")
        ca_glayout = QtWidgets.QHBoxLayout(ca_group)

        self.tls_gen_ca_btn = QtWidgets.QPushButton("Generate CA")
        self.tls_gen_ca_btn.setObjectName("tls_gen_ca_btn")
        self.tls_gen_ca_btn.setToolTip(
            "Generate a new root CA key + certificate.\n"
            "Only needed once — the CA is saved to ~/.sharkpy/ca/")
        ca_glayout.addWidget(self.tls_gen_ca_btn)

        self.tls_export_ca_btn = QtWidgets.QPushButton("Export CA cert...")
        self.tls_export_ca_btn.setObjectName("tls_export_ca_btn")
        self.tls_export_ca_btn.setToolTip(
            "Save ca.crt to a location of your choice.\n"
            "Install it in your OS / browser trust store so forged certs are accepted.")
        ca_glayout.addWidget(self.tls_export_ca_btn)

        ca_glayout.addStretch()

        self.tls_ca_status = QtWidgets.QLabel("CA: not generated")
        self.tls_ca_status.setObjectName("tls_ca_status")
        ca_glayout.addWidget(self.tls_ca_status)

        tls_layout.addWidget(ca_group)

        # ── TLS proxy controls ────────────────────────────────────────────
        proxy_group = QtWidgets.QGroupBox("TLS Interception  (HTTPS and any TLS port)")
        proxy_glayout = QtWidgets.QHBoxLayout(proxy_group)

        proxy_glayout.addWidget(QtWidgets.QLabel("TLS ports:"))
        self.tls_intercept_port = QtWidgets.QLineEdit("443")
        self.tls_intercept_port.setObjectName("tls_intercept_port")
        self.tls_intercept_port.setMinimumWidth(160)
        self.tls_intercept_port.setPlaceholderText("443, 993, 8443, …")
        self.tls_intercept_port.setToolTip(
            "Comma-separated list of TCP ports to intercept.\n"
            "All listed ports are redirected to the proxy port via iptables.")
        proxy_glayout.addWidget(self.tls_intercept_port)

        proxy_glayout.addWidget(QtWidgets.QLabel("Proxy port:"))
        self.tls_proxy_port = QtWidgets.QLineEdit("8443")
        self.tls_proxy_port.setObjectName("tls_proxy_port")
        self.tls_proxy_port.setMaximumWidth(60)
        proxy_glayout.addWidget(self.tls_proxy_port)

        self.tls_block_quic_cb = QtWidgets.QCheckBox("Block QUIC (force HTTP/2)")
        self.tls_block_quic_cb.setObjectName("tls_block_quic_cb")
        self.tls_block_quic_cb.setToolTip(
            "Drop UDP port 443 traffic to prevent browsers from using QUIC/HTTP3.\n"
            "Browsers automatically fall back to HTTPS over TCP, which SharkPy can intercept.\n"
            "Rule is added on Start and removed on Stop.")
        proxy_glayout.addWidget(self.tls_block_quic_cb)

        self.tls_start_btn = QtWidgets.QPushButton("Start")
        self.tls_start_btn.setObjectName("tls_start_btn")
        proxy_glayout.addWidget(self.tls_start_btn)

        self.tls_stop_btn = QtWidgets.QPushButton("Stop")
        self.tls_stop_btn.setObjectName("tls_stop_btn")
        proxy_glayout.addWidget(self.tls_stop_btn)

        proxy_glayout.addStretch()

        self.tls_proxy_status = QtWidgets.QLabel("Stopped")
        self.tls_proxy_status.setObjectName("tls_proxy_status")
        proxy_glayout.addWidget(self.tls_proxy_status)

        tls_layout.addWidget(proxy_group)

        # ── TCP proxy controls ────────────────────────────────────────────
        tcp_group = QtWidgets.QGroupBox("TCP Interception  (plaintext: HTTP, FTP, Telnet, custom…)")
        tcp_glayout = QtWidgets.QHBoxLayout(tcp_group)

        tcp_glayout.addWidget(QtWidgets.QLabel("TCP ports:"))
        self.tcp_intercept_port = QtWidgets.QLineEdit("80")
        self.tcp_intercept_port.setObjectName("tcp_intercept_port")
        self.tcp_intercept_port.setMinimumWidth(160)
        self.tcp_intercept_port.setPlaceholderText("80, 21, 23, 25, …")
        self.tcp_intercept_port.setToolTip(
            "Comma-separated list of plaintext TCP ports to intercept.\n"
            "Do NOT include TLS ports here — use the TLS section above.")
        tcp_glayout.addWidget(self.tcp_intercept_port)

        tcp_glayout.addWidget(QtWidgets.QLabel("Proxy port:"))
        self.tcp_proxy_port = QtWidgets.QLineEdit("8080")
        self.tcp_proxy_port.setObjectName("tcp_proxy_port")
        self.tcp_proxy_port.setMaximumWidth(60)
        tcp_glayout.addWidget(self.tcp_proxy_port)

        self.tcp_start_btn = QtWidgets.QPushButton("Start")
        self.tcp_start_btn.setObjectName("tcp_start_btn")
        tcp_glayout.addWidget(self.tcp_start_btn)

        self.tcp_stop_btn = QtWidgets.QPushButton("Stop")
        self.tcp_stop_btn.setObjectName("tcp_stop_btn")
        tcp_glayout.addWidget(self.tcp_stop_btn)

        tcp_glayout.addStretch()

        self.tcp_proxy_status = QtWidgets.QLabel("Stopped")
        self.tcp_proxy_status.setObjectName("tcp_proxy_status")
        tcp_glayout.addWidget(self.tcp_proxy_status)

        tls_layout.addWidget(tcp_group)

        # ── Intercepted traffic (table + data viewer) ─────────────────────
        tls_vsplit = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        self.tls_table = QtWidgets.QTableWidget(tls_vsplit)
        self.tls_table.setObjectName("tls_table")
        self.tls_table.setColumnCount(4)
        self.tls_table.setRowCount(0)
        self.tls_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tls_table.setSortingEnabled(True)
        self.tls_table.setMinimumHeight(150)
        for col, title in enumerate(["Hostname", "Direction", "Size (bytes)", "Preview"]):
            self.tls_table.setHorizontalHeaderItem(
                col, QtWidgets.QTableWidgetItem(title))
        self.tls_table.horizontalHeader().setStretchLastSection(True)

        tls_bottom = QtWidgets.QWidget(tls_vsplit)
        tls_bvbox = QtWidgets.QVBoxLayout(tls_bottom)
        tls_bvbox.setContentsMargins(0, 0, 0, 0)
        tls_bvbox.setSpacing(2)

        tls_view_hdr = QtWidgets.QHBoxLayout()
        tls_view_hdr.addWidget(QtWidgets.QLabel("Decrypted Data"))
        tls_view_hdr.addStretch()
        self.tls_view_mode = QtWidgets.QComboBox()
        self.tls_view_mode.setObjectName("tls_view_mode")
        self.tls_view_mode.addItems(["Auto (text / hex)", "Force Text", "Force Hex"])
        tls_view_hdr.addWidget(self.tls_view_mode)
        tls_bvbox.addLayout(tls_view_hdr)

        self.tls_data_view = QtWidgets.QTextEdit()
        self.tls_data_view.setObjectName("tls_data_view")
        self.tls_data_view.setReadOnly(True)
        self.tls_data_view.setFont(QtGui.QFont("Monospace", 10))
        tls_bvbox.addWidget(self.tls_data_view)

        tls_vsplit.addWidget(self.tls_table)
        tls_vsplit.addWidget(tls_bottom)
        tls_vsplit.setSizes([280, 420])

        tls_layout.addWidget(tls_vsplit, stretch=1)
        self.tabWidget.addTab(self.tab_tls, "TLS")

        # ═══════════════════════════════════════════════════════════════════
        # TAB 5 — INTRUDER  (packet fuzzer, like Burp Intruder)
        # ═══════════════════════════════════════════════════════════════════
        self.tab_intruder = QtWidgets.QWidget()
        self.tab_intruder.setObjectName("tab_intruder")
        intr_layout = QtWidgets.QVBoxLayout(self.tab_intruder)
        intr_layout.setContentsMargins(4, 4, 4, 4)
        intr_layout.setSpacing(4)

        # ── Outer toolbar ─────────────────────────────────────────────────
        intr_tb = QtWidgets.QHBoxLayout()
        intr_tb.setSpacing(6)

        self.intr_new_tab_btn = QtWidgets.QPushButton("+  New Tab")
        self.intr_new_tab_btn.setObjectName("intr_new_tab_btn")
        intr_tb.addWidget(self.intr_new_tab_btn)

        sep = QtWidgets.QFrame()
        sep.setFrameShape(QtWidgets.QFrame.VLine)
        intr_tb.addWidget(sep)

        intr_tb.addWidget(QtWidgets.QLabel("Attack:"))
        self.intr_attack_combo = QtWidgets.QComboBox()
        self.intr_attack_combo.setObjectName("intr_attack_combo")
        self.intr_attack_combo.addItems(["Sniper", "Battering Ram", "Cluster Bomb"])
        self.intr_attack_combo.setToolTip(
            "Sniper: one position at a time\n"
            "Battering Ram: same payload in all positions\n"
            "Cluster Bomb: all payload combinations")
        intr_tb.addWidget(self.intr_attack_combo)

        intr_tb.addStretch()

        self.intr_start_btn = QtWidgets.QPushButton("▶  Start Attack")
        self.intr_start_btn.setObjectName("intr_start_btn")
        self.intr_start_btn.setStyleSheet("font-weight: bold;")
        intr_tb.addWidget(self.intr_start_btn)

        self.intr_stop_btn = QtWidgets.QPushButton("■  Stop")
        self.intr_stop_btn.setObjectName("intr_stop_btn")
        self.intr_stop_btn.setEnabled(False)
        intr_tb.addWidget(self.intr_stop_btn)

        self.intr_status_lbl = QtWidgets.QLabel("Ready")
        self.intr_status_lbl.setObjectName("intr_status_lbl")
        self.intr_status_lbl.setStyleSheet("color: #888;")
        intr_tb.addWidget(self.intr_status_lbl)

        intr_layout.addLayout(intr_tb)

        # ── Inner tab widget — sub-tabs are created at runtime by main.py ─
        self.intr_inner_tabs = QtWidgets.QTabWidget()
        self.intr_inner_tabs.setObjectName("intr_inner_tabs")
        self.intr_inner_tabs.setTabsClosable(True)
        self.intr_inner_tabs.setMovable(True)
        intr_layout.addWidget(self.intr_inner_tabs, stretch=1)

        self.tabWidget.addTab(self.tab_intruder, "Intruder")

        # ═══════════════════════════════════════════════════════════════════
        # TAB 6 — INSPECTOR  (Protocol-aware traffic inspector)
        # ═══════════════════════════════════════════════════════════════════
        self.tab_proxy = QtWidgets.QWidget()
        self.tab_proxy.setObjectName("tab_proxy")
        proxy_layout = QtWidgets.QVBoxLayout(self.tab_proxy)
        proxy_layout.setContentsMargins(4, 4, 4, 4)
        proxy_layout.setSpacing(4)

        # ── Top toolbar ──────────────────────────────────────────────────
        proxy_toolbar = QtWidgets.QHBoxLayout()
        proxy_toolbar.setSpacing(6)

        self.proxy_filter_edit = QtWidgets.QLineEdit()
        self.proxy_filter_edit.setObjectName("proxy_filter_edit")
        self.proxy_filter_edit.setPlaceholderText("Search / filter…")
        self.proxy_filter_edit.setMinimumWidth(260)
        proxy_toolbar.addWidget(self.proxy_filter_edit)

        self.proxy_clear_filter_btn = QtWidgets.QPushButton("✕")
        self.proxy_clear_filter_btn.setObjectName("proxy_clear_filter_btn")
        self.proxy_clear_filter_btn.setFixedWidth(28)
        self.proxy_clear_filter_btn.setToolTip("Clear filter")
        proxy_toolbar.addWidget(self.proxy_clear_filter_btn)

        proxy_toolbar.addStretch()

        self.proxy_clear_btn = QtWidgets.QPushButton("Clear All")
        self.proxy_clear_btn.setObjectName("proxy_clear_btn")
        proxy_toolbar.addWidget(self.proxy_clear_btn)

        proxy_layout.addLayout(proxy_toolbar)

        # ── Inner tab widget — one tab per protocol view ─────────────────
        self.insp_tabs = QtWidgets.QTabWidget()
        self.insp_tabs.setObjectName("insp_tabs")
        self.insp_tabs.setDocumentMode(True)

        # ── Tab 0: HTTP ──────────────────────────────────────────────────
        http_page = QtWidgets.QWidget()
        http_layout = QtWidgets.QVBoxLayout(http_page)
        http_layout.setContentsMargins(0, 0, 0, 0)
        http_layout.setSpacing(4)

        http_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        # HTTP history table
        self.http_table = QtWidgets.QTableWidget(0, 7)
        self.http_table.setObjectName("http_table")
        self.http_table.setHorizontalHeaderLabels(
            ["#", "Time", "Method", "Host", "Path", "Status", "Length"])
        self.http_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.http_table.horizontalHeader().setStretchLastSection(False)
        self.http_table.horizontalHeader().setSectionResizeMode(
            4, QtWidgets.QHeaderView.Stretch)
        self.http_table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
        self.http_table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.http_table.setAlternatingRowColors(True)
        self.http_table.verticalHeader().setVisible(False)
        http_splitter.addWidget(self.http_table)

        # HTTP request/response detail area
        http_detail = QtWidgets.QWidget()
        http_detail_layout = QtWidgets.QVBoxLayout(http_detail)
        http_detail_layout.setContentsMargins(0, 0, 0, 0)
        http_detail_layout.setSpacing(2)

        http_req_resp_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        # Request panel
        req_panel = QtWidgets.QWidget()
        req_layout = QtWidgets.QVBoxLayout(req_panel)
        req_layout.setContentsMargins(0, 0, 0, 0)
        req_layout.setSpacing(2)
        req_lbl = QtWidgets.QLabel("Request")
        req_lbl.setStyleSheet("color:#aaa;font-size:11px;font-weight:bold;padding:2px 4px;")
        req_layout.addWidget(req_lbl)
        self.http_req_tabs = QtWidgets.QTabWidget()
        self.http_req_tabs.setObjectName("http_req_tabs")
        self.http_req_raw = QtWidgets.QPlainTextEdit()
        self.http_req_raw.setObjectName("http_req_raw")
        self.http_req_raw.setReadOnly(True)
        self.http_req_raw.setFont(QtGui.QFont("Monospace", 9))
        self.http_req_headers = QtWidgets.QTableWidget(0, 2)
        self.http_req_headers.setObjectName("http_req_headers")
        self.http_req_headers.setHorizontalHeaderLabels(["Header", "Value"])
        self.http_req_headers.horizontalHeader().setStretchLastSection(True)
        self.http_req_headers.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.http_req_headers.verticalHeader().setVisible(False)
        self.http_req_body = QtWidgets.QPlainTextEdit()
        self.http_req_body.setObjectName("http_req_body")
        self.http_req_body.setReadOnly(True)
        self.http_req_body.setFont(QtGui.QFont("Monospace", 9))
        self.http_req_tabs.addTab(self.http_req_raw, "Raw")
        self.http_req_tabs.addTab(self.http_req_headers, "Headers")
        self.http_req_tabs.addTab(self.http_req_body, "Body")
        req_layout.addWidget(self.http_req_tabs)
        http_req_resp_splitter.addWidget(req_panel)

        # Response panel
        resp_panel = QtWidgets.QWidget()
        resp_layout = QtWidgets.QVBoxLayout(resp_panel)
        resp_layout.setContentsMargins(0, 0, 0, 0)
        resp_layout.setSpacing(2)
        resp_lbl = QtWidgets.QLabel("Response")
        resp_lbl.setStyleSheet("color:#aaa;font-size:11px;font-weight:bold;padding:2px 4px;")
        resp_layout.addWidget(resp_lbl)
        self.http_resp_tabs = QtWidgets.QTabWidget()
        self.http_resp_tabs.setObjectName("http_resp_tabs")
        self.http_resp_raw = QtWidgets.QPlainTextEdit()
        self.http_resp_raw.setObjectName("http_resp_raw")
        self.http_resp_raw.setReadOnly(True)
        self.http_resp_raw.setFont(QtGui.QFont("Monospace", 9))
        self.http_resp_headers = QtWidgets.QTableWidget(0, 2)
        self.http_resp_headers.setObjectName("http_resp_headers")
        self.http_resp_headers.setHorizontalHeaderLabels(["Header", "Value"])
        self.http_resp_headers.horizontalHeader().setStretchLastSection(True)
        self.http_resp_headers.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.http_resp_headers.verticalHeader().setVisible(False)
        self.http_resp_body = QtWidgets.QPlainTextEdit()
        self.http_resp_body.setObjectName("http_resp_body")
        self.http_resp_body.setReadOnly(True)
        self.http_resp_body.setFont(QtGui.QFont("Monospace", 9))
        self.http_resp_tabs.addTab(self.http_resp_raw, "Raw")
        self.http_resp_tabs.addTab(self.http_resp_headers, "Headers")
        self.http_resp_tabs.addTab(self.http_resp_body, "Body")
        resp_layout.addWidget(self.http_resp_tabs)
        http_req_resp_splitter.addWidget(resp_panel)

        http_req_resp_splitter.setSizes([480, 480])
        http_detail_layout.addWidget(http_req_resp_splitter)
        http_splitter.addWidget(http_detail)
        http_splitter.setSizes([280, 320])
        http_layout.addWidget(http_splitter)
        self.insp_tabs.addTab(http_page, "HTTP")

        # ── Tab 1: DNS ───────────────────────────────────────────────────
        dns_page = QtWidgets.QWidget()
        dns_layout = QtWidgets.QVBoxLayout(dns_page)
        dns_layout.setContentsMargins(0, 0, 0, 0)
        dns_layout.setSpacing(4)

        dns_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        self.dns_table = QtWidgets.QTableWidget(0, 7)
        self.dns_table.setObjectName("dns_table")
        self.dns_table.setHorizontalHeaderLabels(
            ["#", "Time", "Type", "Name", "Response", "TTL", "Server"])
        self.dns_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.dns_table.horizontalHeader().setSectionResizeMode(
            4, QtWidgets.QHeaderView.Stretch)
        self.dns_table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
        self.dns_table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.dns_table.setAlternatingRowColors(True)
        self.dns_table.verticalHeader().setVisible(False)
        dns_splitter.addWidget(self.dns_table)

        self.dns_detail = QtWidgets.QPlainTextEdit()
        self.dns_detail.setObjectName("dns_detail")
        self.dns_detail.setReadOnly(True)
        self.dns_detail.setFont(QtGui.QFont("Monospace", 9))
        self.dns_detail.setPlaceholderText("Select a DNS record to see full detail…")
        dns_splitter.addWidget(self.dns_detail)
        dns_splitter.setSizes([360, 200])
        dns_layout.addWidget(dns_splitter)
        self.insp_tabs.addTab(dns_page, "DNS")

        # ── Tab 2: Streams (conversations) ───────────────────────────────
        conv_page = QtWidgets.QWidget()
        conv_layout = QtWidgets.QVBoxLayout(conv_page)
        conv_layout.setContentsMargins(0, 0, 0, 0)
        conv_layout.setSpacing(4)

        conv_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        self.conv_table = QtWidgets.QTableWidget(0, 7)
        self.conv_table.setObjectName("conv_table")
        self.conv_table.setHorizontalHeaderLabels(
            ["#", "Proto", "Client", "Server", "Pkts", "Bytes", "Start Time"])
        self.conv_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.conv_table.horizontalHeader().setSectionResizeMode(
            2, QtWidgets.QHeaderView.Stretch)
        self.conv_table.horizontalHeader().setSectionResizeMode(
            3, QtWidgets.QHeaderView.Stretch)
        self.conv_table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
        self.conv_table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.conv_table.setAlternatingRowColors(True)
        self.conv_table.verticalHeader().setVisible(False)
        conv_splitter.addWidget(self.conv_table)

        # Stream view: tabs for Text / Hex / A→B / B→A
        self.conv_stream_tabs = QtWidgets.QTabWidget()
        self.conv_stream_tabs.setObjectName("conv_stream_tabs")
        self.conv_stream_text = QtWidgets.QPlainTextEdit()
        self.conv_stream_text.setObjectName("conv_stream_text")
        self.conv_stream_text.setReadOnly(True)
        self.conv_stream_text.setFont(QtGui.QFont("Monospace", 9))
        self.conv_stream_hex = QtWidgets.QPlainTextEdit()
        self.conv_stream_hex.setObjectName("conv_stream_hex")
        self.conv_stream_hex.setReadOnly(True)
        self.conv_stream_hex.setFont(QtGui.QFont("Monospace", 9))
        self.conv_stream_atob = QtWidgets.QPlainTextEdit()
        self.conv_stream_atob.setObjectName("conv_stream_atob")
        self.conv_stream_atob.setReadOnly(True)
        self.conv_stream_atob.setFont(QtGui.QFont("Monospace", 9))
        self.conv_stream_btoa = QtWidgets.QPlainTextEdit()
        self.conv_stream_btoa.setObjectName("conv_stream_btoa")
        self.conv_stream_btoa.setReadOnly(True)
        self.conv_stream_btoa.setFont(QtGui.QFont("Monospace", 9))
        self.conv_stream_tabs.addTab(self.conv_stream_text, "Text")
        self.conv_stream_tabs.addTab(self.conv_stream_hex, "Hex")
        self.conv_stream_tabs.addTab(self.conv_stream_atob, "Client → Server")
        self.conv_stream_tabs.addTab(self.conv_stream_btoa, "Server → Client")
        conv_splitter.addWidget(self.conv_stream_tabs)
        conv_splitter.setSizes([300, 260])
        conv_layout.addWidget(conv_splitter)
        self.insp_tabs.addTab(conv_page, "Streams")

        # ── Tab 3: TLS Handshakes ────────────────────────────────────────
        tls_hs_page = QtWidgets.QWidget()
        tls_hs_layout = QtWidgets.QVBoxLayout(tls_hs_page)
        tls_hs_layout.setContentsMargins(0, 0, 0, 0)
        tls_hs_layout.setSpacing(4)

        tls_hs_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        self.tls_hs_table = QtWidgets.QTableWidget(0, 8)
        self.tls_hs_table.setObjectName("tls_hs_table")
        self.tls_hs_table.setHorizontalHeaderLabels(
            ["#", "Time", "Client", "Server", "SNI", "Version", "Cipher Suite", "Cert CN"])
        self.tls_hs_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.tls_hs_table.horizontalHeader().setSectionResizeMode(
            4, QtWidgets.QHeaderView.Stretch)
        self.tls_hs_table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
        self.tls_hs_table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.tls_hs_table.setAlternatingRowColors(True)
        self.tls_hs_table.verticalHeader().setVisible(False)
        tls_hs_splitter.addWidget(self.tls_hs_table)

        tls_hs_detail_widget = QtWidgets.QWidget()
        tls_hs_detail_layout = QtWidgets.QVBoxLayout(tls_hs_detail_widget)
        tls_hs_detail_layout.setContentsMargins(0, 0, 0, 0)
        tls_hs_detail_layout.setSpacing(2)

        tls_hs_detail_hdr = QtWidgets.QHBoxLayout()
        tls_hs_detail_hdr.addWidget(QtWidgets.QLabel("Handshake Detail"))
        tls_hs_detail_hdr.addStretch()
        tls_hs_detail_layout.addLayout(tls_hs_detail_hdr)

        self.tls_hs_detail = QtWidgets.QPlainTextEdit()
        self.tls_hs_detail.setObjectName("tls_hs_detail")
        self.tls_hs_detail.setReadOnly(True)
        self.tls_hs_detail.setFont(QtGui.QFont("Monospace", 9))
        self.tls_hs_detail.setPlaceholderText(
            "Select a handshake above to see full details…\n\n"
            "Captures TLS ClientHello / ServerHello from passive traffic.\n"
            "SNI (Server Name Indication) reveals which hostname was requested.\n"
            "No decryption key needed — this is metadata only.")
        tls_hs_detail_layout.addWidget(self.tls_hs_detail)

        tls_hs_splitter.addWidget(tls_hs_detail_widget)
        tls_hs_splitter.setSizes([320, 240])
        tls_hs_layout.addWidget(tls_hs_splitter)
        self.insp_tabs.addTab(tls_hs_page, "TLS Handshakes")

        # ── Tab 4: Credentials ───────────────────────────────────────────
        creds_page = QtWidgets.QWidget()
        creds_layout = QtWidgets.QVBoxLayout(creds_page)
        creds_layout.setContentsMargins(0, 0, 0, 0)
        creds_layout.setSpacing(4)

        creds_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        self.creds_table = QtWidgets.QTableWidget(0, 7)
        self.creds_table.setObjectName("creds_table")
        self.creds_table.setHorizontalHeaderLabels(
            ["#", "Time", "Protocol", "Source", "Destination", "Username", "Secret"])
        self.creds_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.creds_table.horizontalHeader().setSectionResizeMode(
            5, QtWidgets.QHeaderView.Stretch)
        self.creds_table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
        self.creds_table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.creds_table.setAlternatingRowColors(True)
        self.creds_table.verticalHeader().setVisible(False)
        creds_splitter.addWidget(self.creds_table)

        creds_detail_widget = QtWidgets.QWidget()
        creds_detail_layout = QtWidgets.QVBoxLayout(creds_detail_widget)
        creds_detail_layout.setContentsMargins(0, 0, 0, 0)
        creds_detail_layout.setSpacing(2)

        creds_detail_hdr = QtWidgets.QHBoxLayout()
        creds_detail_hdr.addWidget(QtWidgets.QLabel("Credential Detail"))
        creds_detail_hdr.addStretch()
        self.creds_copy_btn = QtWidgets.QPushButton("Copy")
        self.creds_copy_btn.setObjectName("creds_copy_btn")
        self.creds_copy_btn.setFixedWidth(60)
        creds_detail_hdr.addWidget(self.creds_copy_btn)
        creds_detail_layout.addLayout(creds_detail_hdr)

        self.creds_detail = QtWidgets.QPlainTextEdit()
        self.creds_detail.setObjectName("creds_detail")
        self.creds_detail.setReadOnly(True)
        self.creds_detail.setFont(QtGui.QFont("Monospace", 9))
        self.creds_detail.setPlaceholderText(
            "Credentials found in captured traffic will appear here.\n\n"
            "Detected automatically from:\n"
            "  \u2022 HTTP Basic Auth  (Authorization: Basic \u2026)\n"
            "  \u2022 HTTP Digest Auth  (Authorization: Digest \u2026)\n"
            "  \u2022 FTP  (USER / PASS commands)\n"
            "  \u2022 Telnet  (cleartext login sequences)\n"
            "  \u2022 SMB NTLM  (NTLMv1/v2 challenge-response hashes)\n"
            "  \u2022 MySQL  (login username from auth handshake)\n"
            "  \u2022 PostgreSQL  (username + database from startup message)\n"
            "  \u2022 MSSQL  (username from TDS7 Login packet)")
        creds_detail_layout.addWidget(self.creds_detail)

        creds_splitter.addWidget(creds_detail_widget)
        creds_splitter.setSizes([280, 280])
        creds_layout.addWidget(creds_splitter)
        self.insp_tabs.addTab(creds_page, "Credentials")

        # ── Tab 5: Telnet / FTP ──────────────────────────────────────────
        telnet_page = QtWidgets.QWidget()
        telnet_layout = QtWidgets.QVBoxLayout(telnet_page)
        telnet_layout.setContentsMargins(0, 0, 0, 0)
        telnet_layout.setSpacing(4)

        telnet_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        self.telnet_table = QtWidgets.QTableWidget(0, 6)
        self.telnet_table.setObjectName("telnet_table")
        self.telnet_table.setHorizontalHeaderLabels(
            ["#", "Time", "Client", "Server", "Bytes", "Packets"])
        self.telnet_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.telnet_table.horizontalHeader().setSectionResizeMode(
            2, QtWidgets.QHeaderView.Stretch)
        self.telnet_table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
        self.telnet_table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.telnet_table.setAlternatingRowColors(True)
        self.telnet_table.verticalHeader().setVisible(False)
        telnet_splitter.addWidget(self.telnet_table)

        telnet_detail = QtWidgets.QWidget()
        telnet_detail_layout = QtWidgets.QVBoxLayout(telnet_detail)
        telnet_detail_layout.setContentsMargins(0, 0, 0, 0)
        telnet_detail_layout.setSpacing(2)

        self.telnet_session_tabs = QtWidgets.QTabWidget()
        self.telnet_session_tabs.setObjectName("telnet_session_tabs")

        self.telnet_combined = QtWidgets.QPlainTextEdit()
        self.telnet_combined.setObjectName("telnet_combined")
        self.telnet_combined.setReadOnly(True)
        self.telnet_combined.setFont(QtGui.QFont("Monospace", 9))
        self.telnet_combined.setPlaceholderText("Select a session above…")

        self.telnet_client_view = QtWidgets.QPlainTextEdit()
        self.telnet_client_view.setObjectName("telnet_client_view")
        self.telnet_client_view.setReadOnly(True)
        self.telnet_client_view.setFont(QtGui.QFont("Monospace", 9))

        self.telnet_server_view = QtWidgets.QPlainTextEdit()
        self.telnet_server_view.setObjectName("telnet_server_view")
        self.telnet_server_view.setReadOnly(True)
        self.telnet_server_view.setFont(QtGui.QFont("Monospace", 9))

        self.telnet_raw_view = QtWidgets.QPlainTextEdit()
        self.telnet_raw_view.setObjectName("telnet_raw_view")
        self.telnet_raw_view.setReadOnly(True)
        self.telnet_raw_view.setFont(QtGui.QFont("Monospace", 9))

        self.telnet_session_tabs.addTab(self.telnet_combined, "Session")
        self.telnet_session_tabs.addTab(self.telnet_client_view, "Client → Server")
        self.telnet_session_tabs.addTab(self.telnet_server_view, "Server → Client")
        self.telnet_session_tabs.addTab(self.telnet_raw_view, "Raw (hex)")
        telnet_detail_layout.addWidget(self.telnet_session_tabs)
        telnet_splitter.addWidget(telnet_detail)
        telnet_splitter.setSizes([220, 320])
        telnet_layout.addWidget(telnet_splitter)
        self.insp_tabs.addTab(telnet_page, "Telnet / FTP")

        # ── Tab 6: SMB ───────────────────────────────────────────────────
        smb_page = QtWidgets.QWidget()
        smb_layout = QtWidgets.QVBoxLayout(smb_page)
        smb_layout.setContentsMargins(0, 0, 0, 0)
        smb_layout.setSpacing(4)

        smb_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        self.smb_table = QtWidgets.QTableWidget(0, 8)
        self.smb_table.setObjectName("smb_table")
        self.smb_table.setHorizontalHeaderLabels(
            ["#", "Time", "Client", "Server", "Command", "Status", "File/Share", "User"])
        self.smb_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.smb_table.horizontalHeader().setSectionResizeMode(
            6, QtWidgets.QHeaderView.Stretch)
        self.smb_table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
        self.smb_table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.smb_table.setAlternatingRowColors(True)
        self.smb_table.verticalHeader().setVisible(False)
        smb_splitter.addWidget(self.smb_table)

        smb_detail_widget = QtWidgets.QWidget()
        smb_detail_layout = QtWidgets.QVBoxLayout(smb_detail_widget)
        smb_detail_layout.setContentsMargins(0, 0, 0, 0)
        smb_detail_layout.setSpacing(2)

        smb_detail_hdr = QtWidgets.QHBoxLayout()
        smb_detail_hdr.addWidget(QtWidgets.QLabel("SMB Detail"))
        smb_detail_hdr.addStretch()
        smb_detail_layout.addLayout(smb_detail_hdr)

        self.smb_detail = QtWidgets.QPlainTextEdit()
        self.smb_detail.setObjectName("smb_detail")
        self.smb_detail.setReadOnly(True)
        self.smb_detail.setFont(QtGui.QFont("Monospace", 9))
        self.smb_detail.setPlaceholderText(
            "Select an SMB operation above to see detail…\n\n"
            "Captures SMB2 traffic on port 445:\n"
            "  • NEGOTIATE / SESSION_SETUP (NTLM auth)\n"
            "  • TREE_CONNECT / TREE_DISCONNECT (share access)\n"
            "  • CREATE / CLOSE / READ / WRITE (file operations)\n"
            "  • IOCTL / QUERY_INFO\n\n"
            "NTLM hashes are automatically forwarded to the Credentials tab.")
        smb_detail_layout.addWidget(self.smb_detail)

        smb_splitter.addWidget(smb_detail_widget)
        smb_splitter.setSizes([320, 240])
        smb_layout.addWidget(smb_splitter)
        self.insp_tabs.addTab(smb_page, "SMB")

        # ── Tab 7: SQL ───────────────────────────────────────────────────
        sql_page = QtWidgets.QWidget()
        sql_layout = QtWidgets.QVBoxLayout(sql_page)
        sql_layout.setContentsMargins(0, 0, 0, 0)
        sql_layout.setSpacing(4)

        sql_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        self.sql_table = QtWidgets.QTableWidget(0, 7)
        self.sql_table.setObjectName("sql_table")
        self.sql_table.setHorizontalHeaderLabels(
            ["#", "Time", "Client", "Server", "Protocol", "Command", "Query"])
        self.sql_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.sql_table.horizontalHeader().setSectionResizeMode(
            6, QtWidgets.QHeaderView.Stretch)
        self.sql_table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
        self.sql_table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.sql_table.setAlternatingRowColors(True)
        self.sql_table.verticalHeader().setVisible(False)
        sql_splitter.addWidget(self.sql_table)

        sql_detail_widget = QtWidgets.QWidget()
        sql_detail_layout = QtWidgets.QVBoxLayout(sql_detail_widget)
        sql_detail_layout.setContentsMargins(0, 0, 0, 0)
        sql_detail_layout.setSpacing(2)

        sql_detail_hdr = QtWidgets.QHBoxLayout()
        sql_detail_hdr.addWidget(QtWidgets.QLabel("Query Detail"))
        sql_detail_hdr.addStretch()
        self.sql_copy_btn = QtWidgets.QPushButton("Copy")
        self.sql_copy_btn.setObjectName("sql_copy_btn")
        self.sql_copy_btn.setFixedWidth(60)
        sql_detail_hdr.addWidget(self.sql_copy_btn)
        sql_detail_layout.addLayout(sql_detail_hdr)

        self.sql_detail = QtWidgets.QPlainTextEdit()
        self.sql_detail.setObjectName("sql_detail")
        self.sql_detail.setReadOnly(True)
        self.sql_detail.setFont(QtGui.QFont("Monospace", 9))
        self.sql_detail.setPlaceholderText(
            "SQL queries captured from unencrypted traffic will appear here.\n\n"
            "Detected automatically from:\n"
            "  \u2022 MySQL  (port 3306) \u2014 COM_QUERY, COM_INIT_DB, COM_STMT_PREPARE\n"
            "  \u2022 PostgreSQL  (port 5432) \u2014 Simple Query, Parse (prepared statements)\n"
            "  \u2022 MSSQL  (port 1433) \u2014 SQL Batch, RPC Request (TDS protocol)\n\n"
            "Credentials (usernames, auth) are forwarded to the Credentials tab.")
        sql_detail_layout.addWidget(self.sql_detail)

        sql_splitter.addWidget(sql_detail_widget)
        sql_splitter.setSizes([300, 260])
        sql_layout.addWidget(sql_splitter)
        self.insp_tabs.addTab(sql_page, "SQL")

        proxy_layout.addWidget(self.insp_tabs, stretch=1)
        self.tabWidget.addTab(self.tab_proxy, "Inspector")

        # ═══════════════════════════════════════════════════════════════════
        # TAB 7 — CRYPTO  (Encode / Decode / Encrypt / Decrypt / Hash)
        # ═══════════════════════════════════════════════════════════════════
        self.tab_crypto = QtWidgets.QWidget()
        self.tab_crypto.setObjectName("tab_crypto")
        crypto_layout = QtWidgets.QVBoxLayout(self.tab_crypto)
        crypto_layout.setContentsMargins(4, 4, 4, 4)
        crypto_layout.setSpacing(4)

        # ── Toolbar ───────────────────────────────────────────────────────
        crypto_tb = QtWidgets.QHBoxLayout()
        crypto_tb.setSpacing(6)
        self.crypto_load_capture_btn = QtWidgets.QPushButton("Load from Capture")
        self.crypto_load_capture_btn.setObjectName("crypto_load_capture_btn")
        crypto_tb.addWidget(self.crypto_load_capture_btn)
        self.crypto_load_rep_btn = QtWidgets.QPushButton("Load from Repeater")
        self.crypto_load_rep_btn.setObjectName("crypto_load_rep_btn")
        crypto_tb.addWidget(self.crypto_load_rep_btn)
        crypto_tb.addStretch()
        self.crypto_clear_btn = QtWidgets.QPushButton("Clear")
        self.crypto_clear_btn.setObjectName("crypto_clear_btn")
        crypto_tb.addWidget(self.crypto_clear_btn)
        crypto_layout.addLayout(crypto_tb)

        # ── Vertical splitter: input | controls | output ──────────────────
        crypto_vsplit = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        # Input
        input_group = QtWidgets.QGroupBox("Input")
        input_gl = QtWidgets.QVBoxLayout(input_group)
        input_fmt_bar = QtWidgets.QHBoxLayout()
        input_fmt_bar.addWidget(QtWidgets.QLabel("Format:"))
        self.crypto_input_fmt = QtWidgets.QComboBox()
        self.crypto_input_fmt.setObjectName("crypto_input_fmt")
        self.crypto_input_fmt.addItems(["Text", "Hex", "Base64"])
        input_fmt_bar.addWidget(self.crypto_input_fmt)
        input_fmt_bar.addStretch()
        input_gl.addLayout(input_fmt_bar)
        self.crypto_input = QtWidgets.QTextEdit()
        self.crypto_input.setObjectName("crypto_input")
        self.crypto_input.setFont(QtGui.QFont("Monospace", 10))
        self.crypto_input.setPlaceholderText(
            "Paste or load input here…\n"
            "Hex format: de ad be ef 00 …\n"
            "Text format: any string\n"
            "Base64 format: dGVzdA==")
        input_gl.addWidget(self.crypto_input)
        crypto_vsplit.addWidget(input_group)

        # Controls
        ctrl_group = QtWidgets.QGroupBox("Operation")
        ctrl_gl = QtWidgets.QGridLayout(ctrl_group)
        ctrl_gl.setSpacing(6)

        ctrl_gl.addWidget(QtWidgets.QLabel("Algorithm:"), 0, 0)
        self.crypto_algo = QtWidgets.QComboBox()
        self.crypto_algo.setObjectName("crypto_algo")
        _ALGOS = [
            ("── Encoding ──", True),
            ("Base64", False), ("Hex", False), ("URL", False),
            ("── Hashing ──", True),
            ("MD5", False), ("SHA-1", False), ("SHA-256", False),
            ("SHA-512", False), ("SHA3-256", False),
            ("HMAC-SHA256", False), ("HMAC-SHA512", False),
            ("── Symmetric ──", True),
            ("XOR", False), ("RC4", False),
            ("AES-128-CBC", False), ("AES-256-CBC", False),
            ("AES-128-ECB", False), ("AES-256-ECB", False),
            ("AES-128-CTR", False), ("AES-256-CTR", False),
            ("AES-128-GCM", False), ("AES-256-GCM", False),
            ("3DES-CBC", False), ("ChaCha20-Poly1305", False),
        ]
        for label, is_sep in _ALGOS:
            self.crypto_algo.addItem(label)
            if is_sep:
                idx = self.crypto_algo.count() - 1
                item = self.crypto_algo.model().item(idx)
                item.setEnabled(False)
                item.setForeground(QtGui.QColor(0x80, 0x80, 0x80))
        ctrl_gl.addWidget(self.crypto_algo, 0, 1, 1, 3)

        ctrl_gl.addWidget(QtWidgets.QLabel("Key (hex):"), 1, 0)
        self.crypto_key = QtWidgets.QLineEdit()
        self.crypto_key.setObjectName("crypto_key")
        self.crypto_key.setFont(QtGui.QFont("Monospace", 10))
        self.crypto_key.setPlaceholderText(
            "Hex bytes, e.g. 0011223344556677…  (not needed for Encoding / Hashing)")
        ctrl_gl.addWidget(self.crypto_key, 1, 1, 1, 3)

        ctrl_gl.addWidget(QtWidgets.QLabel("IV / Nonce (hex):"), 2, 0)
        self.crypto_iv = QtWidgets.QLineEdit()
        self.crypto_iv.setObjectName("crypto_iv")
        self.crypto_iv.setFont(QtGui.QFont("Monospace", 10))
        self.crypto_iv.setPlaceholderText(
            "16-byte IV for CBC/CTR, 12-byte nonce for GCM, 8-byte IV for 3DES")
        ctrl_gl.addWidget(self.crypto_iv, 2, 1, 1, 3)

        self.crypto_fwd_btn = QtWidgets.QPushButton("Encrypt / Encode / Hash  ▶")
        self.crypto_fwd_btn.setObjectName("crypto_fwd_btn")
        self.crypto_fwd_btn.setStyleSheet("font-weight: bold;")
        ctrl_gl.addWidget(self.crypto_fwd_btn, 3, 0, 1, 2)

        self.crypto_rev_btn = QtWidgets.QPushButton("◀  Decrypt / Decode")
        self.crypto_rev_btn.setObjectName("crypto_rev_btn")
        ctrl_gl.addWidget(self.crypto_rev_btn, 3, 2, 1, 2)

        self.crypto_status = QtWidgets.QLabel("")
        self.crypto_status.setObjectName("crypto_status")
        self.crypto_status.setStyleSheet("color: #888; font-style: italic;")
        ctrl_gl.addWidget(self.crypto_status, 4, 0, 1, 4)

        crypto_vsplit.addWidget(ctrl_group)

        # Output
        output_group = QtWidgets.QGroupBox("Output")
        output_gl = QtWidgets.QVBoxLayout(output_group)
        output_fmt_bar = QtWidgets.QHBoxLayout()
        output_fmt_bar.addWidget(QtWidgets.QLabel("Format:"))
        self.crypto_output_fmt = QtWidgets.QComboBox()
        self.crypto_output_fmt.setObjectName("crypto_output_fmt")
        self.crypto_output_fmt.addItems(["Text", "Hex", "Base64"])
        self.crypto_output_fmt.setCurrentIndex(1)   # default to Hex
        output_fmt_bar.addWidget(self.crypto_output_fmt)
        output_fmt_bar.addStretch()
        self.crypto_send_rep_btn = QtWidgets.QPushButton("Send to Repeater")
        self.crypto_send_rep_btn.setObjectName("crypto_send_rep_btn")
        output_fmt_bar.addWidget(self.crypto_send_rep_btn)
        self.crypto_copy_btn = QtWidgets.QPushButton("Copy")
        self.crypto_copy_btn.setObjectName("crypto_copy_btn")
        output_fmt_bar.addWidget(self.crypto_copy_btn)
        output_gl.addLayout(output_fmt_bar)
        self.crypto_output = QtWidgets.QTextEdit()
        self.crypto_output.setObjectName("crypto_output")
        self.crypto_output.setReadOnly(True)
        self.crypto_output.setFont(QtGui.QFont("Monospace", 10))
        output_gl.addWidget(self.crypto_output)
        crypto_vsplit.addWidget(output_group)

        crypto_vsplit.setSizes([240, 210, 240])
        crypto_layout.addWidget(crypto_vsplit, stretch=1)
        self.tabWidget.addTab(self.tab_crypto, "Crypto")

        # ── Attack tab ────────────────────────────────────────────────────
        self.tab_attack = QtWidgets.QWidget()
        self.tab_attack.setObjectName("tab_attack")
        atk_layout = QtWidgets.QVBoxLayout(self.tab_attack)
        atk_layout.setContentsMargins(4, 4, 4, 4)

        # Outer category tabs
        self.attack_tabs = QtWidgets.QTabWidget()
        self.attack_tabs.setObjectName("attack_tabs")
        atk_layout.addWidget(self.attack_tabs)

        # Inner tab widgets per category
        def _atk_category(name, label):
            page = QtWidgets.QWidget()
            inner = QtWidgets.QTabWidget()
            inner.setObjectName(f"atk_{name}_tabs")
            QtWidgets.QVBoxLayout(page).addWidget(inner)
            self.attack_tabs.addTab(page, label)
            return inner

        self.atk_net_tabs  = _atk_category("net",  "Network")
        self.atk_wifi_tabs = _atk_category("wifi", "WiFi")
        self.atk_bt_tabs   = _atk_category("bt",   "Bluetooth")

        # ── Attack sub-tab helper ─────────────────────────────────────────
        def _atk_log(name):
            """Return a read-only QPlainTextEdit log widget."""
            w = QtWidgets.QPlainTextEdit()
            w.setObjectName(f"atk_log_{name}")
            w.setReadOnly(True)
            w.setFont(QtGui.QFont("Monospace", 9))
            w.setMaximumBlockCount(1000)
            return w

        def _atk_start_stop(name):
            """Return (start_btn, stop_btn) pair."""
            start = QtWidgets.QPushButton("▶  Start")
            start.setObjectName(f"atk_start_{name}")
            stop  = QtWidgets.QPushButton("■  Stop")
            stop.setObjectName(f"atk_stop_{name}")
            stop.setEnabled(False)
            return start, stop

        def _iface_combo(name):
            w = QtWidgets.QComboBox()
            w.setObjectName(f"atk_iface_{name}")
            return w

        # ── Sub-tab 1: ARP Spoof ──────────────────────────────────────────
        w_arp = QtWidgets.QWidget()
        arp_layout = QtWidgets.QVBoxLayout(w_arp)

        arp_cfg = QtWidgets.QGroupBox("Configuration")
        arp_form = QtWidgets.QFormLayout(arp_cfg)

        self.atk_arp_target = QtWidgets.QLineEdit()
        self.atk_arp_target.setPlaceholderText("e.g. 192.168.1.100")
        arp_form.addRow("Target IP:", self.atk_arp_target)

        self.atk_arp_gateway = QtWidgets.QLineEdit()
        self.atk_arp_gateway.setPlaceholderText("e.g. 192.168.1.1")
        arp_form.addRow("Gateway IP:", self.atk_arp_gateway)

        self.atk_arp_iface = _iface_combo("arp")
        arp_form.addRow("Interface:", self.atk_arp_iface)

        self.atk_arp_ipfwd = QtWidgets.QCheckBox("Enable IP forwarding (MitM)")
        self.atk_arp_ipfwd.setChecked(True)
        arp_form.addRow("", self.atk_arp_ipfwd)

        arp_layout.addWidget(arp_cfg)

        arp_btn_row = QtWidgets.QHBoxLayout()
        self.atk_arp_start, self.atk_arp_stop = _atk_start_stop("arp")
        arp_btn_row.addWidget(self.atk_arp_start)
        arp_btn_row.addWidget(self.atk_arp_stop)
        arp_btn_row.addStretch()
        arp_layout.addLayout(arp_btn_row)

        arp_log_grp = QtWidgets.QGroupBox("Log")
        QtWidgets.QVBoxLayout(arp_log_grp).addWidget(_atk_log("arp"))
        self.atk_log_arp = arp_log_grp.findChild(QtWidgets.QPlainTextEdit)
        arp_layout.addWidget(arp_log_grp, stretch=1)

        self.atk_net_tabs.addTab(w_arp, "ARP Spoof")

        # ── Sub-tab 2: DNS Spoof ──────────────────────────────────────────
        w_dns = QtWidgets.QWidget()
        dns_layout = QtWidgets.QVBoxLayout(w_dns)

        dns_cfg = QtWidgets.QGroupBox("Configuration")
        dns_cfg_layout = QtWidgets.QVBoxLayout(dns_cfg)

        dns_form = QtWidgets.QFormLayout()
        self.atk_dns_iface = _iface_combo("dns")
        dns_form.addRow("Interface:", self.atk_dns_iface)
        dns_cfg_layout.addLayout(dns_form)

        dns_tbl_lbl = QtWidgets.QLabel("Domain → Fake IP  (use * to spoof all queries):")
        dns_cfg_layout.addWidget(dns_tbl_lbl)

        self.atk_dns_table = QtWidgets.QTableWidget(0, 2)
        self.atk_dns_table.setObjectName("atk_dns_table")
        self.atk_dns_table.setHorizontalHeaderLabels(["Domain / Pattern", "Fake IP"])
        self.atk_dns_table.horizontalHeader().setStretchLastSection(True)
        self.atk_dns_table.setMaximumHeight(140)
        dns_cfg_layout.addWidget(self.atk_dns_table)

        dns_tbl_btns = QtWidgets.QHBoxLayout()
        self.atk_dns_add_row = QtWidgets.QPushButton("+ Add Row")
        self.atk_dns_del_row = QtWidgets.QPushButton("− Remove Row")
        dns_tbl_btns.addWidget(self.atk_dns_add_row)
        dns_tbl_btns.addWidget(self.atk_dns_del_row)
        dns_tbl_btns.addStretch()
        dns_cfg_layout.addLayout(dns_tbl_btns)

        dns_layout.addWidget(dns_cfg)

        dns_btn_row = QtWidgets.QHBoxLayout()
        self.atk_dns_start, self.atk_dns_stop = _atk_start_stop("dns")
        dns_btn_row.addWidget(self.atk_dns_start)
        dns_btn_row.addWidget(self.atk_dns_stop)
        dns_btn_row.addStretch()
        dns_layout.addLayout(dns_btn_row)

        dns_log_grp = QtWidgets.QGroupBox("Log")
        QtWidgets.QVBoxLayout(dns_log_grp).addWidget(_atk_log("dns"))
        self.atk_log_dns = dns_log_grp.findChild(QtWidgets.QPlainTextEdit)
        dns_layout.addWidget(dns_log_grp, stretch=1)

        self.atk_net_tabs.addTab(w_dns, "DNS Spoof")

        # ── Sub-tab 3: 802.11 Deauth ──────────────────────────────────────
        w_deauth = QtWidgets.QWidget()
        deauth_layout = QtWidgets.QVBoxLayout(w_deauth)

        deauth_cfg = QtWidgets.QGroupBox("Configuration")
        deauth_form = QtWidgets.QFormLayout(deauth_cfg)

        self.atk_deauth_iface = _iface_combo("deauth")
        deauth_form.addRow("Interface (monitor mode):", self.atk_deauth_iface)

        self.atk_deauth_bssid = QtWidgets.QLineEdit()
        self.atk_deauth_bssid.setPlaceholderText("AA:BB:CC:DD:EE:FF")
        deauth_form.addRow("BSSID (AP MAC):", self.atk_deauth_bssid)

        self.atk_deauth_client = QtWidgets.QLineEdit("FF:FF:FF:FF:FF:FF")
        self.atk_deauth_client.setToolTip("FF:FF:FF:FF:FF:FF = broadcast (kick all clients)")
        deauth_form.addRow("Client MAC:", self.atk_deauth_client)

        self.atk_deauth_reason = QtWidgets.QSpinBox()
        self.atk_deauth_reason.setRange(1, 23)
        self.atk_deauth_reason.setValue(7)
        self.atk_deauth_reason.setToolTip(
            "Reason codes: 1=Unspecified, 4=Inactivity, 7=Class3 not assoc, "
            "8=Leaving BSS, 15=4-way handshake timeout"
        )
        deauth_form.addRow("Reason code:", self.atk_deauth_reason)

        deauth_layout.addWidget(deauth_cfg)

        deauth_btn_row = QtWidgets.QHBoxLayout()
        self.atk_deauth_start, self.atk_deauth_stop = _atk_start_stop("deauth")
        deauth_btn_row.addWidget(self.atk_deauth_start)
        deauth_btn_row.addWidget(self.atk_deauth_stop)
        deauth_btn_row.addStretch()
        deauth_layout.addLayout(deauth_btn_row)

        deauth_log_grp = QtWidgets.QGroupBox("Log")
        QtWidgets.QVBoxLayout(deauth_log_grp).addWidget(_atk_log("deauth"))
        self.atk_log_deauth = deauth_log_grp.findChild(QtWidgets.QPlainTextEdit)
        deauth_layout.addWidget(deauth_log_grp, stretch=1)

        self.atk_wifi_tabs.addTab(w_deauth, "802.11 Deauth")

        # ── Sub-tab 5: DHCP Starvation ────────────────────────────────────
        w_dhcp_starve = QtWidgets.QWidget()
        dhs_layout = QtWidgets.QVBoxLayout(w_dhcp_starve)

        dhs_cfg = QtWidgets.QGroupBox("Configuration")
        dhs_form = QtWidgets.QFormLayout(dhs_cfg)
        self.atk_dhs_iface = _iface_combo("dhs")
        dhs_form.addRow("Interface:", self.atk_dhs_iface)
        dhs_note = QtWidgets.QLabel(
            "Floods the DHCP server with DISCOVER packets using random\n"
            "MAC addresses to exhaust its IP address pool."
        )
        dhs_note.setStyleSheet("color: gray; font-size: 10px;")
        dhs_form.addRow("", dhs_note)
        dhs_layout.addWidget(dhs_cfg)

        dhs_btn_row = QtWidgets.QHBoxLayout()
        self.atk_dhs_start, self.atk_dhs_stop = _atk_start_stop("dhs")
        dhs_btn_row.addWidget(self.atk_dhs_start)
        dhs_btn_row.addWidget(self.atk_dhs_stop)
        dhs_btn_row.addStretch()
        dhs_layout.addLayout(dhs_btn_row)

        dhs_log_grp = QtWidgets.QGroupBox("Log")
        QtWidgets.QVBoxLayout(dhs_log_grp).addWidget(_atk_log("dhs"))
        self.atk_log_dhs = dhs_log_grp.findChild(QtWidgets.QPlainTextEdit)
        dhs_layout.addWidget(dhs_log_grp, stretch=1)

        self.atk_net_tabs.addTab(w_dhcp_starve, "DHCP Starvation")

        # ── Sub-tab 6: Rogue DHCP ─────────────────────────────────────────
        w_rdhcp = QtWidgets.QWidget()
        rd_layout = QtWidgets.QVBoxLayout(w_rdhcp)

        rd_cfg = QtWidgets.QGroupBox("Configuration")
        rd_form = QtWidgets.QFormLayout(rd_cfg)

        self.atk_rd_iface = _iface_combo("rd")
        rd_form.addRow("Interface:", self.atk_rd_iface)

        self.atk_rd_server_ip = QtWidgets.QLineEdit()
        self.atk_rd_server_ip.setPlaceholderText("Our IP — e.g. 192.168.1.50")
        rd_form.addRow("Server IP (ours):", self.atk_rd_server_ip)

        self.atk_rd_router = QtWidgets.QLineEdit()
        self.atk_rd_router.setPlaceholderText("e.g. 192.168.1.50  (our IP for full MitM)")
        rd_form.addRow("Router / Gateway:", self.atk_rd_router)

        self.atk_rd_dns = QtWidgets.QLineEdit()
        self.atk_rd_dns.setPlaceholderText("e.g. 192.168.1.50  (our IP for DNS spoof)")
        rd_form.addRow("DNS Server:", self.atk_rd_dns)

        self.atk_rd_mask = QtWidgets.QLineEdit("255.255.255.0")
        rd_form.addRow("Subnet Mask:", self.atk_rd_mask)

        self.atk_rd_pool_start = QtWidgets.QLineEdit()
        self.atk_rd_pool_start.setPlaceholderText("e.g. 192.168.1.100")
        rd_form.addRow("Pool Start:", self.atk_rd_pool_start)

        self.atk_rd_pool_end = QtWidgets.QLineEdit()
        self.atk_rd_pool_end.setPlaceholderText("e.g. 192.168.1.200")
        rd_form.addRow("Pool End:", self.atk_rd_pool_end)

        self.atk_rd_lease = QtWidgets.QSpinBox()
        self.atk_rd_lease.setRange(60, 86400)
        self.atk_rd_lease.setValue(3600)
        self.atk_rd_lease.setSuffix(" s")
        rd_form.addRow("Lease Time:", self.atk_rd_lease)

        rd_layout.addWidget(rd_cfg)

        rd_btn_row = QtWidgets.QHBoxLayout()
        self.atk_rd_start, self.atk_rd_stop = _atk_start_stop("rd")
        rd_btn_row.addWidget(self.atk_rd_start)
        rd_btn_row.addWidget(self.atk_rd_stop)
        rd_btn_row.addStretch()
        rd_layout.addLayout(rd_btn_row)

        rd_log_grp = QtWidgets.QGroupBox("Log")
        QtWidgets.QVBoxLayout(rd_log_grp).addWidget(_atk_log("rd"))
        self.atk_log_rd = rd_log_grp.findChild(QtWidgets.QPlainTextEdit)
        rd_layout.addWidget(rd_log_grp, stretch=1)

        self.atk_net_tabs.addTab(w_rdhcp, "Rogue DHCP")

        # ── Sub-tab 7: LLMNR / NBT-NS Poison ─────────────────────────────
        w_llmnr = QtWidgets.QWidget()
        ll_layout = QtWidgets.QVBoxLayout(w_llmnr)

        ll_cfg = QtWidgets.QGroupBox("Configuration")
        ll_form = QtWidgets.QFormLayout(ll_cfg)

        self.atk_ll_our_ip = QtWidgets.QLineEdit()
        self.atk_ll_our_ip.setPlaceholderText("e.g. 192.168.1.50  (this machine's IP)")
        ll_form.addRow("Our IP (reply with):", self.atk_ll_our_ip)

        self.atk_ll_names = QtWidgets.QLineEdit()
        self.atk_ll_names.setPlaceholderText("fileserver, wpad, share  (empty = all)")
        ll_form.addRow("Target names (CSV):", self.atk_ll_names)

        ll_note = QtWidgets.QLabel(
            "Responds to LLMNR (UDP 5355) and NBT-NS (UDP 137) broadcast queries\n"
            "with our IP. Windows machines fall back to these when DNS fails.\n"
            "Tip: also start the TCP/TLS Proxy to capture redirected auth."
        )
        ll_note.setStyleSheet("color: gray; font-size: 10px;")
        ll_form.addRow("", ll_note)

        ll_layout.addWidget(ll_cfg)

        ll_btn_row = QtWidgets.QHBoxLayout()
        self.atk_ll_start, self.atk_ll_stop = _atk_start_stop("ll")
        ll_btn_row.addWidget(self.atk_ll_start)
        ll_btn_row.addWidget(self.atk_ll_stop)
        ll_btn_row.addStretch()
        ll_layout.addLayout(ll_btn_row)

        ll_log_grp = QtWidgets.QGroupBox("Log")
        QtWidgets.QVBoxLayout(ll_log_grp).addWidget(_atk_log("ll"))
        self.atk_log_ll = ll_log_grp.findChild(QtWidgets.QPlainTextEdit)
        ll_layout.addWidget(ll_log_grp, stretch=1)

        self.atk_net_tabs.addTab(w_llmnr, "LLMNR / NBT-NS")

        # ── WiFi: Rogue AP ────────────────────────────────────────────────
        w_rap = QtWidgets.QWidget()
        rap_layout = QtWidgets.QVBoxLayout(w_rap)

        rap_cfg = QtWidgets.QGroupBox("Configuration")
        rap_form = QtWidgets.QFormLayout(rap_cfg)

        self.atk_rap_iface = _iface_combo("rap")
        rap_form.addRow("Interface (AP mode):", self.atk_rap_iface)

        self.atk_rap_ssid = QtWidgets.QLineEdit()
        self.atk_rap_ssid.setPlaceholderText("e.g. FreeWifi")
        rap_form.addRow("SSID:", self.atk_rap_ssid)

        self.atk_rap_channel = QtWidgets.QSpinBox()
        self.atk_rap_channel.setRange(1, 13)
        self.atk_rap_channel.setValue(6)
        rap_form.addRow("Channel:", self.atk_rap_channel)

        self.atk_rap_enc = QtWidgets.QComboBox()
        self.atk_rap_enc.addItems(["Open", "WPA2"])
        self.atk_rap_enc.setObjectName("atk_rap_enc")
        rap_form.addRow("Encryption:", self.atk_rap_enc)

        self.atk_rap_password = QtWidgets.QLineEdit()
        self.atk_rap_password.setPlaceholderText("WPA2 passphrase (min 8 chars)")
        self.atk_rap_password.setEnabled(False)
        rap_form.addRow("Password:", self.atk_rap_password)

        rap_note = QtWidgets.QLabel(
            "Requires hostapd (apt install hostapd).\n"
            "Interface must support AP mode — check with: iw list | grep 'AP'\n"
            "Tip: combine with Rogue DHCP to assign IPs to connecting clients."
        )
        rap_note.setStyleSheet("color: gray; font-size: 10px;")
        rap_form.addRow("", rap_note)

        rap_layout.addWidget(rap_cfg)

        rap_btn_row = QtWidgets.QHBoxLayout()
        self.atk_rap_start, self.atk_rap_stop = _atk_start_stop("rap")
        rap_btn_row.addWidget(self.atk_rap_start)
        rap_btn_row.addWidget(self.atk_rap_stop)
        rap_btn_row.addStretch()
        rap_layout.addLayout(rap_btn_row)

        rap_log_grp = QtWidgets.QGroupBox("Log")
        QtWidgets.QVBoxLayout(rap_log_grp).addWidget(_atk_log("rap"))
        self.atk_log_rap = rap_log_grp.findChild(QtWidgets.QPlainTextEdit)
        rap_layout.addWidget(rap_log_grp, stretch=1)

        self.atk_wifi_tabs.addTab(w_rap, "Rogue AP")

        # ── Bluetooth: placeholder ────────────────────────────────────────
        w_bt = QtWidgets.QWidget()
        bt_layout = QtWidgets.QVBoxLayout(w_bt)
        bt_label = QtWidgets.QLabel(
            "Bluetooth attacks coming soon.\n\n"
            "Planned: BLE advertisement spoofing, RFCOMM fuzzing, HCI replay."
        )
        bt_label.setAlignment(QtCore.Qt.AlignCenter)
        bt_label.setStyleSheet("color: gray;")
        bt_layout.addWidget(bt_label)
        self.atk_bt_tabs.addTab(w_bt, "Coming Soon")

        self.tabWidget.addTab(self.tab_attack, "Attack")

        # ── Menu bar ─────────────────────────────────────────────────────
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1280, 24))
        self.menubar.setDefaultUp(True)
        self.menubar.setObjectName("menubar")

        self.menufile = QtWidgets.QMenu(self.menubar)
        self.menufile.setObjectName("menufile")
        self.menuCapture = QtWidgets.QMenu(self.menubar)
        self.menuCapture.setObjectName("menuCapture")
        self.menuReplacer = QtWidgets.QMenu(self.menubar)
        self.menuReplacer.setObjectName("menuReplacer")
        self.menuHelp = QtWidgets.QMenu(self.menubar)
        self.menuHelp.setObjectName("menuHelp")
        self.menuAbout = QtWidgets.QMenu(self.menubar)
        self.menuAbout.setObjectName("menuAbout")
        self.menuStatistics = QtWidgets.QMenu(self.menubar)
        self.menuStatistics.setObjectName("menuStatistics")
        self.menuSettings = QtWidgets.QMenu(self.menubar)
        self.menuSettings.setObjectName("menuSettings")
        MainWindow.setMenuBar(self.menubar)

        self.statusBar = QtWidgets.QStatusBar(MainWindow)
        self.statusBar.setObjectName("statusBar")
        MainWindow.setStatusBar(self.statusBar)

        # Actions
        self.actionOpen = QtWidgets.QAction(MainWindow)
        self.actionOpen.setObjectName("actionOpen")
        self.actionSave = QtWidgets.QAction(MainWindow)
        self.actionSave.setObjectName("actionSave")
        self.actionSave_as = QtWidgets.QAction(MainWindow)
        self.actionSave_as.setObjectName("actionSave_as")
        self.actionClose = QtWidgets.QAction(MainWindow)
        self.actionClose.setObjectName("actionClose")
        self.actionOpen_Recent = QtWidgets.QAction(MainWindow)
        self.actionOpen_Recent.setObjectName("actionOpen_Recent")
        self.actionOptions = QtWidgets.QAction(MainWindow)
        self.actionOptions.setObjectName("actionOptions")
        self.actionSniff = QtWidgets.QAction(MainWindow)
        self.actionSniff.setObjectName("actionSniff")
        self.actionHalt = QtWidgets.QAction(MainWindow)
        self.actionHalt.setObjectName("actionHalt")
        self.actionInterfaces = QtWidgets.QAction(MainWindow)
        self.actionInterfaces.setObjectName("actionInterfaces")
        self.actionFirewall = QtWidgets.QAction(MainWindow)
        self.actionFirewall.setObjectName("actionFirewall")
        self.actionRules = QtWidgets.QAction(MainWindow)
        self.actionRules.setObjectName("actionRules")
        self.actionIPv4_Statistics = QtWidgets.QAction(MainWindow)
        self.actionIPv4_Statistics.setObjectName("actionIPv4_Statistics")
        self.actionIPv6_Statistics = QtWidgets.QAction(MainWindow)
        self.actionIPv6_Statistics.setObjectName("actionIPv6_Statistics")
        self.actionLight_Mode = QtWidgets.QAction(MainWindow)
        self.actionLight_Mode.setObjectName("actionLight_Mode")
        self.actionDark_Mode = QtWidgets.QAction(MainWindow)
        self.actionDark_Mode.setObjectName("actionDark_Mode")

        self.menufile.addAction(self.actionOpen)
        self.menufile.addAction(self.actionOpen_Recent)
        self.menufile.addAction(self.actionClose)
        self.menufile.addSeparator()
        self.menufile.addAction(self.actionSave)
        self.menufile.addAction(self.actionSave_as)
        self.menuCapture.addAction(self.actionOptions)
        self.menuCapture.addAction(self.actionSniff)
        self.menuCapture.addAction(self.actionHalt)
        self.menuCapture.addSeparator()
        self.menuCapture.addAction(self.actionInterfaces)
        self.menuCapture.addAction(self.actionFirewall)
        self.menuReplacer.addAction(self.actionRules)
        self.menuStatistics.addAction(self.actionIPv4_Statistics)
        self.menuStatistics.addAction(self.actionIPv6_Statistics)
        self.menuSettings.addAction(self.actionLight_Mode)
        self.menuSettings.addAction(self.actionDark_Mode)
        self.menubar.addAction(self.menufile.menuAction())
        self.menubar.addAction(self.menuCapture.menuAction())
        self.menubar.addAction(self.menuReplacer.menuAction())
        self.menubar.addAction(self.menuStatistics.menuAction())
        self.menubar.addAction(self.menuSettings.menuAction())
        self.actionAbout = QtWidgets.QAction(MainWindow)
        self.actionAbout.setObjectName("actionAbout")
        self.menuAbout.addAction(self.actionAbout)

        self.menubar.addAction(self.menuHelp.menuAction())
        self.menubar.addAction(self.menuAbout.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "SharkPy"))
        self.sniffButton.setText(_translate("MainWindow", "Sniff"))
        self.haltButton.setText(_translate("MainWindow", "Stop"))
        self.label.setText(_translate("MainWindow", "Status:"))
        self.deb_breakButton.setText(_translate("MainWindow", "Break"))
        self.deb_nextButton.setText(_translate("MainWindow", "Next"))
        self.deb_continueButton.setText(_translate("MainWindow", "Continue"))
        self.checkBox.setText(_translate("MainWindow", "Discard queue packets"))
        self.filterText.setPlaceholderText(
            _translate("MainWindow", "Filter...  e.g.  tcp  |  ip.src == 1.2.3.4  |  udp.port == 53"))
        self.filterButton.setText(_translate("MainWindow", "Apply"))
        self.clearButton.setText(_translate("MainWindow", "Clear"))
        self.tabWidget.setTabText(0, _translate("MainWindow", "Capture"))
        self.tabWidget.setTabText(1, _translate("MainWindow", "Repeater"))
        self.tabWidget.setTabText(2, _translate("MainWindow", "Sessions"))
        self.tabWidget.setTabText(3, _translate("MainWindow", "TLS"))
        self.menufile.setTitle(_translate("MainWindow", "File"))
        self.menuCapture.setTitle(_translate("MainWindow", "Capture"))
        self.menuReplacer.setTitle(_translate("MainWindow", "Replacer"))
        self.menuHelp.setTitle(_translate("MainWindow", "Help"))
        self.menuAbout.setTitle(_translate("MainWindow", "About"))
        self.actionAbout.setText(_translate("MainWindow", "About SharkPy"))
        self.menuStatistics.setTitle(_translate("MainWindow", "Statistics"))
        self.menuSettings.setTitle(_translate("MainWindow", "View"))
        self.actionOpen.setText(_translate("MainWindow", "Open"))
        self.actionSave.setText(_translate("MainWindow", "Save"))
        self.actionSave_as.setText(_translate("MainWindow", "Save as..."))
        self.actionClose.setText(_translate("MainWindow", "Close"))
        self.actionOpen_Recent.setText(_translate("MainWindow", "Open Recent"))
        self.actionOptions.setText(_translate("MainWindow", "Options"))
        self.actionSniff.setText(_translate("MainWindow", "Sniff"))
        self.actionHalt.setText(_translate("MainWindow", "Halt"))
        self.actionInterfaces.setText(_translate("MainWindow", "Interfaces"))
        self.actionFirewall.setText(_translate("MainWindow", "Firewall"))
        self.actionRules.setText(_translate("MainWindow", "Rules"))
        self.actionIPv4_Statistics.setText(_translate("MainWindow", "IPv4 Statistics"))
        self.actionIPv6_Statistics.setText(_translate("MainWindow", "IPv6 Statistics"))
        self.actionLight_Mode.setText(_translate("MainWindow", "Light Mode"))
        self.actionDark_Mode.setText(_translate("MainWindow", "Dark Mode"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
