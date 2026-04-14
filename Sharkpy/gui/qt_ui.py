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

        sp_min = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum,
                                       QtWidgets.QSizePolicy.Minimum)

        self.hexdump_row = QtWidgets.QListWidget(hex_container)
        self.hexdump_row.setObjectName("hexdump_row")
        self.hexdump_row.setMaximumWidth(70)
        self.hexdump_row.setAutoScroll(False)
        self.hexdump_row.setSizePolicy(sp_min)
        hex_row_layout.addWidget(self.hexdump_row)

        self.hexdump_hex1 = QtWidgets.QListWidget(hex_container)
        self.hexdump_hex1.setObjectName("hexdump_hex1")
        self.hexdump_hex1.setSizeAdjustPolicy(
            QtWidgets.QAbstractScrollArea.AdjustIgnored)
        self.hexdump_hex1.setAutoScroll(False)
        hex_row_layout.addWidget(self.hexdump_hex1)

        self.hexdump_ascii = QtWidgets.QListWidget(hex_container)
        self.hexdump_ascii.setObjectName("hexdump_ascii")
        self.hexdump_ascii.setMaximumWidth(200)
        self.hexdump_ascii.setAutoScroll(False)
        self.hexdump_ascii.setSizePolicy(sp_min)
        hex_row_layout.addWidget(self.hexdump_ascii)

        cap_hsplit.addWidget(self.detail_tree_widget)
        cap_hsplit.addWidget(hex_container)
        cap_hsplit.setSizes([420, 580])

        cap_vsplit.addWidget(self.filter_table)
        cap_vsplit.addWidget(cap_hsplit)
        cap_vsplit.setSizes([420, 260])

        cap_layout.addWidget(cap_vsplit)
        self.tabWidget.addTab(self.tab_capture, "Capture")

        # ═══════════════════════════════════════════════════════════════════
        # TAB 2 — REPEATER  (edit & resend packets, like Burp Repeater)
        # ═══════════════════════════════════════════════════════════════════
        self.tab_repeater = QtWidgets.QWidget()
        self.tab_repeater.setObjectName("tab_repeater")
        rep_layout = QtWidgets.QVBoxLayout(self.tab_repeater)
        rep_layout.setContentsMargins(4, 4, 4, 4)
        rep_layout.setSpacing(4)

        # ── Repeater toolbar ─────────────────────────────────────────────
        rep_toolbar = QtWidgets.QHBoxLayout()
        rep_toolbar.setSpacing(6)

        self.rep_loadButton = QtWidgets.QPushButton("Load Selected Packet")
        self.rep_loadButton.setObjectName("rep_loadButton")
        rep_toolbar.addWidget(self.rep_loadButton)

        self.rep_sendButton = QtWidgets.QPushButton("Send")
        self.rep_sendButton.setObjectName("rep_sendButton")
        rep_toolbar.addWidget(self.rep_sendButton)

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

        # ── Horizontal splitter: packet editor | response ────────────────
        rep_hsplit = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        mono = QtGui.QFont("Monospace", 10)

        req_widget = QtWidgets.QWidget()
        req_vbox = QtWidgets.QVBoxLayout(req_widget)
        req_vbox.setContentsMargins(0, 0, 0, 0)
        req_vbox.setSpacing(2)
        req_vbox.addWidget(QtWidgets.QLabel("Request / Packet"))
        self.rep_edit_area = QtWidgets.QTextEdit()
        self.rep_edit_area.setObjectName("rep_edit_area")
        self.rep_edit_area.setFont(mono)
        self.rep_edit_area.setPlaceholderText(
            "Select a packet in the Capture tab, then click 'Load Selected Packet'")
        req_vbox.addWidget(self.rep_edit_area)

        resp_widget = QtWidgets.QWidget()
        resp_vbox = QtWidgets.QVBoxLayout(resp_widget)
        resp_vbox.setContentsMargins(0, 0, 0, 0)
        resp_vbox.setSpacing(2)
        resp_vbox.addWidget(QtWidgets.QLabel("Response"))
        self.rep_response_area = QtWidgets.QTextEdit()
        self.rep_response_area.setObjectName("rep_response_area")
        self.rep_response_area.setReadOnly(True)
        self.rep_response_area.setFont(mono)
        resp_vbox.addWidget(self.rep_response_area)

        rep_hsplit.addWidget(req_widget)
        rep_hsplit.addWidget(resp_widget)
        rep_hsplit.setSizes([600, 600])
        rep_layout.addWidget(rep_hsplit, stretch=1)

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

        # ── Proxy controls group ──────────────────────────────────────────
        proxy_group = QtWidgets.QGroupBox("Interception")
        proxy_glayout = QtWidgets.QHBoxLayout(proxy_group)

        proxy_glayout.addWidget(QtWidgets.QLabel("Intercept port:"))
        self.tls_intercept_port = QtWidgets.QLineEdit("443")
        self.tls_intercept_port.setObjectName("tls_intercept_port")
        self.tls_intercept_port.setMaximumWidth(60)
        proxy_glayout.addWidget(self.tls_intercept_port)

        proxy_glayout.addWidget(QtWidgets.QLabel("Proxy port:"))
        self.tls_proxy_port = QtWidgets.QLineEdit("8443")
        self.tls_proxy_port.setObjectName("tls_proxy_port")
        self.tls_proxy_port.setMaximumWidth(60)
        proxy_glayout.addWidget(self.tls_proxy_port)

        self.tls_start_btn = QtWidgets.QPushButton("Start Interception")
        self.tls_start_btn.setObjectName("tls_start_btn")
        proxy_glayout.addWidget(self.tls_start_btn)

        self.tls_stop_btn = QtWidgets.QPushButton("Stop Interception")
        self.tls_stop_btn.setObjectName("tls_stop_btn")
        proxy_glayout.addWidget(self.tls_stop_btn)

        proxy_glayout.addStretch()

        self.tls_proxy_status = QtWidgets.QLabel("Status: Stopped")
        self.tls_proxy_status.setObjectName("tls_proxy_status")
        proxy_glayout.addWidget(self.tls_proxy_status)

        tls_layout.addWidget(proxy_group)

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
