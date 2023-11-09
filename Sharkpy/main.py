from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QTreeWidgetItem

import qtmodern.windows
import qtmodern.styles
from gui import qt_ui
import netifaces
from protocol_parser import *
from scapy.all import *
from core import CoreClass


class SniffTool(QtWidgets.QMainWindow, qt_ui.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.statusBar().setStyleSheet("border :3px solid black;")
        self.c = CoreClass(self)
        self.setupUi(self)
        self.t = None
        self.thread = None
        self.running_info.setText("Ready to sniff")
        self.packet_list = []
        self.auto_down_scroll = True
        self.initial_time = 0.0
        self.event_time = 0.0
        self.interface_2.addItem("Any...")
        self.interface_2.addItems(netifaces.interfaces())
        self.haltButton.setEnabled(False)
        self.sCorruptButton.setEnabled(False)
        self.deb_nextButton.setEnabled(False)
        self.deb_continueButton.setEnabled(False)
        self.debugmode = False
        self.sniffButton.clicked.connect(self.sniff_button_event)
        self.haltButton.clicked.connect(self.stop_button_event)
        self.clearButton.clicked.connect(self.clear_view)
        self.filter_table.cellClicked.connect(self.show_packet)
        self.filter_table.cellClicked.connect(self.show_hex_packet)
        self.corruptButton.clicked.connect(self.corrupt_button_event)
        self.sCorruptButton.clicked.connect(self.stop_corrupt_button_event)
        self.deb_breakButton.clicked.connect(self.deb_break_button_event)
        self.deb_continueButton.clicked.connect(self.deb_continue_button_event)
        self.deb_nextButton.clicked.connect(self.deb_next_button_event)

        self.filter_table.itemChanged.connect(self.updateObject)
        # self.filter_table.itemChanged.connect(self.show_packet)
        # self.detail_tree_widget.itemChanged.connect(self.updateObject)
        self.detail_tree_widget.itemChanged.connect(self.updateFilterTable)

    def updateObject(self, item):
        # To review, this is very inefficient because every single time a new packet arrives this function is called.
        # We only want this when someone make a change in on the items of the table
        if(item.column() == 1):
            packet = self.packet_list[item.row()]
            packet[IP].src = item.text()
            self.packet_list[item.row()] = packet
        if(item.column() == 2):
            packet = self.packet_list[item.row()]
            packet[IP].dst = item.text()
            self.packet_list[item.row()] = packet
        self.updateTreeView(item)
        self.updateFilterTable(item)

    def updateTreeView(self, item):
        pass

    def updateFilterTable(self, item):
        pass

    def sniff_button_event(self):
        self.sniffButton.setEnabled(False)
        self.haltButton.setEnabled(True)
        self.c.should_exit = True
        def insert_packets():
            self.c.run(selected_interface)

        selected_interface = str(self.interface_2.currentText())
        self.t = threading.Thread(target=insert_packets)
        self.t.start()

    def stop_button_event(self):
        self.sniffButton.setEnabled(True)
        self.haltButton.setEnabled(False)
        self.c.stop()


    def corrupt_button_event(self):
        self.corruptButton.setEnabled(False)
        self.sCorruptButton.setEnabled(True)
        self.c.automod = True

    def stop_corrupt_button_event(self):
        self.sCorruptButton.setEnabled(False)
        self.corruptButton.setEnabled(True)
        print("stop corrupt button")
        self.c.automod = False

    def deb_break_button_event(self):
        self.deb_breakButton.setEnabled(False)
        self.deb_nextButton.setEnabled(True)
        self.deb_continueButton.setEnabled(True)
        self.debugmode = True

    def deb_next_button_event(self):
        self.c.myturn += 1

    def deb_continue_button_event(self):
        self.deb_breakButton.setEnabled(True)
        self.deb_nextButton.setEnabled(False)
        self.deb_continueButton.setEnabled(False)
        self.debugmode = False

    def clear_view(self):
        self.filter_table.clearContents()
        self.filter_table.setRowCount(0)
        self.detail_tree_widget.clear()
        self.hexdump_hex1.clear()
        self.hexdump_ascii.clear()
        self.hexdump_row.clear()

        self.packet_list = []
        self.c.packet_counter = 0
        self.c.myturn = 0

    def show_packet(self, row, col):
        self.detail_tree_widget.clear()
        selected_packet = self.packet_list[row]
        general = QTreeWidgetItem(self.detail_tree_widget, ["General"])
        for protocol in list(self.expand(selected_packet)):
            if protocol == "Raw":
                raw_layer_gui = QTreeWidgetItem(self.detail_tree_widget, ["Data"])
                QTreeWidgetItem(raw_layer_gui, ["Data: " + str(selected_packet[Raw])])
            elif protocol == "Ethernet":
                ether_layer = QTreeWidgetItem(self.detail_tree_widget, ["Ethernet"])
                for field in selected_packet[protocol].fields:
                    ether_layer_details = QTreeWidgetItem(ether_layer, [
                        field + ": " + str(selected_packet[protocol].fields[field])])
            elif protocol == "IP":
                ip_layer = QTreeWidgetItem(self.detail_tree_widget, ["IP"])
                for field in selected_packet[protocol].fields:
                    ip_layer_details = QTreeWidgetItem(ip_layer, [
                        field + ": " + str(selected_packet[protocol].fields[field])])
            elif protocol == "TCP" or protocol == "UDP":
                transport_layer = QTreeWidgetItem(self.detail_tree_widget, ["Transport"])
                for field in selected_packet[protocol].fields:
                    transport_layer_details = QTreeWidgetItem(transport_layer, [
                        field + ": " + str(selected_packet[protocol].fields[field])])
            else:
                aux_layer = QTreeWidgetItem(self.detail_tree_widget, [protocol])
                for field in selected_packet[protocol].fields:
                    aux_layer_details = QTreeWidgetItem(aux_layer, [
                        field + ": " + str(selected_packet[protocol].fields[field])])

    def show_hex_packet(self, row, col):
        self.hexdump_row.clear()
        self.hexdump_hex1.clear()
        # self.hexdump_hex2.clear()
        self.hexdump_ascii.clear()
        selected_packet = self.packet_list[row]

        hexdump_str = hexdump(selected_packet[IP], dump=True)
        s = ""
        x = bytes_encode(selected_packet[IP])
        x_len = len(x)
        i = 0

        while i < x_len:
            counter = 0
            var1 = ""
            var2 = ""
            var = ""
            s += "%04x  " % i
            self.hexdump_row.addItem("%04x  " % i)
            for j in range(16):
                counter += 1
                if i + j < x_len:
                    s += "%02X " % orb(x[i + j])
                    var += "%02X " % orb(x[i + j])
                    if counter <= 8:
                        var1 += "%02X " % orb(x[i + j])
                    else:
                        var2 += "%02X " % orb(x[i + j])
                else:
                    s += "   "
                    var += "   "
                    var2 += "   "

            s += " %s\n" % x[i:i + 16]
            self.hexdump_ascii.addItem(" %s" % x[i:i + 16])

            i += 16

            self.hexdump_hex1.setStyleSheet("QListWidget::item { text-align: justify; }")
            self.hexdump_hex1.addItem(var)



    def push_packets(self, spacket, row="null"):
        if row == "null":
            row = self.filter_table.rowCount()
            self.packet_list.append(spacket)
            self.filter_table.insertRow(row)
        else:
            self.packet_list[row] = spacket


        if self.event_time == 0.0:
            self.initial_time = time.time()

        self.event_time = time.time() - self.initial_time
        self.filter_table.setItem(row, 0, QtWidgets.QTableWidgetItem(str(round(self.event_time, 4))))

        self.filter_table.setItem(row, 1, QtWidgets.QTableWidgetItem(spacket[IP].src))
        self.filter_table.setItem(row, 2, QtWidgets.QTableWidgetItem(spacket[IP].dst))
        self.filter_table.setItem(row, 3, QtWidgets.QTableWidgetItem(get_protocol(spacket)))
        self.filter_table.setItem(row, 4, QtWidgets.QTableWidgetItem(str(spacket[IP].len)))
        self.filter_table.setItem(row, 5, QtWidgets.QTableWidgetItem(spacket[IP].summary()))

        if self.auto_down_scroll:
            self.filter_table.scrollToBottom()
    def expand(self, x):
        yield x.name
        while x.payload:
            x = x.payload
            yield x.name




if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    tool = SniffTool()
    # qtmodern.styles.light(app)
    qtmodern.styles.dark(app)
    # qtmodern.styles.dark(app)

    moderntool = qtmodern.windows.ModernWindow(tool)

    moderntool.showMaximized()
    # moderntool.show()
    app.exec_()
