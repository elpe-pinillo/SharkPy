from binascii import hexlify, unhexlify
import sys
import socket
import threading
import time
import logging
try:
    import netifaces
except ImportError:
    import netifaces2 as netifaces
from scapy.all import *
from PyQt5.QtCore import QMetaObject, Qt, Q_ARG

if sys.platform == "win32":
    import pydivert
else:
    from netfilterqueue import NetfilterQueue
    from p_firewall import filter, flush

logger = logging.getLogger(__name__)


class CoreClass():
    def __init__(self, parent):
        self.parent = parent
        self.running = False
        self.is_started = False
        self.automod = False
        self.packet_counter = 0
        self.myturn = 0
        self.filter_input = True
        self.filter_output = True
        self.filter_forward = False
        self._debug_event = threading.Event()

    def procesar_paquete(self, pkt):
        """
        This function is executed whenever a packet is sniffed
        """
        if self.is_started:
            ip_packet = IP(pkt.get_payload())
            spacket = ip_packet

            self.packet_counter += 1

            # Push packet to GUI from the capture thread via invokeMethod
            QMetaObject.invokeMethod(
                self.parent, "push_packets",
                Qt.QueuedConnection,
                Q_ARG("PyQt_PyObject", ip_packet),
            )

            # Block until the user steps forward in debug mode
            if self.parent.debugmode:
                self._debug_event.clear()
                self._debug_event.wait()
                if not self.is_started:
                    raise KeyboardInterrupt

            ip_packet = self.parent.packet_list[self.packet_counter - 1]

            if self.myturn != self.packet_counter:
                self.myturn += 1

            if self.automod:
                if self.parent.outputCheckBox_2.isChecked():
                    for ip in self.get_source_ip():
                        if spacket[IP].src == ip:
                            ip_packet = self.automod_packets(spacket, self.parent.textEdit.toPlainText(),
                                                             self.parent.textEdit_2.toPlainText())
                            QMetaObject.invokeMethod(
                                self.parent, "push_packets",
                                Qt.QueuedConnection,
                                Q_ARG("PyQt_PyObject", ip_packet),
                                Q_ARG("PyQt_PyObject", self.packet_counter - 1),
                            )

                if self.parent.InputCheckBox.isChecked():
                    for ip in self.get_source_ip():
                        if spacket[IP].dst == ip:
                            ip_packet = self.automod_packets(spacket, self.parent.textEdit.toPlainText(),
                                                             self.parent.textEdit_2.toPlainText())
                            QMetaObject.invokeMethod(
                                self.parent, "push_packets",
                                Qt.QueuedConnection,
                                Q_ARG("PyQt_PyObject", ip_packet),
                                Q_ARG("PyQt_PyObject", self.packet_counter - 1),
                            )

                if self.parent.forwardCheckBox_3.isChecked():
                    ip_packet = self.automod_packets(spacket, self.parent.textEdit.toPlainText(),
                                                     self.parent.textEdit_2.toPlainText())
                    QMetaObject.invokeMethod(
                        self.parent, "push_packets",
                        Qt.QueuedConnection,
                        Q_ARG("PyQt_PyObject", ip_packet),
                        Q_ARG("PyQt_PyObject", self.packet_counter - 1),
                    )

            pkt.set_payload(bytes(ip_packet))
            pkt.accept()

        else:
            raise KeyboardInterrupt

    def debug_step(self):
        """Signal the capture thread to release the next packet."""
        self._debug_event.set()

    def automod_packets(self, spacket, search, replace):

        pktHex = hexlify(bytes(spacket))

        if search.lower() in str(pktHex).lower():

            pktHex = pktHex.replace(search.lower().encode(), replace.lower().encode())

        spacketbytes = unhexlify(pktHex)
        spacket = IP(spacketbytes)

        if spacket.haslayer(IP):
            spacket[IP].len = None
            spacket[IP].chksum = None
        if spacket.haslayer(TCP):
            spacket[TCP].len = None
            spacket[TCP].chksum = None
        if spacket.haslayer(UDP):
            spacket[UDP].len = None
            spacket[UDP].chksum = None
        if spacket.haslayer(ICMP):
            spacket[ICMP].chksum = None
        return spacket

    def run(self, iface):
        """Intercept mode: route traffic through NFQUEUE for modify/drop/forward."""
        filter(mitm=True, i=iface)
        self.is_started = True
        nfqueue = NetfilterQueue()
        nfqueue.bind(0, self.procesar_paquete)
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            nfqueue.unbind()
            flush()

    def run_windivert(self, iface):
        """Windows intercept mode: hold every IP packet via WinDivert, allow
        modify/drop, then reinject.  Requires the WinDivert driver and pydivert.

        Per-interface filtering uses the Windows adapter index.  Falls back to
        capturing all traffic when the index cannot be determined.
        """
        # Build WinDivert filter string.
        # Attempt per-interface filtering via ifIdx; fall back to "true" (all traffic).
        wd_filter = "true"
        if iface != "Any...":
            try:
                idx = socket.if_nametoindex(iface)
                wd_filter = f"ifIdx == {idx}"
            except (AttributeError, OSError):
                pass   # socket.if_nametoindex not available on older Windows

        self.is_started = True
        try:
            with pydivert.WinDivert(wd_filter) as w:
                self._windivert_handle = w
                while self.is_started:
                    try:
                        packet = w.recv()
                    except Exception:
                        break   # handle closed by stop()

                    if not self.is_started:
                        try:
                            w.send(packet)
                        except Exception:
                            pass
                        break

                    try:
                        ip_pkt = IP(packet.raw)
                    except Exception:
                        try:
                            w.send(packet)
                        except Exception:
                            pass
                        continue

                    self.packet_counter += 1

                    QMetaObject.invokeMethod(
                        self.parent, "push_packets",
                        Qt.QueuedConnection,
                        Q_ARG("PyQt_PyObject", ip_pkt),
                    )

                    # Debug / intercept stepping
                    if self.parent.debugmode:
                        self._debug_event.clear()
                        self._debug_event.wait()
                        if not self.is_started:
                            try:
                                w.send(packet)
                            except Exception:
                                pass
                            break

                    ip_pkt = self.parent.packet_list[self.packet_counter - 1]

                    if self.automod:
                        local_ips = self.get_source_ip()

                        if self.parent.outputCheckBox_2.isChecked():
                            for lip in local_ips:
                                if ip_pkt.haslayer(IP) and ip_pkt[IP].src == lip:
                                    ip_pkt = self.automod_packets(
                                        ip_pkt,
                                        self.parent.textEdit.toPlainText(),
                                        self.parent.textEdit_2.toPlainText(),
                                    )
                                    QMetaObject.invokeMethod(
                                        self.parent, "push_packets",
                                        Qt.QueuedConnection,
                                        Q_ARG("PyQt_PyObject", ip_pkt),
                                        Q_ARG("PyQt_PyObject", self.packet_counter - 1),
                                    )

                        if self.parent.InputCheckBox.isChecked():
                            for lip in local_ips:
                                if ip_pkt.haslayer(IP) and ip_pkt[IP].dst == lip:
                                    ip_pkt = self.automod_packets(
                                        ip_pkt,
                                        self.parent.textEdit.toPlainText(),
                                        self.parent.textEdit_2.toPlainText(),
                                    )
                                    QMetaObject.invokeMethod(
                                        self.parent, "push_packets",
                                        Qt.QueuedConnection,
                                        Q_ARG("PyQt_PyObject", ip_pkt),
                                        Q_ARG("PyQt_PyObject", self.packet_counter - 1),
                                    )

                        if self.parent.forwardCheckBox_3.isChecked():
                            ip_pkt = self.automod_packets(
                                ip_pkt,
                                self.parent.textEdit.toPlainText(),
                                self.parent.textEdit_2.toPlainText(),
                            )
                            QMetaObject.invokeMethod(
                                self.parent, "push_packets",
                                Qt.QueuedConnection,
                                Q_ARG("PyQt_PyObject", ip_pkt),
                                Q_ARG("PyQt_PyObject", self.packet_counter - 1),
                            )

                    packet.raw = bytes(ip_pkt)
                    try:
                        w.send(packet)
                    except Exception as exc:
                        logger.warning("WinDivert send failed: %s", exc)

        except Exception as exc:
            logger.error("WinDivert error: %s", exc)

    def run_sniff(self, iface):
        """Passive sniff mode: capture full L2 frames via raw socket (read-only)."""
        self.is_started = True
        iface_arg = None if iface == "Any..." else iface
        self._sniffer = AsyncSniffer(
            iface=iface_arg,
            prn=self._handle_sniffed_packet,
            store=False,
        )
        self._sniffer.start()
        while self.is_started:
            time.sleep(0.1)
        if self._sniffer.running:
            self._sniffer.stop()

    def _handle_sniffed_packet(self, pkt):
        if not self.is_started:
            return
        self.packet_counter += 1
        QMetaObject.invokeMethod(
            self.parent, "push_packets",
            Qt.QueuedConnection,
            Q_ARG("PyQt_PyObject", pkt),
        )
        if self.parent.debugmode:
            self._debug_event.clear()
            self._debug_event.wait()

    def get_source_ip(self):
        direcciones_ip = []
        try:
            # Obtén la información de todas las interfaces de red
            interfaces = netifaces.interfaces()

            for interface in interfaces:
                # Obtén la información de la interfaz
                interfaz_info = netifaces.ifaddresses(interface)

                # Busca la dirección IPv4 (AF_INET) en la interfaz
                if netifaces.AF_INET in interfaz_info:
                    direcciones_ip.extend(info['addr'] for info in interfaz_info[netifaces.AF_INET])

        except (socket.error, netifaces.error) as e:
            print(f"Error al obtener las direcciones IP: {e}")

        return direcciones_ip

    def stop(self):
        logger.info("Stopping packet capture")
        self.is_started = False
        self._debug_event.set()  # unblock capture thread if waiting in debug mode
        if hasattr(self, '_sniffer') and self._sniffer.running:
            self._sniffer.stop()
        elif hasattr(self, '_windivert_handle'):
            try:
                self._windivert_handle.close()
            except Exception:
                pass
        elif sys.platform != "win32":
            flush()  # Linux intercept mode: clear iptables rules
