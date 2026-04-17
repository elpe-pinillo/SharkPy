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
        self._port_filter = None
        self._edited_bytes = None

    def _port_matches(self, ip_pkt):
        """Return True if packet matches active port filter (or no filter set)."""
        pf = getattr(self, '_port_filter', None)
        if not pf:
            return True
        pkt_ports = set()
        if ip_pkt.haslayer(TCP):
            pkt_ports |= {ip_pkt[TCP].sport, ip_pkt[TCP].dport}
        if ip_pkt.haslayer(UDP):
            pkt_ports |= {ip_pkt[UDP].sport, ip_pkt[UDP].dport}
        return bool(pkt_ports & pf)

    def procesar_paquete(self, pkt):
        """
        This function is executed whenever a packet is sniffed
        """
        if not self.is_started:
            raise KeyboardInterrupt

        raw = pkt.get_payload()
        ip_version = (raw[0] >> 4) if raw else 4
        ip_packet = IPv6(raw) if ip_version == 6 else IP(raw)
        spacket = ip_packet

        # Port filter: silently forward non-matching packets
        if not self._port_matches(ip_packet):
            pkt.accept()
            return

        self.packet_counter += 1

        if self.parent.debugmode:
            # ── Intercept/debug mode: hold packet until user steps forward ──
            # Block until GUI appends to packet_list so user can edit it.
            QMetaObject.invokeMethod(
                self.parent, "push_packets",
                Qt.BlockingQueuedConnection,
                Q_ARG("PyQt_PyObject", ip_packet),
                Q_ARG("PyQt_PyObject", "null"),
            )
            self._debug_event.clear()
            self._debug_event.wait()
            if not self.is_started:
                raise KeyboardInterrupt

            # Use edited bytes if the user modified the packet in the GUI
            if self._edited_bytes is not None:
                try:
                    eb = self._edited_bytes
                    ip_packet = IPv6(eb) if (eb and eb[0] >> 4 == 6) else IP(eb)
                except Exception:
                    ip_packet = self.parent.packet_list[self.packet_counter - 1]
                self._edited_bytes = None
            else:
                ip_packet = self.parent.packet_list[self.packet_counter - 1]
        else:
            # ── Normal mode: forward immediately, update GUI asynchronously ──
            # Apply automod before forwarding (does not require GUI round-trip).
            if self.automod:
                _pkt_src = (spacket[IP].src if spacket.haslayer(IP) else
                            spacket[IPv6].src if spacket.haslayer(IPv6) else None)
                _pkt_dst = (spacket[IP].dst if spacket.haslayer(IP) else
                            spacket[IPv6].dst if spacket.haslayer(IPv6) else None)
                if self.parent.outputCheckBox_2.isChecked():
                    for lip in self.get_source_ip():
                        if _pkt_src == lip:
                            ip_packet = self.automod_packets(
                                spacket,
                                self.parent.textEdit.toPlainText(),
                                self.parent.textEdit_2.toPlainText(),
                            )
                if self.parent.InputCheckBox.isChecked():
                    for lip in self.get_source_ip():
                        if _pkt_dst == lip:
                            ip_packet = self.automod_packets(
                                spacket,
                                self.parent.textEdit.toPlainText(),
                                self.parent.textEdit_2.toPlainText(),
                            )
                if self.parent.forwardCheckBox_3.isChecked():
                    ip_packet = self.automod_packets(
                        spacket,
                        self.parent.textEdit.toPlainText(),
                        self.parent.textEdit_2.toPlainText(),
                    )

            # Forward packet immediately — no waiting for GUI.
            pkt.set_payload(bytes(ip_packet))
            pkt.accept()

            # Push display update to GUI asynchronously (does not block forwarding).
            QMetaObject.invokeMethod(
                self.parent, "push_packets",
                Qt.QueuedConnection,
                Q_ARG("PyQt_PyObject", ip_packet),
                Q_ARG("PyQt_PyObject", "null"),
            )
            return

        if self.myturn != self.packet_counter:
            self.myturn += 1

        pkt.set_payload(bytes(ip_packet))
        pkt.accept()

    def debug_step(self):
        """Signal the capture thread to release the next packet."""
        self._debug_event.set()

    def automod_packets(self, spacket, search, replace):

        pktHex = hexlify(bytes(spacket))

        if search.lower() in str(pktHex).lower():

            pktHex = pktHex.replace(search.lower().encode(), replace.lower().encode())

        spacketbytes = unhexlify(pktHex)
        spacket = IPv6(spacketbytes) if (spacketbytes and spacketbytes[0] >> 4 == 6) else IP(spacketbytes)

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

    def run(self, iface, port_filter=None):
        """Intercept mode: route traffic through NFQUEUE for modify/drop/forward."""
        self._port_filter = port_filter
        filter(mitm=True, i=iface)
        self.is_started = True
        nfqueue = NetfilterQueue()
        nfqueue.bind(0, self.procesar_paquete)
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            nfqueue.unbind()
            flush()

    def run_windivert(self, iface, port_filter=None):
        """Windows intercept mode: hold every IP packet via WinDivert, allow
        modify/drop, then reinject.  Requires the WinDivert driver and pydivert.

        Per-interface filtering uses the Windows adapter index.  Falls back to
        capturing all traffic when the index cannot be determined.
        """
        self._port_filter = port_filter

        # Build WinDivert filter string.
        parts = []
        if iface != "Any...":
            try:
                idx = socket.if_nametoindex(iface)
                parts.append(f"ifIdx == {idx}")
            except (AttributeError, OSError):
                pass
        if port_filter:
            port_clauses = " or ".join(
                f"tcp.DstPort == {p} or tcp.SrcPort == {p} or "
                f"udp.DstPort == {p} or udp.SrcPort == {p}"
                for p in port_filter
            )
            parts.append(f"({port_clauses})")
        wd_filter = " and ".join(parts) if parts else "true"

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
                        _raw = bytes(packet.raw)
                        _ver = (_raw[0] >> 4) if _raw else 4
                        ip_pkt = IPv6(_raw) if _ver == 6 else IP(_raw)
                    except Exception:
                        try:
                            w.send(packet)
                        except Exception:
                            pass
                        continue

                    self.packet_counter += 1

                    QMetaObject.invokeMethod(
                        self.parent, "push_packets",
                        Qt.BlockingQueuedConnection,
                        Q_ARG("PyQt_PyObject", ip_pkt),
                        Q_ARG("PyQt_PyObject", "null"),
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

                    packet.raw = memoryview(bytearray(bytes(ip_pkt)))
                    try:
                        w.send(packet)
                    except Exception as exc:
                        logger.warning("WinDivert send failed: %s", exc)

        except Exception as exc:
            logger.error("WinDivert error: %s", exc)

    def run_sniff(self, iface, bpf_filter=None):
        """Passive sniff mode: capture full L2 frames via raw socket (read-only)."""
        self._port_filter = None  # not needed; BPF handles it at capture level
        self.is_started = True
        iface_arg = None if iface == "Any..." else iface
        kwargs = dict(iface=iface_arg, prn=self._handle_sniffed_packet, store=False)
        if bpf_filter:
            kwargs['filter'] = bpf_filter
        self._sniffer = AsyncSniffer(**kwargs)
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
            Q_ARG("PyQt_PyObject", "null"),
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
