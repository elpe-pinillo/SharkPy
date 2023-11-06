from binascii import hexlify, unhexlify

from netfilterqueue import NetfilterQueue
from scapy.all import *
from p_firewall import *
import ctypes


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

    def procesar_paquete(self, pkt):
        """
        This function is executed whenever a packet is sniffed
        """
        if self.is_started:
            # Parser el paquete con Scapy
            ether_packet = Ether(pkt.get_payload())
            del ether_packet[Raw]
            ip_packet = IP(pkt.get_payload())
            spacket = ip_packet

            self.packet_counter += 1
            self.parent.push_packets(ip_packet)

            # Loop for debugging and ordering packets
            while ((self.myturn != self.packet_counter) & self.parent.debugmode):
                if not (self.is_started):
                    raise KeyboardInterrupt
                pass

            ip_packet = self.parent.packet_list[self.packet_counter - 1]    # This is just to synchronize gui with core

            if (self.myturn != self.packet_counter):
                self.myturn += 1

            if self.automod:
                ip_packet = self.automod_packets(spacket, self.parent.textEdit.toPlainText(),
                                             self.parent.textEdit_2.toPlainText())
                self.parent.push_packets(ip_packet)

            pkt.set_payload(bytes(ip_packet))
            pkt.accept()

        else:
            raise KeyboardInterrupt

    def automod_packets(self, spacket, search, replace):
        # Modificar el paquete
        pktHex = hexlify(bytes(spacket))
        if search in str(pktHex):
            pktHex = pktHex.replace(search.encode(), replace.encode())
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
        filter(mitm="false", i=iface)
        self.is_started = True
        nfqueue = NetfilterQueue()
        nfqueue.bind(0, self.procesar_paquete)
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            nfqueue.unbind()
            flush()
            # El flush tiene que ir despues de la interrupcion porque es la unica forma que tengo de que el
            # hilo se mate. Stop modifica el valor is_started para que sea el mismo hilo el que lance la excecpion.
            # Sino no puedo lanzar la excepcion a otro hilo. Tiene que ser el.




    def stop(self):
        print("Deteniendo el procesamiento de paquetes...")
        self.is_started = False

