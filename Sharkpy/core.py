from binascii import hexlify, unhexlify
import socket
import netifaces
from netfilterqueue import NetfilterQueue
from scapy.all import *
from p_firewall import *

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

            ip_packet = self.parent.packet_list[self.packet_counter - 1]  # This is just to synchronize gui with core

            if (self.myturn != self.packet_counter):
                self.myturn += 1

            if self.automod:
                if self.parent.outputCheckBox_2.isChecked():
                    for ip in self.get_source_ip():
                        if spacket[IP].src == ip:
                            ip_packet = self.automod_packets(spacket, self.parent.textEdit.toPlainText(),
                                                             self.parent.textEdit_2.toPlainText())
                            self.parent.push_packets(ip_packet, self.packet_counter - 1)

                if self.parent.InputCheckBox.isChecked():
                    for ip in self.get_source_ip():
                        if spacket[IP].dst == ip:
                            ip_packet = self.automod_packets(spacket, self.parent.textEdit.toPlainText(),
                                                             self.parent.textEdit_2.toPlainText())
                            self.parent.push_packets(ip_packet, self.packet_counter - 1)

                if self.parent.forwardCheckBox_3.isChecked():
                    ip_packet = self.automod_packets(spacket, self.parent.textEdit.toPlainText(),
                                                     self.parent.textEdit_2.toPlainText())
                    self.parent.push_packets(ip_packet, self.packet_counter - 1)

            pkt.set_payload(bytes(ip_packet))
            pkt.accept()

        else:
            raise KeyboardInterrupt

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
        filter(mitm=True, i=iface)
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
        print("Deteniendo el procesamiento de paquetes...")
        flush()
        self.is_started = False
