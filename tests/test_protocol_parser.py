# -*- coding: utf-8 -*-
"""
Unit tests for protocol_parser helper functions.

Tests use actual scapy packet construction so the logic is exercised end-to-end.
No network access, no root, no display server required.
"""

import sys
import os
import unittest

# Allow import from the Sharkpy package without an installed package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, Raw  # noqa: E402
from Sharkpy.protocol_parser import (                              # noqa: E402
    get_protocol, packet_src, packet_dst, packet_len
)


class TestGetProtocol(unittest.TestCase):

    # ── TCP-based protocols ─────────────────────────────────────────────────

    def test_http_by_dport(self):
        pkt = Ether() / IP() / TCP(dport=80)
        self.assertEqual(get_protocol(pkt), 'HTTP')

    def test_http_by_sport(self):
        # Server-originated flow: sport=80
        pkt = Ether() / IP() / TCP(sport=80, dport=54321)
        self.assertEqual(get_protocol(pkt), 'HTTP')

    def test_https_by_dport(self):
        pkt = Ether() / IP() / TCP(dport=443)
        self.assertEqual(get_protocol(pkt), 'HTTPS')

    def test_https_by_sport(self):
        pkt = Ether() / IP() / TCP(sport=443, dport=12345)
        self.assertEqual(get_protocol(pkt), 'HTTPS')

    def test_ssh(self):
        pkt = Ether() / IP() / TCP(dport=22)
        self.assertEqual(get_protocol(pkt), 'SSH')

    def test_ftp(self):
        pkt = Ether() / IP() / TCP(dport=21)
        self.assertEqual(get_protocol(pkt), 'FTP')

    def test_smtp(self):
        pkt = Ether() / IP() / TCP(dport=25)
        self.assertEqual(get_protocol(pkt), 'SMTP')

    def test_rdp(self):
        pkt = Ether() / IP() / TCP(dport=3389)
        self.assertEqual(get_protocol(pkt), 'RDP')

    def test_mysql(self):
        pkt = Ether() / IP() / TCP(dport=3306)
        self.assertEqual(get_protocol(pkt), 'MySQL')

    def test_unknown_tcp_port_returns_tcp(self):
        pkt = Ether() / IP() / TCP(dport=9999)
        self.assertEqual(get_protocol(pkt), 'TCP')

    # ── UDP-based protocols ─────────────────────────────────────────────────

    def test_dns_udp(self):
        pkt = Ether() / IP() / UDP(dport=53)
        self.assertEqual(get_protocol(pkt), 'DNS')

    def test_dns_tcp(self):
        # DNS over TCP (zone transfer / large responses)
        pkt = Ether() / IP() / TCP(dport=53)
        self.assertEqual(get_protocol(pkt), 'DNS')

    def test_dhcp_udp(self):
        pkt = Ether() / IP() / UDP(dport=67)
        self.assertEqual(get_protocol(pkt), 'DHCP')

    def test_ntp(self):
        pkt = Ether() / IP() / UDP(dport=123)
        self.assertEqual(get_protocol(pkt), 'NTP')

    def test_unknown_udp_port_returns_udp(self):
        # Use a port not in _UDP_PORTS and not auto-decoded by scapy as DNS
        pkt = Ether() / IP() / UDP(dport=9000, sport=9001)
        self.assertEqual(get_protocol(pkt), 'UDP')

    # ── Other layer-3 protocols ─────────────────────────────────────────────

    def test_icmp(self):
        pkt = Ether() / IP() / ICMP()
        self.assertEqual(get_protocol(pkt), 'ICMP')

    def test_arp(self):
        pkt = Ether() / ARP()
        self.assertEqual(get_protocol(pkt), 'ARP')

    def test_plain_ip_returns_ip(self):
        # IP packet with no transport layer scapy recognises
        pkt = IP() / Raw(b'\x00' * 4)
        self.assertEqual(get_protocol(pkt), 'IP')


class TestPacketSrc(unittest.TestCase):

    def test_ipv4_src(self):
        pkt = Ether() / IP(src='10.0.0.1') / TCP(dport=80)
        self.assertEqual(packet_src(pkt), '10.0.0.1')

    def test_ipv6_src(self):
        pkt = Ether() / IPv6(src='::1') / TCP(dport=80)
        self.assertEqual(packet_src(pkt), '::1')

    def test_arp_src(self):
        pkt = Ether() / ARP(psrc='192.168.1.50')
        self.assertEqual(packet_src(pkt), '192.168.1.50')

    def test_ethernet_only_src(self):
        pkt = Ether(src='aa:bb:cc:dd:ee:ff')
        self.assertEqual(packet_src(pkt), 'aa:bb:cc:dd:ee:ff')

    def test_no_recognised_layer_returns_na(self):
        from scapy.packet import Raw
        pkt = Raw(b'\xff\xff\xff\xff')
        self.assertEqual(packet_src(pkt), 'N/A')


class TestPacketDst(unittest.TestCase):

    def test_ipv4_dst(self):
        pkt = Ether() / IP(dst='8.8.8.8') / UDP(dport=53)
        self.assertEqual(packet_dst(pkt), '8.8.8.8')

    def test_ipv6_dst(self):
        pkt = Ether() / IPv6(dst='2001:db8::1') / TCP(dport=443)
        self.assertEqual(packet_dst(pkt), '2001:db8::1')

    def test_arp_dst(self):
        pkt = Ether() / ARP(pdst='192.168.1.1')
        self.assertEqual(packet_dst(pkt), '192.168.1.1')

    def test_ethernet_only_dst(self):
        pkt = Ether(dst='ff:ff:ff:ff:ff:ff')
        self.assertEqual(packet_dst(pkt), 'ff:ff:ff:ff:ff:ff')


class TestPacketLen(unittest.TestCase):

    def test_ipv4_len_matches_ip_field(self):
        pkt = IP(src='1.2.3.4', dst='5.6.7.8') / TCP(dport=80) / Raw(b'GET / HTTP/1.0\r\n\r\n')
        # scapy fills IP.len automatically; packet_len should return it
        built = IP(bytes(pkt))  # force scapy to compute fields
        self.assertEqual(packet_len(built), built[IP].len)

    def test_fallback_to_raw_length(self):
        # Raw packet without IP or IPv6 layer — should return len(pkt)
        from scapy.packet import Raw
        payload = b'ABCDEFGHIJ'
        pkt = Raw(payload)
        self.assertEqual(packet_len(pkt), len(pkt))

    def test_ipv4_minimum_packet(self):
        pkt = IP() / ICMP()
        built = IP(bytes(pkt))
        self.assertGreater(packet_len(built), 0)

    def test_different_payloads_change_length(self):
        small = IP(bytes(IP() / TCP(dport=80) / Raw(b'X' * 10)))
        large = IP(bytes(IP() / TCP(dport=80) / Raw(b'X' * 500)))
        self.assertLess(packet_len(small), packet_len(large))


class TestRoundtrip(unittest.TestCase):
    """Integration-style: build packets and check all three helpers together."""

    def test_http_packet(self):
        pkt = IP(src='192.168.1.10', dst='93.184.216.34') / TCP(sport=54321, dport=80) / Raw(b'GET / HTTP/1.1\r\n')
        built = IP(bytes(pkt))
        self.assertEqual(get_protocol(built), 'HTTP')
        self.assertEqual(packet_src(built), '192.168.1.10')
        self.assertEqual(packet_dst(built), '93.184.216.34')
        self.assertGreater(packet_len(built), 0)

    def test_dns_packet(self):
        pkt = IP(src='10.0.0.5', dst='8.8.8.8') / UDP(sport=12345, dport=53) / Raw(b'\x00' * 12)
        built = IP(bytes(pkt))
        self.assertEqual(get_protocol(built), 'DNS')
        self.assertEqual(packet_src(built), '10.0.0.5')
        self.assertEqual(packet_dst(built), '8.8.8.8')

    def test_icmp_packet(self):
        pkt = IP(src='172.16.0.1', dst='172.16.0.2') / ICMP(type=8, code=0)
        built = IP(bytes(pkt))
        self.assertEqual(get_protocol(built), 'ICMP')
        self.assertEqual(packet_src(built), '172.16.0.1')
        self.assertEqual(packet_dst(built), '172.16.0.2')

    def test_arp_packet(self):
        pkt = Ether(src='aa:bb:cc:00:00:01', dst='ff:ff:ff:ff:ff:ff') / ARP(psrc='10.0.0.1', pdst='10.0.0.2')
        self.assertEqual(get_protocol(pkt), 'ARP')
        self.assertEqual(packet_src(pkt), '10.0.0.1')
        self.assertEqual(packet_dst(pkt), '10.0.0.2')


if __name__ == '__main__':
    unittest.main()
