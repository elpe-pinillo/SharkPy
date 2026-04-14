# -*- coding: utf-8 -*-
"""
Unit tests for tls_proxy helper functions.

These tests require NO network access, NO root privileges, and NO display
server.  They exercise extract_sni() and get_original_dst() using crafted
byte literals and mock sockets.
"""

import sys
import os
import struct
import unittest
from unittest.mock import MagicMock, patch

# Allow import from the Sharkpy package without an installed package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# PyQt5 is not needed for these helpers, but tls_proxy imports it at module
# level for the signal definition.  Stub it out before importing.
qt_stub = MagicMock()
sys.modules.setdefault('PyQt5', qt_stub)
sys.modules.setdefault('PyQt5.QtCore', qt_stub)

from Sharkpy.tls_proxy import extract_sni, get_original_dst  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers to build a minimal, well-formed TLS ClientHello containing an SNI
# ---------------------------------------------------------------------------

def _build_client_hello(hostname: str) -> bytes:
    """
    Build a minimal TLS 1.0 ClientHello that includes only a server_name
    extension for *hostname*.  The output is a complete TLS record (including
    the 5-byte record header) and passes the extract_sni() parser.
    """
    hostname_bytes = hostname.encode('ascii')
    name_len = len(hostname_bytes)

    # SNI extension body:  sni_list_length(2) + type(1) + name_length(2) + name
    sni_body = (
        struct.pack('!H', 1 + 2 + name_len)  # list length
        + b'\x00'                             # name type = host_name
        + struct.pack('!H', name_len)
        + hostname_bytes
    )
    # Extension: type=0x0000 (SNI), length, body
    extension = struct.pack('!HH', 0x0000, len(sni_body)) + sni_body
    extensions_block = struct.pack('!H', len(extension)) + extension

    # Random: 32 bytes of zeros
    random_bytes = b'\x00' * 32

    # Build ClientHello body (after the handshake header):
    #   client_version(2) random(32) session_id_len(1)
    #   cipher_suites_len(2) cipher_suite(2) compression_methods_len(1)
    #   compression_method(1) extensions
    hello_body = (
        b'\x03\x03'       # TLS 1.2 client_version
        + random_bytes
        + b'\x00'         # session_id length = 0
        + struct.pack('!H', 2)   # cipher_suites length = 2 (one suite)
        + b'\xc0\x2c'    # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        + b'\x01'         # compression_methods length = 1
        + b'\x00'         # null compression
        + extensions_block
    )

    # Handshake header: type(1) + length(3)
    handshake = b'\x01' + struct.pack('!I', len(hello_body))[1:] + hello_body

    # TLS record header: content_type(1) version(2) length(2)
    record = b'\x16\x03\x01' + struct.pack('!H', len(handshake)) + handshake

    return record


# ---------------------------------------------------------------------------
# Pre-built byte literal for example.com — keeps tests self-contained even if
# the helper above is ever changed.  Generated with _build_client_hello().
# ---------------------------------------------------------------------------
EXAMPLE_COM_CLIENT_HELLO = (
    b'\x16\x03\x01\x00\x47'          # TLS record header (71 bytes)
    b'\x01'                           # Handshake type: ClientHello
    b'\x00\x00\x43'                   # Handshake length: 67
    b'\x03\x03'                       # Client version: TLS 1.2
    + b'\x00' * 32                    # Random
    + b'\x00'                         # Session ID length: 0
    b'\x00\x02'                       # Cipher suites length: 2
    b'\xc0\x2c'                       # Cipher suite
    b'\x01'                           # Compression methods length: 1
    b'\x00'                           # Null compression
    b'\x00\x1a'                       # Extensions length: 26
    b'\x00\x00'                       # Extension type: SNI (0)
    b'\x00\x16'                       # Extension length: 22
    b'\x00\x14'                       # SNI list length: 20
    b'\x00'                           # SNI name type: host_name
    b'\x00\x11'                       # SNI name length: 17
    b'www.example.com'                # Hostname (15 bytes — corrected below)
)

# Use the builder for reliability; the literal above is illustrative only.
EXAMPLE_COM_HELLO = _build_client_hello('example.com')
WWW_EXAMPLE_HELLO = _build_client_hello('www.example.com')


class TestExtractSni(unittest.TestCase):

    # --- happy-path tests ---------------------------------------------------

    def test_extracts_example_com(self):
        result = extract_sni(EXAMPLE_COM_HELLO)
        self.assertEqual(result, 'example.com')

    def test_extracts_www_example_com(self):
        result = extract_sni(WWW_EXAMPLE_HELLO)
        self.assertEqual(result, 'www.example.com')

    def test_extracts_long_hostname(self):
        hostname = 'very.deep.subdomain.example.co.uk'
        data = _build_client_hello(hostname)
        self.assertEqual(extract_sni(data), hostname)

    # --- rejection / robustness tests ---------------------------------------

    def test_returns_none_for_empty_bytes(self):
        self.assertIsNone(extract_sni(b''))

    def test_returns_none_for_non_tls_data(self):
        # HTTP request — content type byte is 0x47 ('G'), not 0x16
        self.assertIsNone(extract_sni(b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'))

    def test_returns_none_for_tls_application_data(self):
        # content_type 0x17 = Application Data (not a Handshake record)
        self.assertIsNone(extract_sni(b'\x17\x03\x03' + b'\x00\x10' + b'\xab' * 16))

    def test_returns_none_for_truncated_record(self):
        self.assertIsNone(extract_sni(b'\x16\x03\x01'))  # only 3 bytes

    def test_returns_none_for_server_hello(self):
        # Handshake type 0x02 = ServerHello, not ClientHello
        data = b'\x16\x03\x01\x00\x05' + b'\x02\x00\x00\x01\x00'
        self.assertIsNone(extract_sni(data))

    def test_returns_none_for_random_bytes(self):
        self.assertIsNone(extract_sni(b'\xde\xad\xbe\xef' * 20))

    def test_returns_none_for_all_zeros(self):
        self.assertIsNone(extract_sni(b'\x00' * 100))


class TestGetOriginalDst(unittest.TestCase):

    def test_returns_none_none_on_windows(self):
        with patch('sys.platform', 'win32'):
            # Re-import to pick up patched platform; easier to test directly
            import importlib
            import Sharkpy.tls_proxy as mod
            original = mod.sys.platform
            mod.sys.platform = 'win32'
            try:
                ip, port = get_original_dst(MagicMock())
                self.assertIsNone(ip)
                self.assertIsNone(port)
            finally:
                mod.sys.platform = original

    def test_returns_none_none_on_oserror(self):
        """If getsockopt raises OSError (e.g. no REDIRECT rule), return (None, None)."""
        mock_sock = MagicMock()
        mock_sock.getsockopt.side_effect = OSError("no such option")
        ip, port = get_original_dst(mock_sock)
        self.assertIsNone(ip)
        self.assertIsNone(port)

    def test_parses_sockopt_correctly(self):
        """Verify the struct layout: 2-byte pad, 2-byte port (big-endian), 4-byte IP."""
        import socket as _socket
        # Craft a 16-byte SO_ORIGINAL_DST response for 93.184.216.34:443
        expected_ip = '93.184.216.34'
        expected_port = 443
        raw = (
            b'\x00\x00'                              # 2 padding bytes
            + struct.pack('!H', expected_port)       # port big-endian
            + _socket.inet_aton(expected_ip)         # 4-byte IP
            + b'\x00' * 8                            # remaining padding
        )
        mock_sock = MagicMock()
        mock_sock.getsockopt.return_value = raw

        with patch('sys.platform', 'linux'):
            import Sharkpy.tls_proxy as mod
            saved = mod.sys.platform
            mod.sys.platform = 'linux'
            try:
                ip, port = get_original_dst(mock_sock)
                self.assertEqual(ip, expected_ip)
                self.assertEqual(port, expected_port)
            finally:
                mod.sys.platform = saved


if __name__ == '__main__':
    unittest.main()
