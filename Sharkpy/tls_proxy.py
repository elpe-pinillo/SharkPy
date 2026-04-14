# -*- coding: utf-8 -*-
"""
SharkPy TLS Proxy
Transparent TLS MITM proxy.  iptables (Linux) or WinDivert (Windows) redirects
port-443 traffic to our listen_port.  For each TCP connection we:
  1. Use MSG_PEEK on the raw socket to read the ClientHello and extract SNI.
  2. Generate (or reuse a cached) per-host certificate signed by our CA.
  3. Complete the TLS handshake with the client using the forged cert.
  4. Open a real TLS connection to the original server.
  5. Relay traffic bidirectionally, emitting plaintext via Qt signal.
"""

import ssl
import sys
import socket
import struct
import threading
import logging

from PyQt5.QtCore import QObject, pyqtSignal

logger = logging.getLogger(__name__)

_SO_ORIGINAL_DST = 80   # Linux: getsockopt level SOL_IP


# ── helpers ───────────────────────────────────────────────────────────────────

def extract_sni(data: bytes):
    """Parse the SNI hostname out of raw TLS ClientHello bytes.
    Returns the hostname string, or None if not found / not parseable."""
    try:
        # TLS record: content_type(1) version(2) length(2)
        if len(data) < 5 or data[0] != 0x16:        # 0x16 = Handshake
            return None
        pos = 5
        if data[pos] != 0x01:                        # 0x01 = ClientHello
            return None
        pos += 4                                     # type(1) + length(3)
        pos += 2 + 32                                # client_version + random
        sid_len = data[pos]; pos += 1 + sid_len      # session_id
        cs_len  = int.from_bytes(data[pos:pos+2], 'big'); pos += 2 + cs_len
        cm_len  = data[pos]; pos += 1 + cm_len       # compression_methods
        if pos + 2 > len(data):
            return None
        ext_end = pos + 2 + int.from_bytes(data[pos:pos+2], 'big'); pos += 2
        while pos + 4 <= ext_end:
            ext_type = int.from_bytes(data[pos:pos+2], 'big')
            ext_len  = int.from_bytes(data[pos+2:pos+4], 'big')
            pos += 4
            if ext_type == 0 and pos + 5 <= ext_end:   # SNI extension (type 0)
                # sni_list_length(2) + sni_type(1) + sni_name_length(2) + name
                name_len = int.from_bytes(data[pos+3:pos+5], 'big')
                return data[pos+5:pos+5+name_len].decode('ascii', errors='replace')
            pos += ext_len
    except (IndexError, struct.error):
        pass
    return None


def get_original_dst(sock):
    """Return (ip_str, port) of the original destination before iptables REDIRECT.
    Returns (None, None) on Windows or if the socket option is unavailable."""
    if sys.platform == 'win32':
        return None, None
    try:
        raw = sock.getsockopt(socket.SOL_IP, _SO_ORIGINAL_DST, 16)
        port = struct.unpack_from('!2xH', raw)[0]
        ip   = socket.inet_ntoa(raw[4:8])
        return ip, port
    except OSError:
        return None, None


# ── proxy ─────────────────────────────────────────────────────────────────────

class TLSProxy(QObject):
    """
    Transparent TLS MITM proxy.

    Signals
    -------
    data_intercepted(hostname, direction, raw_bytes)
        Emitted for every chunk of plaintext relayed.
        direction is '→' (client→server) or '←' (server→client).
        Safe to connect to GUI slots — emitted from worker threads but
        PyQt5 automatically queues cross-thread signal delivery.
    """

    data_intercepted = pyqtSignal(str, str, bytes)

    def __init__(self, ca_manager, listen_port: int = 8443, parent=None):
        super().__init__(parent)
        self.ca_manager  = ca_manager
        self.listen_port = listen_port
        self.running     = False
        self._sock       = None
        self._thread     = None

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(
            target=self._accept_loop, daemon=True, name='TLSProxy-accept'
        )
        self._thread.start()
        logger.info("TLS proxy started on 127.0.0.1:%d", self.listen_port)

    def stop(self):
        self.running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        logger.info("TLS proxy stopped")

    # ── accept loop ───────────────────────────────────────────────────────────

    def _accept_loop(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(('127.0.0.1', self.listen_port))
            self._sock.listen(64)
            self._sock.settimeout(1.0)
            while self.running:
                try:
                    client_sock, addr = self._sock.accept()
                except socket.timeout:
                    continue
                threading.Thread(
                    target=self._handle,
                    args=(client_sock,),
                    daemon=True,
                    name=f'TLSProxy-{addr}',
                ).start()
        except Exception as exc:
            logger.error("Accept loop error: %s", exc)
        finally:
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass

    # ── per-connection handler ────────────────────────────────────────────────

    def _handle(self, raw_sock: socket.socket):
        client_ssl = None
        real_ssl   = None
        try:
            raw_sock.settimeout(10)

            # Where was this packet originally headed?
            dst_ip, dst_port = get_original_dst(raw_sock)
            dst_port = dst_port or 443

            # Peek at ClientHello to get SNI without consuming bytes
            try:
                peek = raw_sock.recv(4096, socket.MSG_PEEK)
                hostname = extract_sni(peek)
            except Exception:
                hostname = None
            hostname = hostname or dst_ip or 'unknown'

            # Build (or reuse) a per-host SSL context with a forged cert
            try:
                srv_ctx = self.ca_manager.get_ssl_context(hostname)
            except Exception as exc:
                logger.warning("Cert generation failed for %s: %s", hostname, exc)
                return

            # TLS handshake with the client (they see our forged cert)
            try:
                client_ssl = srv_ctx.wrap_socket(raw_sock, server_side=True)
                client_ssl.settimeout(30)
            except ssl.SSLError as exc:
                logger.debug("Client handshake failed (%s): %s", hostname, exc)
                return

            # Real TLS connection to the destination server
            try:
                cli_ctx  = ssl.create_default_context()
                real_raw = socket.create_connection(
                    (dst_ip or hostname, dst_port), timeout=10
                )
                real_ssl = cli_ctx.wrap_socket(real_raw, server_hostname=hostname)
                real_ssl.settimeout(30)
            except Exception as exc:
                logger.warning("Cannot reach %s:%s — %s", hostname, dst_port, exc)
                return

            # Relay in both directions simultaneously
            done = threading.Event()
            t1 = threading.Thread(
                target=self._relay,
                args=(client_ssl, real_ssl, hostname, '→', done),
                daemon=True,
            )
            t2 = threading.Thread(
                target=self._relay,
                args=(real_ssl, client_ssl, hostname, '←', done),
                daemon=True,
            )
            t1.start()
            t2.start()
            t1.join()
            t2.join()

        except Exception as exc:
            logger.debug("Handler error: %s", exc)
        finally:
            for s in (client_ssl, real_ssl, raw_sock):
                try:
                    s.close()
                except Exception:
                    pass

    def _relay(self, src, dst, hostname: str, direction: str, done: threading.Event):
        try:
            while not done.is_set():
                try:
                    chunk = src.recv(65536)
                except ssl.SSLError:
                    break
                if not chunk:
                    break
                dst.sendall(chunk)
                # Emit to Qt main thread (cross-thread signal delivery is automatic)
                self.data_intercepted.emit(hostname, direction, bytes(chunk))
        except (OSError, ssl.SSLError):
            pass
        finally:
            done.set()
            try:
                dst.close()
            except Exception:
                pass
