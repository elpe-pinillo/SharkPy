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


def _drain_http_headers(sock):
    """Read and discard HTTP headers until the blank line (\\r\\n\\r\\n)."""
    buf = b''
    while b'\r\n\r\n' not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk


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

    # hostname, conn_id, port, direction ('→'/'←'), raw_bytes
    data_intercepted = pyqtSignal(str, int, int, str, bytes)

    def __init__(self, ca_manager, listen_port: int = 8443, parent=None):
        super().__init__(parent)
        self.ca_manager  = ca_manager
        self.listen_port = listen_port
        self.running     = False
        self._sock       = None
        self._thread     = None
        self._conn_counter = 0
        self._conn_lock    = threading.Lock()

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
                except OSError:
                    break
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

    def _next_conn_id(self) -> int:
        with self._conn_lock:
            self._conn_counter += 1
            return self._conn_counter

    # ── per-connection handler ────────────────────────────────────────────────

    def _handle(self, raw_sock: socket.socket):
        client_ssl = None
        real_ssl   = None
        conn_id    = self._next_conn_id()
        try:
            raw_sock.settimeout(10)

            # ── Detect HTTP CONNECT (explicit proxy) vs direct TLS (transparent) ──
            peek = raw_sock.recv(8, socket.MSG_PEEK)
            if peek.upper().startswith(b'CONNECT '):
                hostname, dst_port = self._read_connect(raw_sock)
                if hostname is None:
                    return
                # Consume the rest of the CONNECT headers
                _drain_http_headers(raw_sock)
                raw_sock.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            else:
                # Transparent mode: iptables redirected the connection here
                dst_ip, dst_port = get_original_dst(raw_sock)
                dst_port = dst_port or 443
                try:
                    peek2 = raw_sock.recv(4096, socket.MSG_PEEK)
                    hostname = extract_sni(peek2)
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
                real_raw = socket.create_connection((hostname, dst_port), timeout=10)
                real_ssl = cli_ctx.wrap_socket(real_raw, server_hostname=hostname)
                real_ssl.settimeout(30)
            except Exception as exc:
                logger.warning("Cannot reach %s:%s — %s", hostname, dst_port, exc)
                return

            # Relay in both directions simultaneously
            done = threading.Event()
            t1 = threading.Thread(
                target=self._relay,
                args=(client_ssl, real_ssl, hostname, dst_port, conn_id, '→', done),
                daemon=True,
            )
            t2 = threading.Thread(
                target=self._relay,
                args=(real_ssl, client_ssl, hostname, dst_port, conn_id, '←', done),
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

    @staticmethod
    def _read_connect(sock) -> tuple:
        """Read the CONNECT request line; return (hostname, port) or (None, None)."""
        buf = b''
        while b'\r\n' not in buf:
            chunk = sock.recv(256)
            if not chunk:
                return None, None
            buf += chunk
        first_line = buf.split(b'\r\n')[0].decode(errors='replace')
        try:
            _, target, _ = first_line.split(' ', 2)
            host, _, port_str = target.rpartition(':')
            return host, int(port_str) if port_str else 443
        except Exception:
            return None, None

    def _relay(self, src, dst, hostname: str, port: int, conn_id: int,
               direction: str, done: threading.Event):
        try:
            while not done.is_set():
                try:
                    chunk = src.recv(65536)
                except ssl.SSLError:
                    break
                if not chunk:
                    break
                dst.sendall(chunk)
                self.data_intercepted.emit(hostname, conn_id, port, direction, bytes(chunk))
        except (OSError, ssl.SSLError):
            pass
        finally:
            done.set()
            try:
                dst.close()
            except Exception:
                pass
