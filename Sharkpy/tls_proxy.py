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
    """Return (ip_str, port) of the original destination before redirect.
    On Linux reads SO_ORIGINAL_DST; on Windows queries the WinDivert table."""
    if sys.platform == 'win32':
        try:
            from p_firewall_win import get_original_dst_win
            client_src_port = sock.getpeername()[1]
            return get_original_dst_win(client_src_port)
        except Exception:
            return None, None
    try:
        raw = sock.getsockopt(socket.SOL_IP, _SO_ORIGINAL_DST, 16)
        port = struct.unpack_from('!2xH', raw)[0]
        ip   = socket.inet_ntoa(raw[4:8])
        return ip, port
    except OSError:
        return None, None


def _make_socket_pair():
    """Return a connected (s1, s2) socket pair — works on all platforms."""
    try:
        return socket.socketpair()
    except (OSError, AttributeError):
        # Windows Python < 3.12: socketpair not available; emulate via loopback
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('127.0.0.1', 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        s1 = socket.create_connection(('127.0.0.1', port))
        s2, _ = srv.accept()
        srv.close()
        return s1, s2


# ── TDS (MSSQL) wire helpers ──────────────────────────────────────────────────

def _recv_exactly(sock, n: int) -> bytes:
    """Receive exactly n bytes; raise ConnectionError on premature EOF."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk
    return bytes(buf)


def _recv_tds_packet(sock) -> bytes:
    """Read one complete TDS packet (8-byte header + payload)."""
    hdr = _recv_exactly(sock, 8)
    pkt_len = int.from_bytes(hdr[2:4], 'big')
    if pkt_len < 8:
        raise ValueError(f"Invalid TDS packet length: {pkt_len}")
    return hdr + _recv_exactly(sock, pkt_len - 8)


def _tds_wrap(payload: bytes, seq: int = 1) -> bytes:
    """Wrap a raw TLS record as a TDS Pre-Login (type=0x12) packet."""
    n = 8 + len(payload)
    return bytes([0x12, 0x01, n >> 8, n & 0xFF, 0, 0, seq & 0xFF, 0]) + payload


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
            elif peek and peek[0] == 0x12:
                # MSSQL: TDS Pre-Login packet — hand off to MSSQL handler
                self._handle_mssql(raw_sock, conn_id)
                return
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

    # ── MSSQL / TDS interception ──────────────────────────────────────────────

    def _handle_mssql(self, raw_sock: socket.socket, conn_id: int):
        """
        MSSQL interception entry point.

        Flow:
          1. Relay TDS Pre-Login exchange (plain bytes, no TLS yet).
          2. Peek at what follows to decide mode:
             - 0x16  → raw TLS after Pre-Login  (some drivers / Encrypt=strict)
             - 0x12  → TDS-wrapped TLS handshake (most common: ODBC Driver 17/18)
             - other → unencrypted plain TDS
        """
        server_sock = None
        dst_ip, dst_port = get_original_dst(raw_sock)
        dst_port = dst_port or 1433
        hostname = dst_ip or 'mssql-server'

        if dst_ip is None:
            logger.debug("MSSQL intercept: original destination unknown — is the intercept rule active?")
            try: raw_sock.close()
            except Exception: pass
            return

        try:
            raw_sock.settimeout(15)
            server_sock = socket.create_connection((dst_ip, dst_port), timeout=10)
            server_sock.settimeout(15)

            # Relay Pre-Login: client → server, server → client
            prelogin = _recv_tds_packet(raw_sock)
            server_sock.sendall(prelogin)
            prelogin_resp = _recv_tds_packet(server_sock)
            raw_sock.sendall(prelogin_resp)

            # Detect what follows
            next_b = raw_sock.recv(1, socket.MSG_PEEK)
            if not next_b:
                return
            fb = next_b[0]

            if fb == 0x16:
                self._mssql_raw_tls(raw_sock, server_sock, hostname, dst_port, conn_id)
            elif fb == 0x12:
                self._mssql_tds_tls(raw_sock, server_sock, hostname, dst_port, conn_id)
            else:
                self._mssql_plain(raw_sock, server_sock, hostname, dst_port, conn_id)

        except Exception as exc:
            logger.debug("MSSQL handler error (%s:%s): %s", dst_ip, dst_port, exc)
        finally:
            if server_sock:
                try:
                    server_sock.close()
                except Exception:
                    pass
            try:
                raw_sock.close()
            except Exception:
                pass

    def _mssql_raw_tls(self, client_sock, server_raw, hostname, port, conn_id):
        """Standard TLS MITM — raw TLS immediately after Pre-Login."""
        client_ssl = server_ssl = None
        try:
            ctx = self.ca_manager.get_ssl_context(hostname)
            client_ssl = ctx.wrap_socket(client_sock, server_side=True)
            client_ssl.settimeout(30)

            cli_ctx = ssl.create_default_context()
            cli_ctx.check_hostname = False
            cli_ctx.verify_mode = ssl.CERT_NONE
            server_ssl = cli_ctx.wrap_socket(server_raw, server_hostname=hostname)
            server_ssl.settimeout(30)

            done = threading.Event()
            t1 = threading.Thread(target=self._relay,
                args=(client_ssl, server_ssl, hostname, port, conn_id, '→', done), daemon=True)
            t2 = threading.Thread(target=self._relay,
                args=(server_ssl, client_ssl, hostname, port, conn_id, '←', done), daemon=True)
            t1.start(); t2.start()
            t1.join(); t2.join()
        except Exception as exc:
            logger.debug("MSSQL raw-TLS error: %s", exc)
        finally:
            for s in (client_ssl, server_ssl):
                if s:
                    try: s.close()
                    except Exception: pass

    def _mssql_tds_tls(self, client_sock, server_sock, hostname, port, conn_id):
        """
        TLS MITM where the TLS handshake is wrapped inside TDS Pre-Login (0x12) frames.
        This is the default for ODBC Driver 17/18 and most SQL Server installations.

        Uses socketpairs to bridge between TDS-framed sockets (client/server) and
        the raw-TLS sockets that Python's ssl module operates on.

             client_sock ←TDS→ [c1 bridge c2] ←raw TLS→ ssl_client
             server_sock ←TDS→ [s1 bridge s2] ←raw TLS→ ssl_server
        """
        stop = threading.Event()
        try:
            c1, c2 = _make_socket_pair()
            s1, s2 = _make_socket_pair()
        except OSError as exc:
            logger.debug("socket pair unavailable: %s", exc)
            return

        c_seq = [0]
        s_seq = [0]

        def strip_tds(src, dst):
            """Reads TDS Pre-Login from src, writes raw TLS payload to dst.
            After the handshake the client sends raw TLS — pass those through."""
            try:
                while not stop.is_set():
                    fb = _recv_exactly(src, 1)
                    b = fb[0]
                    if b == 0x12:
                        rest = _recv_exactly(src, 7)
                        n = int.from_bytes(rest[1:3], 'big')
                        payload = _recv_exactly(src, n - 8)
                        dst.sendall(payload)
                    elif 0x14 <= b <= 0x17:
                        rest = _recv_exactly(src, 4)
                        n = int.from_bytes(rest[2:4], 'big')
                        data = _recv_exactly(src, n)
                        dst.sendall(fb + rest + data)
                    else:
                        break
            except Exception:
                pass
            finally:
                stop.set()
                try: dst.shutdown(socket.SHUT_WR)
                except Exception: pass

        def wrap_tds(src, dst, seq_ref):
            """Reads raw TLS records from src (TLS engine output), wraps in TDS, sends to dst.
            Switches to pass-through once TLS Application Data (0x17) is first seen."""
            handshake_done = False
            try:
                while not stop.is_set():
                    fb = _recv_exactly(src, 1)
                    b = fb[0]
                    if 0x14 <= b <= 0x17:
                        rest = _recv_exactly(src, 4)
                        n = int.from_bytes(rest[2:4], 'big')
                        data = _recv_exactly(src, n)
                        record = fb + rest + data
                        if not handshake_done:
                            seq_ref[0] = (seq_ref[0] + 1) & 0xFF
                            dst.sendall(_tds_wrap(record, seq_ref[0]))
                            if b == 0x17:
                                handshake_done = True
                        else:
                            dst.sendall(record)
                    else:
                        break
            except Exception:
                pass
            finally:
                stop.set()

        bridge_threads = [
            threading.Thread(target=strip_tds, args=(client_sock, c1), daemon=True),
            threading.Thread(target=wrap_tds,  args=(c1, client_sock, c_seq), daemon=True),
            threading.Thread(target=strip_tds, args=(server_sock, s1), daemon=True),
            threading.Thread(target=wrap_tds,  args=(s1, server_sock, s_seq), daemon=True),
        ]
        for t in bridge_threads:
            t.start()

        client_ssl = server_ssl = None
        try:
            ctx = self.ca_manager.get_ssl_context(hostname)
            client_ssl = ctx.wrap_socket(c2, server_side=True)
            client_ssl.settimeout(30)

            cli_ctx = ssl.create_default_context()
            cli_ctx.check_hostname = False
            cli_ctx.verify_mode = ssl.CERT_NONE
            server_ssl = cli_ctx.wrap_socket(s2, server_hostname=hostname)
            server_ssl.settimeout(30)

            done = threading.Event()
            t5 = threading.Thread(target=self._relay,
                args=(client_ssl, server_ssl, hostname, port, conn_id, '→', done), daemon=True)
            t6 = threading.Thread(target=self._relay,
                args=(server_ssl, client_ssl, hostname, port, conn_id, '←', done), daemon=True)
            t5.start(); t6.start()
            t5.join(); t6.join()

        except ssl.SSLError as exc:
            logger.debug("MSSQL TDS-TLS handshake failed (%s): %s", hostname, exc)
        finally:
            for s in (client_ssl, server_ssl, c1, c2, s1, s2):
                try: s.close()
                except Exception: pass
            stop.set()
            for t in bridge_threads:
                t.join(timeout=2)

    def _mssql_plain(self, client_sock, server_sock, hostname, port, conn_id):
        """Relay unencrypted TDS, emitting client→server packets to the SQL parser."""
        stop = threading.Event()

        def relay(src, dst, direction):
            try:
                while not stop.is_set():
                    pkt = _recv_tds_packet(src)
                    dst.sendall(pkt)
                    if direction == '→':
                        self.data_intercepted.emit(hostname, conn_id, port, '→', pkt)
            except Exception:
                pass
            finally:
                stop.set()

        t1 = threading.Thread(target=relay, args=(client_sock, server_sock, '→'), daemon=True)
        t2 = threading.Thread(target=relay, args=(server_sock, client_sock, '←'), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
