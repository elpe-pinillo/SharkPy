# -*- coding: utf-8 -*-
"""
SharkPy plaintext TCP proxy.
iptables REDIRECT sends arbitrary TCP ports here.  For each connection we:
  1. Recover the original destination via SO_ORIGINAL_DST.
  2. Open a raw TCP connection to that destination.
  3. Relay data bidirectionally, emitting every chunk via Qt signal.

Works for any TCP protocol that is NOT TLS: HTTP, FTP, Telnet, SMTP,
Redis, MySQL, custom game/IoT protocols, etc.
"""

import sys
import socket
import struct
import threading
import logging

from PyQt5.QtCore import QObject, pyqtSignal

logger = logging.getLogger(__name__)

_SO_ORIGINAL_DST = 80   # Linux SOL_IP


def get_original_dst(sock):
    """Return (ip_str, port) of the pre-redirect destination, or (None, None).

    On Linux reads SO_ORIGINAL_DST (iptables REDIRECT).
    On Windows queries the WinDivert connection table.
    """
    if sys.platform == 'win32':
        try:
            from p_firewall_win import get_original_dst_win
            client_src_port = sock.getpeername()[1]
            return get_original_dst_win(client_src_port)
        except Exception:
            return None, None
    # IPv4
    try:
        raw  = sock.getsockopt(socket.SOL_IP, _SO_ORIGINAL_DST, 16)
        port = struct.unpack_from('!2xH', raw)[0]
        ip   = socket.inet_ntoa(raw[4:8])
        if ip and port:
            return ip, port
    except OSError:
        pass
    # IPv6 fallback (SOL_IPV6 = 41, IP6T_SO_ORIGINAL_DST = 80)
    try:
        raw  = sock.getsockopt(41, 80, 28)
        port = struct.unpack_from('!2xH', raw)[0]
        ip   = socket.inet_ntop(socket.AF_INET6, raw[8:24])
        if ip and port:
            return ip, port
    except OSError:
        pass
    return None, None


class TCPProxy(QObject):
    """
    Transparent plaintext TCP proxy.

    Signals
    -------
    data_intercepted(hostname, conn_id, port, direction, raw_bytes)
        Emitted for every relayed chunk.  direction '→' = client→server,
        '←' = server→client.  Thread-safe — PyQt5 queues cross-thread delivery.
    """

    data_intercepted = pyqtSignal(str, int, int, str, bytes)
    conn_failed      = pyqtSignal(int, str)   # conn_id, reason

    def __init__(self, listen_port: int = 8080, parent=None):
        super().__init__(parent)
        self.listen_port   = listen_port
        self.running       = False
        self._sock         = None
        self._thread       = None
        self._conn_counter = 0
        self._conn_lock    = threading.Lock()

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(
            target=self._accept_loop, daemon=True, name='TCPProxy-accept')
        self._thread.start()
        logger.info("TCP proxy started on 127.0.0.1:%d", self.listen_port)

    def stop(self):
        self.running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        logger.info("TCP proxy stopped")

    # ── accept loop ───────────────────────────────────────────────────────────

    def _next_conn_id(self):
        with self._conn_lock:
            self._conn_counter += 1
            return self._conn_counter

    def _accept_loop(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(('127.0.0.1', self.listen_port))
            self._sock.listen(64)
            self._sock.settimeout(1.0)
            while self.running:
                try:
                    client_sock, _ = self._sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(
                    target=self._handle,
                    args=(client_sock, self._next_conn_id()),
                    daemon=True,
                ).start()
        except Exception as exc:
            logger.error("TCP accept loop error: %s", exc)
        finally:
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass

    # ── per-connection handler ────────────────────────────────────────────────

    def _handle(self, client_sock: socket.socket, conn_id: int):
        server_sock = None
        try:
            client_sock.settimeout(10)
            dst_ip, dst_port = get_original_dst(client_sock)
            if dst_ip is None:
                reason = (
                    "SO_ORIGINAL_DST unavailable — make sure SharkPy runs as root "
                    "and iptables REDIRECT rules are in place."
                )
                logger.warning("TCP proxy conn %d: %s", conn_id, reason)
                self.conn_failed.emit(conn_id, reason)
                return

            try:
                server_sock = socket.create_connection((dst_ip, dst_port), timeout=10)
                server_sock.settimeout(30)
                client_sock.settimeout(30)
            except Exception as exc:
                reason = f"Cannot reach {dst_ip}:{dst_port} — {exc}"
                logger.warning("TCP proxy conn %d: %s", conn_id, reason)
                self.conn_failed.emit(conn_id, reason)
                return

            hostname = dst_ip   # plaintext — no SNI available
            done = threading.Event()
            t1 = threading.Thread(
                target=self._relay,
                args=(client_sock, server_sock, hostname, dst_port, conn_id, '→', done),
                daemon=True,
            )
            t2 = threading.Thread(
                target=self._relay,
                args=(server_sock, client_sock, hostname, dst_port, conn_id, '←', done),
                daemon=True,
            )
            t1.start()
            t2.start()
            t1.join()
            t2.join()

        except Exception as exc:
            logger.debug("TCP handler error: %s", exc)
        finally:
            for s in (client_sock, server_sock):
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass

    def _relay(self, src, dst, hostname: str, port: int, conn_id: int,
               direction: str, done: threading.Event):
        try:
            while not done.is_set():
                try:
                    chunk = src.recv(65536)
                except OSError:
                    break
                if not chunk:
                    break
                dst.sendall(chunk)
                self.data_intercepted.emit(hostname, conn_id, port, direction, bytes(chunk))
        except OSError:
            pass
        finally:
            done.set()
            try:
                dst.close()
            except Exception:
                pass
