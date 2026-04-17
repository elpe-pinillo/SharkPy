# -*- coding: utf-8 -*-
"""
Windows transparent TCP intercept using WinDivert (pydivert).

Mirrors the iptables REDIRECT behaviour on Linux:
  - Outbound TCP packets to intercept_ports are redirected to proxy_port on
    localhost.  The original (dst_ip, dst_port) is stored keyed by the
    client's source port so the proxy can look it up via get_original_dst_win().
  - Inbound responses from the proxy are rewritten so that the source address
    appears to be the original server — the client's TCP stack never knows it
    talked to a proxy.

Requires pydivert >= 2.1 and WinDivert >= 2.2 (for processId filter support).
Run SharkPy with Administrator privileges.
"""

import os
import threading
import logging

logger = logging.getLogger(__name__)

# Global connection table: client_src_port -> (orig_dst_ip, orig_dst_port)
_orig_dst_map: dict = {}
_orig_dst_lock = threading.Lock()

_active_proxies: list = []


def get_original_dst_win(client_src_port: int):
    """Return (ip, port) of the original server for this client source port."""
    with _orig_dst_lock:
        return _orig_dst_map.get(client_src_port, (None, None))


def _parse_ports(ports_arg):
    if isinstance(ports_arg, int):
        return [ports_arg]
    if isinstance(ports_arg, str):
        return [int(p.strip()) for p in ports_arg.split(',') if p.strip()]
    return [int(p) for p in ports_arg]


class WinTransparentProxy:
    """
    WinDivert-based transparent proxy redirector.

    Intercepts outbound TCP to target ports (excluding our own process to
    prevent loops) and redirects to proxy_port on 127.0.0.1.  Also intercepts
    inbound responses from proxy_port and rewrites the source back to the
    original server so the client TCP stack sees the expected peer.
    """

    def __init__(self, ports: list, proxy_port: int):
        self.ports = [int(p) for p in ports]
        self.proxy_port = int(proxy_port)
        self._handle = None
        self._thread = None
        self.running = False

    def start(self):
        import pydivert
        pid = os.getpid()
        port_exprs = ' or '.join(f'tcp.DstPort == {p}' for p in self.ports)
        # processId != pid avoids intercepting our own outbound connections to
        # the real server (which would cause an infinite redirect loop).
        filt = (
            f'(outbound and tcp and ({port_exprs}) and processId != {pid}) or '
            f'(inbound and tcp.SrcPort == {self.proxy_port})'
        )
        self._handle = pydivert.WinDivert(filt)
        self._handle.open()
        self.running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name='WinDivert-intercept'
        )
        self._thread.start()
        logger.info(
            "WinDivert transparent intercept started: ports %s → localhost:%d",
            self.ports, self.proxy_port,
        )

    def stop(self):
        self.running = False
        if self._handle:
            try:
                self._handle.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2)
        logger.info("WinDivert transparent intercept stopped")

    def _loop(self):
        while self.running:
            try:
                packet = self._handle.recv()
            except Exception:
                break
            try:
                if packet.is_outbound:
                    src_port = packet.src_port
                    if packet.tcp.syn and not packet.tcp.ack:
                        # First SYN for a new connection — record original dst
                        with _orig_dst_lock:
                            _orig_dst_map[src_port] = (packet.dst_addr, packet.dst_port)
                    # Redirect to our local proxy
                    packet.dst_addr = '127.0.0.1'
                    packet.dst_port = self.proxy_port
                else:
                    # Inbound from our proxy back to the client.
                    # Rewrite source so client sees it from the original server.
                    client_port = packet.dst_port
                    with _orig_dst_lock:
                        entry = _orig_dst_map.get(client_port)
                    if entry:
                        packet.src_addr, packet.src_port = entry
                    else:
                        # No mapping — pass through unchanged
                        self._handle.send(packet)
                        continue
                self._handle.send(packet)
            except Exception as exc:
                logger.debug("WinDivert packet error: %s", exc)
                # Best-effort: try to forward unmodified so TCP doesn't stall
                try:
                    self._handle.send(packet)
                except Exception:
                    pass


# ── public API (mirrors p_firewall.py) ───────────────────────────────────────

def tls_intercept(intercept_ports=443, proxy_port: int = 8443):
    ports = _parse_ports(intercept_ports)
    w = WinTransparentProxy(ports, proxy_port)
    w.start()
    _active_proxies.append(w)


def tls_flush(intercept_ports=443, proxy_port: int = 8443):
    for w in list(_active_proxies):
        w.stop()
    _active_proxies.clear()
    with _orig_dst_lock:
        _orig_dst_map.clear()


def tcp_intercept(intercept_ports=80, proxy_port: int = 8080):
    ports = _parse_ports(intercept_ports)
    w = WinTransparentProxy(ports, proxy_port)
    w.start()
    _active_proxies.append(w)


def tcp_flush(intercept_ports=80, proxy_port: int = 8080):
    for w in list(_active_proxies):
        w.stop()
    _active_proxies.clear()
    with _orig_dst_lock:
        _orig_dst_map.clear()


def flush():
    tls_flush()
    tcp_flush()


def quic_block(ports=(443,)):
    logger.info("QUIC blocking not supported on Windows")


def quic_unblock(ports=(443,)):
    pass
