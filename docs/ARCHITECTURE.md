# SharkPy Architecture

This document describes the internal design of SharkPy for contributors and anyone integrating with or extending the codebase.

---

## High-Level Component Diagram

```
┌────────────────────────────────────────────────────────────────────────────┐
│  SharkPy Process                                                            │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Qt Main Thread                                                        │  │
│  │                                                                        │  │
│  │  main.py (MainWindow)                                                  │  │
│  │   ├── push_packets(pkt)          ◄── QueuedConnection from CoreClass   │  │
│  │   ├── filter_table()             — re-applies display filter           │  │
│  │   ├── _on_tls_data(host,dir,raw) ◄── data_intercepted signal          │  │
│  │   └── all widget event handlers                                        │  │
│  │                                                                        │  │
│  │  gui/qt_ui.py (Ui_MainWindow)                                          │  │
│  │   └── all QWidget definitions for the four tabs                        │  │
│  └────────────────────────┬───────────────────────────────────────────────┘  │
│                            │ creates / owns                                  │
│         ┌──────────────────┼──────────────────┐                             │
│         ▼                  ▼                  ▼                             │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────┐                     │
│  │  CoreClass  │   │  TLSProxy    │   │  CAManager   │                     │
│  │  (thread)   │   │  (QObject)   │   │  (in-process)│                     │
│  │  core.py    │   │  tls_proxy.py│   │  ca_manager.py│                    │
│  └──────┬──────┘   └──────┬───────┘   └──────────────┘                     │
│         │                  │                                                 │
│         │ NFQUEUE /         │ per-connection threads                         │
│         │ WinDivert /       │ (TLSProxy-accept,                             │
│         │ AsyncSniffer      │  TLSProxy-<addr>)                             │
└─────────┼──────────────────┼──────────────────────────────────────────────┘
          │                  │
    Network traffic     Network traffic
    (raw packets)       (TLS connections)
```

---

## Thread Model

| Thread | Name | Created by | Purpose |
|---|---|---|---|
| Qt main thread | (main) | OS | All UI rendering and slot execution |
| Capture thread | `CoreClass-*` (unnamed) | `threading.Thread` in `main.py` | Runs NFQUEUE/WinDivert/AsyncSniffer loop |
| TLS accept thread | `TLSProxy-accept` | `TLSProxy.start()` | Accepts incoming TCP connections on the proxy port |
| TLS relay threads | `TLSProxy-<ip>:<port>` | TLS accept thread | One pair per active TLS connection, bidirectional relay |

**Rule:** Widget reads and writes must only happen on the Qt main thread. All cross-thread data delivery uses `QMetaObject.invokeMethod(..., Qt.QueuedConnection)` or PyQt5 signals with default `AutoConnection`, which queues delivery when the sender is on a different thread.

---

## Capture Modes

### Intercept via NFQUEUE (Linux)

1. `p_firewall.filter()` inserts iptables rules that send all IP packets to NFQUEUE queue 0.
2. `CoreClass.run()` binds to queue 0 via `netfilterqueue.NetfilterQueue`.
3. For each packet, `procesar_paquete()` is called synchronously by the NFQUEUE library.
4. The packet is pushed to the GUI via `QMetaObject.invokeMethod(parent, "push_packets", Qt.QueuedConnection, ...)`.
5. If `debugmode` is active, a `threading.Event` blocks the capture thread until the user presses "Step".
6. After any Auto-Replacer transformations, `pkt.set_payload(bytes(ip_packet))` and `pkt.accept()` forward the packet.
7. On stop, `p_firewall.flush()` removes all iptables rules; an `atexit` handler ensures cleanup even on crash.

### Passive Sniff via AsyncSniffer (Linux + Windows)

1. `CoreClass.run_sniff()` starts a scapy `AsyncSniffer` on the selected interface (or all interfaces if "Any..." is chosen).
2. Each captured packet calls `_handle_sniffed_packet()` from the sniffer's internal thread.
3. The packet is forwarded to the GUI via `QMetaObject.invokeMethod` with `QueuedConnection`.
4. No packet modification or forwarding — read-only capture.

### Intercept via WinDivert (Windows)

1. `CoreClass.run_windivert()` opens a WinDivert handle with a filter string. Interface-specific filtering uses `socket.if_nametoindex()` to obtain the Windows adapter index.
2. Each packet is received with `w.recv()`, parsed with scapy `IP()`, and pushed to the GUI.
3. After optional Auto-Replacer modification, `packet.raw = bytes(ip_pkt)` and `w.send(packet)` reinjects the (possibly modified) packet.
4. The WinDivert handle is closed on stop, which causes `w.recv()` to raise an exception and exit the loop.

---

## TLS Interception Pipeline

```
Browser makes HTTPS request
         │
         ▼
iptables PREROUTING REDIRECT (port 443 → 8443)   [set up by p_firewall.tls_intercept()]
         │
         ▼
TLSProxy._accept_loop() — accepts raw TCP connection on 127.0.0.1:8443
         │
         ▼
TLSProxy._handle(raw_sock)
   1. get_original_dst(raw_sock)  — SO_ORIGINAL_DST getsockopt recovers real server IP
   2. raw_sock.recv(4096, MSG_PEEK)  — peek at ClientHello without consuming bytes
   3. extract_sni(peek)  — parse SNI extension from TLS record
   4. CAManager.get_ssl_context(hostname)  — forge or retrieve cached per-host cert
   5. srv_ctx.wrap_socket(raw_sock, server_side=True)  — complete TLS handshake with client
   6. ssl.create_default_context() + wrap_socket(real_raw, server_hostname=hostname)
         — establish real TLS connection to origin server
   7. Two relay threads: client→server and server→client
   8. Each relay thread calls self.data_intercepted.emit(hostname, direction, chunk)
         │
         ▼
Qt main thread: _on_tls_data(hostname, direction, raw_bytes)
   — appends row to TLS tab table
```

### SNI Extraction (`extract_sni`)

Parses the raw TLS ClientHello bytes without any library dependency:

```
TLS record header:  content_type(1=0x16) + version(2) + length(2)
Handshake header:   type(1=0x01) + length(3)
ClientHello body:   client_version(2) + random(32) + session_id(var) +
                    cipher_suites(var) + compression_methods(var) + extensions(var)
Extension:          type(2) + length(2) + data
SNI extension:      type=0x0000, data = sni_list_length(2) + sni_type(1) + name_length(2) + name
```

Returns the hostname string, or `None` if the data is not a ClientHello or contains no SNI.

---

## Qt Signal/Slot Pattern

Cross-thread communication follows one of two patterns:

**Pattern 1 — `QMetaObject.invokeMethod` (used by CoreClass):**
```python
QMetaObject.invokeMethod(
    self.parent,          # QObject on the main thread
    "push_packets",       # slot name (str)
    Qt.QueuedConnection,  # queue for delivery on target thread
    Q_ARG("PyQt_PyObject", ip_packet),
)
```
The call returns immediately. The slot executes on the Qt main thread during the next event loop iteration.

**Pattern 2 — `pyqtSignal` (used by TLSProxy):**
```python
# In TLSProxy (QObject subclass):
data_intercepted = pyqtSignal(str, str, bytes)

# Emit from any thread:
self.data_intercepted.emit(hostname, direction, bytes(chunk))

# Connect in main.py:
self.tls_proxy.data_intercepted.connect(self._on_tls_data)
```
PyQt5 detects that the signal is emitted from a different thread than the receiver's thread and automatically uses `QueuedConnection` semantics.

---

## Data Flow: Packet Capture → UI

```
capture thread
  procesar_paquete(pkt) / _handle_sniffed_packet(pkt)
       │
       │  QMetaObject.invokeMethod(parent, "push_packets", QueuedConnection, pkt)
       │
       ▼
Qt main thread
  MainWindow.push_packets(pkt)
    ├── appends pkt to self.packet_list
    ├── calls protocol_parser.get_protocol(pkt), packet_src(), packet_dst(), packet_len()
    ├── inserts new row into self.capture_table (QTableWidget)
    └── calls filter_table() to apply the current display filter
```

`filter_table()` iterates over all rows and hides rows that don't match the current filter expression by evaluating it against the scapy packet stored in `self.packet_list[row]`.

---

## Data Flow: TLS Data → UI

```
TLS relay thread
  _relay(src, dst, hostname, direction, done)
    ├── chunk = src.recv(65536)
    ├── dst.sendall(chunk)
    └── self.data_intercepted.emit(hostname, direction, bytes(chunk))
         │
         │  [PyQt5 queues delivery across thread boundary]
         │
         ▼
Qt main thread
  MainWindow._on_tls_data(hostname, direction, raw_bytes)
    ├── attempts UTF-8 decode (falls back to repr for binary)
    └── appends row to self.tls_table (QTableWidget)
```

---

## File Reference

| File | Responsibility |
|---|---|
| `Sharkpy/main.py` | Qt `QMainWindow` subclass; all event handlers; owns `CoreClass`, `TLSProxy`, `CAManager` |
| `Sharkpy/core.py` | `CoreClass`; NFQUEUE, WinDivert, AsyncSniffer backends |
| `Sharkpy/tls_proxy.py` | `TLSProxy` QObject; accept loop; per-connection handler; SNI extraction; original dest recovery |
| `Sharkpy/ca_manager.py` | `CAManager`; root CA generation/persistence; per-host cert factory; SSL context cache |
| `Sharkpy/protocol_parser.py` | Stateless helpers: `get_protocol()`, `packet_src()`, `packet_dst()`, `packet_len()` |
| `Sharkpy/p_firewall.py` | iptables helpers: NFQUEUE rules, TLS REDIRECT rules, flush on exit |
| `Sharkpy/gui/qt_ui.py` | All `QWidget` definitions for the four-tab interface |
| `Sharkpy/auxiliar.py` | Development scratch / utilities (excluded from linting) |
