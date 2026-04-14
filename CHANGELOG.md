# Changelog

All notable changes to SharkPy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

*(Nothing yet — add your changes here before the next release.)*

---

## [1.0.0] - 2025-04-02

### Added

**Capture Tab**
- Live packet capture in passive sniff mode via scapy `AsyncSniffer`
- Live packet intercept mode via Linux NFQUEUE (requires root + `libnetfilter-queue`)
- Live packet intercept mode via Windows WinDivert (bundled with `pydivert`)
- Wireshark-style packet table with columns: Time, Source, Destination, Protocol, Length, Info
- Protocol detail tree pane showing decoded layer fields
- Hex dump pane showing raw packet bytes
- Display filter bar with Wireshark-style expressions (`tcp`, `ip.src == x`, `tcp.port == 80`, etc.)
- Interface selector dropdown populated from `netifaces` / `netifaces2`
- Debug / step mode: pause capture thread on each packet and step forward manually
- Auto-Replacer: hex search/replace applied to every intercepted packet before forwarding
- Direction filters: apply Auto-Replacer to Input, Output, or Forward traffic independently
- `iptables` NFQUEUE rules added on intercept start and flushed on stop (Linux)
- WinDivert per-interface filtering using adapter index (Windows)

**Repeater Tab**
- Load any captured packet into a hex editor
- Edit raw bytes freely
- Resend the modified packet via scapy `send()`

**Sessions Tab**
- Automatic TCP and UDP stream grouping from captured packets
- Conversation list view with endpoint pair and packet count
- Follow Stream view reconstructing the full payload exchange as ASCII or hex

**TLS Tab**
- Root CA generation (2048-bit RSA, 10-year validity) stored at `~/.sharkpy/ca/`
- CA export button to copy `ca.crt` to a user-chosen path
- Per-host certificate generation: unique 2048-bit RSA cert signed by the SharkPy CA, valid 397 days
- In-memory SSL context cache (cert generated once per hostname per session)
- SNI extraction via `MSG_PEEK` on the raw socket before completing the TLS handshake
- Original destination recovery via `SO_ORIGINAL_DST` getsockopt (Linux)
- Bidirectional TLS relay with plaintext data surfaced to the UI via `data_intercepted` signal
- `iptables` PREROUTING + OUTPUT REDIRECT rules to forward port 443 → proxy port 8443 (Linux)
- TLS tab table showing hostname, direction, and decoded payload
- Start / Stop interception buttons

**Infrastructure**
- `protocol_parser.py`: TCP and UDP port-to-name mapping for 25+ well-known protocols
- `p_firewall.py`: iptables helpers with interface validation to prevent shell injection
- `ca_manager.py`: CA lifecycle management using the `cryptography` library
- `tls_proxy.py`: `TLSProxy` QObject with `data_intercepted` pyqtSignal for thread-safe UI updates
- `core.py`: `CoreClass` with NFQUEUE, WinDivert, and AsyncSniffer backends
- `gui/qt_ui.py`: all PyQt5 widget definitions for the four-tab interface
- `setup.py`: pip-installable, platform-conditional dependencies
- `install.sh`: Linux one-command installer supporting apt, dnf, and pacman
- `install.ps1`: Windows installer with Npcap check, `netifaces2`, and optional PyInstaller setup
- `SharkPy.spec`: PyInstaller spec producing a single `SharkPy.exe` with UAC elevation and bundled WinDivert
- `build.bat`: Windows PyInstaller build script (must run as non-admin user)
- GPL v3 license

---

[Unreleased]: https://github.com/YourUser/SharkPy/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/YourUser/SharkPy/releases/tag/v1.0.0
