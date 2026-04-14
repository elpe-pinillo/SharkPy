```
  ____  _                   _     ____
 / ___|| |__   __ _ _ __  | | __/ __ \ _   _
 \___ \| '_ \ / _` | '__| | |/ / |_) | | | |
  ___) | | | | (_| | |    |   <|  __/| |_| |
 |____/|_| |_|\__,_|_|    |_|\_\_|    \__, |
                                        |___/
  Network Packet Interceptor & Editor
```

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

SharkPy is a network security testing tool that combines a Wireshark-style capture interface with a Burp Suite-style packet manipulation workflow — for **any protocol**, not just HTTP. Capture live traffic, intercept and modify packets in real time, replay edited payloads, follow TCP/UDP streams, and perform transparent TLS MITM — all from a single PyQt5 desktop application.

---

## Features

| Capability | Status |
|---|---|
| Live packet capture (passive sniff) | ✅ |
| Live packet intercept & modify (NFQUEUE / WinDivert) | ✅ |
| Wireshark-style table (Time / Src / Dst / Protocol / Length / Info) | ✅ |
| Protocol detail tree + hex dump | ✅ |
| Display filters (`tcp`, `ip.src == x.x.x.x`, `tcp.port == 80`, …) | ✅ |
| Repeater — edit raw bytes and resend | ✅ |
| Auto-Replacer — on-the-fly search/replace in live traffic | ✅ |
| Sessions — TCP/UDP stream grouping, follow stream view | ✅ |
| Transparent TLS MITM (any HTTPS host) | ✅ |
| Per-host certificate generation (signed by generated root CA) | ✅ |
| Cross-platform: Linux & Windows | ✅ |
| Debug / step mode (pause on each packet) | ✅ |

---

## Architecture

```
                        ┌─────────────────────────────────────────────────────┐
                        │                    SharkPy                           │
                        │                                                       │
  Network traffic       │   ┌─────────────┐     ┌─────────────────────────┐   │
  ──────────────►       │   │             │     │       Qt Main Thread      │   │
  iptables NFQUEUE      │   │  CoreClass  │────►│  ┌─────────────────────┐ │   │
  (Linux intercept)     │   │  (thread)   │     │  │   Capture Tab       │ │   │
  ──────────────►       │   │             │     │  │  packet table +     │ │   │
  WinDivert             │   └─────────────┘     │  │  detail tree +      │ │   │
  (Windows intercept)   │                       │  │  hex dump           │ │   │
  ──────────────►       │   ┌─────────────┐     │  └─────────────────────┘ │   │
  AsyncSniffer          │   │  TLSProxy   │────►│  ┌─────────────────────┐ │   │
  (passive sniff)       │   │  (threads)  │     │  │   TLS Tab           │ │   │
                        │   └─────────────┘     │  │  decrypted payloads │ │   │
                        │         ▲             │  └─────────────────────┘ │   │
                        │         │             │  ┌─────────────────────┐ │   │
                        │   iptables REDIRECT   │  │   Repeater Tab      │ │   │
                        │   port 443 → 8443     │  └─────────────────────┘ │   │
                        │                       │  ┌─────────────────────┐ │   │
                        │                       │  │   Sessions Tab      │ │   │
                        │                       │  └─────────────────────┘ │   │
                        │                       └─────────────────────────┘   │
                        └─────────────────────────────────────────────────────┘
```

---

## Installation

### Linux

```bash
git clone https://github.com/YourUser/SharkPy.git
cd SharkPy
sudo bash install.sh
```

The installer detects your package manager (apt / dnf / pacman), installs system dependencies (`libnetfilter-queue-dev`, `iptables`, Python dev headers), then runs `pip3 install .`.

### Windows

1. Install [Python 3.11+](https://www.python.org/downloads/) (check "Add to PATH")
2. Install [Npcap](https://npcap.com/#download) — check **"Install Npcap in WinPcap API-compatible mode"**
3. Open **PowerShell as Administrator** and run:

```powershell
git clone https://github.com/elpe-pinillo/SharkPy.git
cd SharkPy
.\install.ps1
```

The installer checks for Npcap, installs `netifaces2` (pre-built wheel, no C++ build tools needed), then runs `pip install .`. WinDivert is bundled inside the `pydivert` package — no separate driver install required.

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/YourUser/SharkPy.git
cd SharkPy

# 2. Install (Linux)
sudo bash install.sh

# 3. Run — root/admin required for intercept and TLS modes
sudo python3 Sharkpy/main.py
```

```powershell
# Windows (Administrator PowerShell)
python Sharkpy\main.py
```

---

## Usage

### Capture Tab

Select a network interface from the dropdown and choose a capture mode:

- **Intercept** — routes all traffic through NFQUEUE (Linux) or WinDivert (Windows). Packets are held until forwarded. Enables the Auto-Replacer and Debug/step mode.
- **Sniff** — passive read-only capture via scapy's `AsyncSniffer`. Lower overhead, no packet modification.

The main table shows Time, Source, Destination, Protocol, Length, and an Info summary. Click any row to expand the protocol detail tree (left pane) and hex dump (right pane).

**Filtering:** Type a filter expression in the filter bar and press Enter or click Apply. The table filters in real time without re-capturing.

### Repeater Tab

1. Right-click a captured packet → **Send to Repeater**.
2. Edit the raw hex bytes in the editor.
3. Click **Send** to retransmit the modified packet.

**Auto-Replacer:** Enter a hex search string and a hex replacement string. While Intercept mode is running, every matching byte sequence is replaced on the fly before the packet is forwarded.

### Sessions Tab

Automatically groups packets into TCP and UDP conversations. Select a stream to see all packets in that flow. Use **Follow Stream** to reconstruct the full payload exchange as ASCII or hex.

### TLS Tab

Transparent TLS MITM — decrypts and re-encrypts HTTPS (and any TLS-wrapped protocol) without the client noticing certificate errors, provided the SharkPy CA is installed as a trusted root.

---

## TLS Interception Walkthrough

```
Step 1  Generate CA
        TLS tab → "Generate CA"
        SharkPy creates a 2048-bit RSA root CA at ~/.sharkpy/ca/ca.crt

Step 2  Export the CA certificate
        TLS tab → "Export CA" → save ca.crt somewhere convenient

Step 3  Install CA in your browser / OS trust store
        Chrome/Edge:  Settings → Privacy → Manage Certificates
                      → Trusted Root CAs → Import → ca.crt
        Firefox:      about:preferences#privacy → View Certificates
                      → Authorities → Import → ca.crt
        Linux system: sudo cp ca.crt /usr/local/share/ca-certificates/sharkpy.crt
                      sudo update-ca-certificates
        Windows:      double-click ca.crt → Install Certificate
                      → Local Machine → Trusted Root CAs

Step 4  Start TLS interception
        TLS tab → "Start Interception"
        SharkPy inserts an iptables REDIRECT rule (port 443 → 8443) and starts
        the TLS proxy listener.

Step 5  Browse normally
        All HTTPS traffic is intercepted. Decrypted payloads appear in the TLS
        tab table in real time, labelled by hostname and direction.
```

See [docs/TLS_INTERCEPTION.md](docs/TLS_INTERCEPTION.md) for detailed browser setup, limitations, and troubleshooting.

---

## Filter Syntax

SharkPy uses a subset of Wireshark-style display filter expressions evaluated against scapy packet fields.

| Expression | Matches |
|---|---|
| `tcp` | Packets containing a TCP layer |
| `udp` | Packets containing a UDP layer |
| `icmp` | ICMP packets |
| `arp` | ARP packets |
| `ip.src == 192.168.1.1` | Source IP equals value |
| `ip.dst == 10.0.0.1` | Destination IP equals value |
| `tcp.port == 80` | TCP source or destination port equals value |
| `udp.port == 53` | UDP source or destination port equals value |
| `tcp.dport == 443` | TCP destination port equals value |
| `tcp.sport == 1234` | TCP source port equals value |
| `http` | Protocol identified as HTTP (TCP/80) |
| `dns` | Protocol identified as DNS (TCP or UDP/53) |

Expressions can be combined with `and`, `or`, `not` — for example: `tcp and ip.dst == 8.8.8.8`.

---

## Building a Standalone Executable (Windows)

The `SharkPy.spec` file bundles WinDivert, scapy, and all dependencies into a single `SharkPy.exe` that auto-elevates via UAC.

**Important:** PyInstaller must run as a normal (non-Administrator) user.

```bat
REM From a normal Command Prompt or PowerShell (not admin):
cd path\to\SharkPy
build.bat
REM Output: dist\SharkPy.exe
```

See [docs/WINDOWS.md](docs/WINDOWS.md) for troubleshooting common build issues.

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, code style guidelines, and pull request process.

---

## Security

SharkPy is intended for use on networks and devices you own or have explicit written permission to test. See [SECURITY.md](SECURITY.md) for the responsible disclosure policy and intended-use statement.

---

## License

SharkPy is released under the [GNU General Public License v3.0](LICENSE).

You are free to use, modify, and distribute this software under the terms of the GPL v3. There is no warranty, express or implied.
