```
  ____  _                   _     ____
 / ___|| |__   __ _ _ __  | | __/ __ \ _   _
 \___ \| '_ \ / _` | '__| | |/ / |_) | | | |
  ___) | | | | (_| | |    |   <|  __/| |_| |
 |____/|_| |_|\__,_|_|    |_|\_\_|    \__, |
                                        |___/
```

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)]()

---

SharkPy is a network security tool that combines the packet capture workflow of **Wireshark** with the interception and manipulation workflow of **Burp Suite** — for every protocol, not just HTTP.

The goal is a single tool that lets you capture and inspect traffic at every layer, intercept and modify packets mid-session, replay application-layer payloads with edits, and perform network-layer attacks that set up the conditions for interception.

---

## Core Concept: Two Modes

Understanding the distinction between these two modes is the most important thing to know about SharkPy.

### Mode 1 — Intercept (Capture Tab, Debug mode)

You are **in** the traffic path. Packets flow through your machine via NFQUEUE (Linux) or WinDivert (Windows). Each packet arrives live, you can inspect it, modify its bytes, and release it forward — or drop it. The TCP session state, TLS encryption, and sequence numbers remain valid because you are operating on in-flight traffic.

**Use this when** you want to modify a request as it leaves a browser, tamper with a response before it reaches a client, or observe exactly what a protocol is doing byte by byte in real time.

### Mode 2 — Replay (Repeater Tab)

You are **not** in the traffic path. You take a captured payload, open a fresh connection to the target, and send it independently. SharkPy handles the transport layer invisibly: TCP handshake, TLS negotiation, sequence numbers. You edit only the application-layer bytes.

**Use this when** you want to resend a captured request with modifications, test how a server responds to a specific payload, or reproduce a finding.

**Why replaying a raw TCP segment doesn't work:** a captured TCP segment has a sequence number that was valid only within its original connection. That connection is closed. The TLS session keys are gone. There is no state to replay into. SharkPy's Repeater solves this by working at the application layer — it extracts the payload, opens a new connection, and sends only the bytes that matter. You never deal with headers.

---

## Installation

**Requires:** Python 3.8+, root (Linux) or Administrator (Windows).

### Linux

```bash
# System libraries (Debian/Ubuntu)
sudo apt install python3-pip libnetfilter-queue-dev iptables

# Python packages
pip install -r requirements.txt

# Run
sudo python3 Sharkpy/main.py
```

Or use the installer script: `sudo bash install.sh`

### Windows

1. Install [Npcap](https://npcap.com/#download) — check *WinPcap API-compatible mode*
2. Install Python packages:
   ```powershell
   pip install -r requirements-windows.txt
   ```
3. Run as Administrator:
   ```powershell
   python Sharkpy\main.py
   ```

Or use the installer script: run `install.ps1` as Administrator

---

## Tabs Reference

### Capture

The Wireshark-style packet capture view. Contains three sub-tabs: **Packets**, **802.11 WiFi**, and **Bluetooth**.

#### Packets

The main packet list. Columns: Time, Source, Destination, Protocol, Length, Info.

**Interface selector** — choose a network interface or "Any...". SharkPy auto-detects Bluetooth (`hci*`) and USB monitor (`usbmon*`) interfaces and auto-switches to Sniff mode for them.

**Mode selector:**
- *Intercept* — routes traffic through NFQUEUE (Linux) / WinDivert (Windows). Packets can be held and modified before forwarding. Required for the debug/intercept workflow.
- *Sniff* — passive capture via raw socket. Read-only but sees all layers including Ethernet. Use for WiFi (monitor mode), Bluetooth, CAN.

**BPF / Port filter** — applied at the kernel level before packets reach SharkPy. Reduces overhead for high-traffic captures.

**Debug / Intercept mode** — enable the Debug checkbox to enter step-through mode. Each incoming packet is held and highlighted orange. Edit the hex bytes directly in the hex editor, then press:
- *Next* — release this packet (with your modifications) and hold the next one
- *Continue* — release all held packets and exit step mode

This is how you modify live in-flight traffic.

**Packet detail tree** — click any row to see a Wireshark-style protocol breakdown with every field parsed and labelled.

**Hex editor** — raw bytes of the selected packet. In intercept mode, bytes are editable (both hex and ASCII columns stay in sync).

**Right-click menu on a packet:**
- Send to Repeater / Intruder / Crypto
- Follow TCP/UDP stream
- Go to Proxy entry (links to the Proxy tab entry for this packet's session)
- Apply/prepare display filter
- Mark / hide row
- Copy as hex / escaped string / summary
- Export selection as PCAP

**Keyboard shortcuts:**

| Key | Action |
|-----|--------|
| Ctrl+O | Open PCAP file |
| Ctrl+S | Save capture as PCAP |
| Ctrl+F | Focus filter bar |

#### 802.11 WiFi

Displays 802.11 wireless frames captured on a monitor-mode interface.

Columns: #, Time, Type, Src MAC, Dst MAC, BSSID, SSID, Signal (dBm).

Frame types shown: Beacon, Probe Request/Response, Authentication, Association Request/Response, Deauthentication, Disassociation, Data, Control.

Selecting a frame shows a detailed text summary and hex dump below.

**To capture WiFi frames:**
```bash
sudo airmon-ng start wlan0   # creates wlan0mon
```
Select `wlan0mon` in SharkPy. Sniff mode is selected automatically.

#### Bluetooth

Displays Bluetooth Classic (HCI/L2CAP) and Bluetooth Low Energy (BLE advertisement) packets captured on an HCI interface.

Columns: #, Time, Protocol, Source, Destination, Info.

Select an `hci*` interface and use Sniff mode.

---

### Proxy

Organises captured traffic by application protocol. Fed automatically from Capture — every packet that passes through Capture is parsed and filed into the appropriate Proxy view.

Use the **protocol selector** dropdown to switch between views. Use the **filter bar** to search within the current view.

#### HTTP

A table of every HTTP request/response pair captured through the TLS proxy or TCP proxy.

Columns: Method, Host, Path, Status, MIME type, Response length, Time.

Selecting a row shows:
- **Request** — raw headers, parsed header table, decoded body
- **Response** — raw headers, parsed header table, decoded body (decompressed automatically from gzip, deflate, brotli, or zstd)

Right-click a row:
- Send to Repeater
- Go to Capture (jumps to the originating packet)
- Go to Session

**Filter** matches against host, path, status code, and body content.

#### DNS

A table of every DNS query and response.

Columns: Query name, Type, Response IPs, Server, Time.

Useful for spotting data exfiltration over DNS, suspicious domain lookups, and DNS rebinding patterns.

#### Conversations

A table of every TCP and UDP conversation (by endpoint pair).

Columns: #, Protocol, Client, Server, Packets, Bytes, Start Time.

Select a row to see the full reconstructed byte stream in four tabs: combined, A→B only, B→A only, and hex dump.

#### Telnet

Captures and reconstructs Telnet sessions. Shows client commands and server responses in separate views and as a combined chronological timeline.

Credentials and commands sent in cleartext are fully visible here.

---

### Repeater

Send application-layer payloads to a target with arbitrary modifications and read the response. Works like Burp Suite's Repeater.

**Loading a packet:**
1. Select a packet in the Capture tab
2. Right-click → Send to Repeater (or press the Load button)

SharkPy extracts the application payload and stores the connection metadata (destination IP, port, transport). The **hex editor is populated with payload bytes only** — not IP/TCP/UDP headers, which are irrelevant to what you are testing.

**Info bar** at the top of each tab shows: timestamp, source→destination, protocol, payload size, and transport mode.

**Transport modes:**
- `TCP` — opens a fresh TCP connection to the stored destination, sends the payload, reads until timeout
- `TLS` — opens a fresh TCP connection, performs a new TLS handshake (certificate verification disabled), sends the payload, reads until timeout
- `UDP` — sends a UDP datagram to the stored destination, waits for a reply
- `RAW` — used for ICMP, ARP, and other non-TCP/UDP packets; sends via raw socket

**What you should understand:** every Send opens a completely new connection. Session state from the original capture is intentionally discarded. This is the correct behaviour — you are testing the server's response to a specific payload, not replaying a specific network event.

**Editing:** the hex editor and protocol tree are kept in sync. You can edit in either. The tree shows the full original packet structure for reference; the hex editor contains only the payload you will send.

**Multiple tabs:** press + to open additional tabs. Each is independent — useful for comparing server responses across variations of a payload.

**Right-click the detail tree** to copy field values, add them to the Intruder, or send the current response to Crypto.

---

### Sessions

A table of all TCP and UDP sessions observed during the capture, grouped by conversation.

Columns: Protocol, Client endpoint, Server endpoint, Packet count, Byte count, Start time.

Select a session to see the reconstructed stream. Use **Follow Stream** to open a full stream view with hex / ASCII / split display modes.

Right-click a session:
- Go to Capture (jumps to the first packet of this session in the Capture tab)
- Go to Proxy entry (if this session has an associated HTTP or Telnet entry)

---

### TLS

The TLS interception proxy. Acts as a transparent man-in-the-middle between a client and a server for any TLS-wrapped protocol.

**How it works:**
1. SharkPy generates a local Certificate Authority (CA) and stores it at `~/.sharkpy/ca/`
2. An iptables NAT REDIRECT rule sends all traffic on the target port to SharkPy's proxy port
3. SharkPy terminates the client's TLS connection using a dynamically-generated certificate signed by your CA
4. SharkPy opens a new TLS connection to the real server
5. Traffic flows through in cleartext — decrypted requests and responses appear in Proxy → HTTP

**CA setup:**
1. Click **Generate CA** (one-time setup)
2. Install the CA certificate in your browser or OS trust store:
   - Firefox: Preferences → Privacy → Certificates → Import
   - Chrome/Edge: Settings → Privacy → Manage Certificates → Trusted Root CAs → Import
   - Linux system: `sudo cp ~/.sharkpy/ca/ca.crt /usr/local/share/ca-certificates/sharkpy.crt && sudo update-ca-certificates`
   - Windows: double-click the cert → Install → Local Machine → Trusted Root Certification Authorities

**Block QUIC/HTTP3:** check this box to drop outbound UDP on the intercepted port(s). This forces browsers using HTTP/3 (QUIC, a UDP-based protocol) to fall back to TLS/TCP, which can be intercepted. Without this, browsers may silently bypass the proxy via QUIC.

**Custom ports:** intercept TLS on any port (8443, custom application protocols) by changing the port field before starting.

**On stop:** all iptables NAT rules are removed. If QUIC blocking was active, the UDP DROP rules are also removed.

---

### Intruder

Automated payload fuzzing. Works like Burp Suite's Intruder.

**Workflow:**
1. Load a request (from Capture via right-click, from Repeater, or from a file)
2. Mark injection positions in the payload with `§markers§`
3. Configure a payload source: wordlist, numeric range, or file
4. Click Start Attack

Each payload value is substituted into all marked positions and sent as a separate request. Results are shown in a table with response length, status code, and elapsed time.

**Interpreting results:** anomalies in response length or response time typically indicate interesting server behaviour — error messages, different code paths, timing-based information leakage.

---

### Crypto

Encode, decode, encrypt, decrypt, and hash data. Works like Burp Suite's Decoder.

**Loading data:** use Load from Capture to import bytes from a selected packet, or Load from Repeater to import from the current Repeater response.

**Input/Output formats:** Raw bytes, Hex, Base64, ASCII.

**Operations:** Base64 encode/decode, URL encode/decode, HTML entity encode/decode, Hex encode/decode, MD5 / SHA-1 / SHA-256 hash, AES encryption/decryption, XOR, and more.

**Sending results:** use Send to Repeater to push the transformed output directly into a new Repeater tab.

---

### Attack

Network-layer attacks that establish the conditions for traffic interception. All attacks run in background threads, log their activity, and stop cleanly when you press Stop or close the application.

These attacks exist to support the capture and interception workflow — they set up the network conditions so that traffic flows through your machine, where SharkPy can capture and manipulate it.

#### ARP Spoof

Poisons the ARP caches of a target host and its default gateway so that traffic between them is routed through your machine.

**Fields:**
- *Target IP* — the host whose traffic you want to intercept
- *Gateway IP* — the router (usually ends in `.1`)
- *Interface* — the interface to send ARP packets on
- *Enable IP forwarding* — writes `1` to `/proc/sys/net/ipv4/ip_forward` so that forwarded packets actually reach their destination

**ARP table restore:** when you press Stop, SharkPy sends correct ARP replies to both the target and the gateway to restore their original MAC mappings. This is important — failing to restore leaves the victim unable to reach the network.

**Typical full workflow:**
1. ARP Spoof (Attack tab) → puts you in the traffic path
2. Intercept mode (Capture tab) → captures and optionally modifies all traffic
3. TLS proxy (TLS tab) → decrypts HTTPS

#### DNS Spoof

Intercepts DNS queries and replies with fake IP addresses. Redirects a victim to a controlled server or to this machine.

**Requires** being in the traffic path first — either via ARP Spoof or by being on a network segment where you can see broadcasts.

**Mapping table:** add Domain → Fake IP rows. The domain column is a substring match (`example` matches `www.example.com`). Use `*` to respond to all DNS queries.

**Combining with TLS proxy:** redirect a domain to this machine's IP, then run the TLS proxy — full HTTPS interception without needing to be on the default gateway.

#### 802.11 Deauth

Sends 802.11 Deauthentication frames to disconnect a client from an access point. Uses two-sided deauth (AP→client and client→AP) for reliability.

**Requires** a wireless interface in monitor mode: `sudo airmon-ng start wlan0`

**Client MAC:** `FF:FF:FF:FF:FF:FF` sends a broadcast deauth — disconnects all clients from the AP simultaneously.

**Reason codes:** 1 = unspecified, 4 = inactivity, 7 = class 3 frame received from non-associated client, 8 = leaving BSS.

**Use cases:**
- Force a client to reconnect so you can capture the WPA handshake
- Force a client to roam to a controlled AP
- Test deauth detection in wireless intrusion detection systems

#### DHCP Starvation

Floods a DHCP server with DISCOVER packets using randomly generated MAC addresses to exhaust its IP address pool. Once the pool is drained, legitimate clients cannot obtain leases.

Use this before starting a Rogue DHCP server to ensure your server wins DISCOVER races.

#### Rogue DHCP

Operates as a fake DHCP server. Responds to DISCOVER and REQUEST messages from clients with your configured gateway and DNS.

**Fields auto-fill** with this machine's IP when you select an interface.

| Field | Effect |
|-------|--------|
| Server IP | Identifies this machine as the DHCP server |
| Router/Gateway | Advertised as the default gateway — set to your IP to route all new-client traffic through you |
| DNS Server | Advertised as the DNS resolver — set to your IP and combine with DNS Spoof |
| Pool Start/End | Range of IP addresses to offer |
| Lease Time | Duration of each lease in seconds |

**Full MitM via DHCP:** set Router and DNS to your machine's IP. New clients joining the network will route all traffic through you automatically — no ARP spoofing needed, but only affects new DHCP clients.

#### LLMNR / NBT-NS Poison

Responds to Link-Local Multicast Name Resolution (LLMNR, UDP 5355) and NetBIOS Name Service (NBT-NS, UDP 137) broadcast queries with your IP address.

**Background:** when a Windows machine fails to resolve a hostname via DNS, it broadcasts these protocols to the local network asking "who is `fileserver`?". Any machine that responds wins. SharkPy responds to all queries (or only those matching your filter), directing Windows clients to connect to this machine instead.

**Why this matters:** when a Windows service or user tries to access a named resource (`\\fileserver\share`, a printer, a backup agent), it will try to authenticate to your machine using NTLM. The authentication attempt arrives at SharkPy's TCP or TLS proxy where it can be captured.

**Target names:** comma-separated list of name substrings to match (`wpad, fileserver, backup`). Leave empty to respond to everything.

**Combining with TCP proxy:** start the TCP proxy on port 445 (SMB) or port 80 to receive and log the authentication exchanges.

**Most effective in:** Windows Active Directory environments where services constantly try to reach named resources by hostname.

---

## Common Workflows

### Intercept and modify HTTPS traffic from a browser

1. TLS tab → Generate CA (one time only)
2. Install the CA certificate in your browser
3. TLS tab → enable "Block QUIC" → Start
4. Capture tab → select your interface → Intercept mode → Sniff
5. Browse — decrypted requests appear in Proxy → HTTP
6. Right-click any request → Send to Repeater to replay with modifications

### MitM another host on the LAN

1. Attack → ARP Spoof: enter target IP and gateway IP, enable IP forwarding, Start
2. Capture → select the interface → Sniff
3. All traffic between the target and its gateway now flows through your machine
4. Start TLS proxy to decrypt HTTPS, or use DNS Spoof to redirect specific domains

### Capture WiFi frames and WPA handshakes

1. `sudo airmon-ng start wlan0`
2. Capture → select `wlan0mon` → Sniff mode (auto-selected)
3. Switch to the 802.11 WiFi sub-tab to watch frames
4. Attack → 802.11 Deauth: enter BSSID, set client to `FF:FF:FF:FF:FF:FF`, Start → clients reconnect, WPA handshake appears in the capture

### Windows credential capture via LLMNR poisoning

1. Be on the same network segment as Windows machines
2. Attack → LLMNR/NBT-NS: set your IP, leave names empty, Start
3. TLS or TCP proxy: start a listener on port 80 or 445
4. Windows machines that try to reach named resources will send NTLM authentication to your proxy

### Fuzz an application protocol

1. Capture a normal session
2. Right-click a relevant packet → Send to Intruder
3. Mark injection positions with `§markers§`
4. Configure a payload list (wordlist, numeric range, or file)
5. Start — analyse response length and timing differences for anomalies

---

## Protocol Support

| Protocol | Capture | Proxy view | Intercept (modify live) | Replay (Repeater) |
|----------|:-------:|:----------:|:------------------------:|:-----------------:|
| TCP (plain) | ✅ | Conversations | ✅ | ✅ |
| TLS / HTTPS | ✅ | HTTP | ✅ via TLS proxy | ✅ |
| UDP | ✅ | Conversations | ✅ | ✅ |
| HTTP | ✅ | HTTP | ✅ | ✅ |
| DNS | ✅ | DNS | ✅ | ✅ |
| Telnet | ✅ | Telnet | ✅ | ✅ |
| ICMP | ✅ | — | ✅ | ✅ raw |
| ARP | ✅ | — | ✅ | ✅ raw |
| IPv6 | ✅ | — | ✅ | ✅ |
| 802.11 WiFi | ✅ monitor mode | 802.11 sub-tab | — | — |
| Bluetooth Classic | ✅ hci interface | Bluetooth sub-tab | — | — |
| Bluetooth LE | ✅ hci interface | Bluetooth sub-tab | — | — |

---

## Architecture

```
  Network traffic
  ─────────────────────────────────────────────────
  iptables NFQUEUE     ┌─────────────────────────────────────┐
  (Linux intercept) ──►│            CoreClass                │
                       │  (capture thread)                   │
  WinDivert            │  holds packets in debug mode        │
  (Windows intercept)──►  forwards immediately in normal mode│
                       └──────────────┬──────────────────────┘
  AsyncSniffer                        │ QMetaObject::invokeMethod
  (passive sniff) ────────────────────►
                                      │
                       ┌──────────────▼──────────────────────┐
                       │          SniffTool (Qt main thread) │
                       │                                     │
                       │  push_packets() ──► Capture tab    │
                       │                 ──► _proxy_ingest()│
                       │                       │             │
                       │              ┌────────▼──────────┐  │
                       │              │  Proxy tab        │  │
                       │              │  HTTP / DNS /     │  │
                       │              │  Conversations /  │  │
                       │              │  Telnet           │  │
                       │              └───────────────────┘  │
                       │                                     │
                       │  TLSProxy ──► decrypted payloads ──► HTTP│
                       │  TCPProxy ──► plaintext TCP ────────► HTTP│
                       │                                     │
                       └─────────────────────────────────────┘
```

---

## Permissions

SharkPy requires root on Linux for:
- Raw packet capture (AF_PACKET sockets, NFQUEUE)
- iptables / ip6tables manipulation (intercept mode, TLS proxy, QUIC blocking)
- Binding to privileged ports (NBT-NS on UDP 137)
- Writing to `/proc/sys/net/ipv4/ip_forward`

On Windows, WinDivert requires Administrator privileges.

---

## License

Released under the [GNU General Public License v3.0](LICENSE).

SharkPy is intended for use on networks and systems you own or have explicit written authorisation to test.
