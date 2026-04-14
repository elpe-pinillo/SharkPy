# TLS Interception Guide

SharkPy implements transparent TLS MITM (man-in-the-middle) interception. This document explains how it works, how to set it up in different browsers, and the known limitations.

---

## How It Works

SharkPy acts as a transparent TLS proxy between your browser (or any TLS client) and the real server:

```
Browser  ──TLS──►  SharkPy (forged cert)  ──TLS──►  Real server
                        │
                   plaintext visible
                   in SharkPy TLS tab
```

The steps SharkPy takes for each intercepted connection:

1. **iptables redirect** — A PREROUTING REDIRECT rule diverts outbound TCP port 443 traffic to SharkPy's local proxy port (default: 8443). An OUTPUT rule with `--uid-owner !<sharkpy-uid>` prevents SharkPy's own outbound connections from looping.

2. **Accept raw connection** — The TLS proxy listener on `127.0.0.1:8443` accepts the TCP connection before any TLS handshake.

3. **Peek for SNI** — `socket.MSG_PEEK` reads the TLS ClientHello without consuming bytes from the socket buffer. The SNI (Server Name Indication) extension inside the ClientHello is parsed to identify the target hostname.

4. **Recover original destination** — `getsockopt(SOL_IP, SO_ORIGINAL_DST)` retrieves the original destination IP and port before the iptables redirect, so SharkPy knows where to forward traffic even without an SNI.

5. **Forge certificate** — A unique RSA certificate is generated for the target hostname, signed by the SharkPy root CA, with the correct Subject Alternative Name. The certificate is cached in memory for the duration of the session.

6. **Dual TLS handshake** — SharkPy completes a TLS handshake with the client using the forged certificate, then opens a real TLS connection to the origin server. The client sees the forged cert (trusted because the SharkPy CA is installed); the server sees a normal TLS client.

7. **Relay and display** — Traffic is relayed bidirectionally in background threads. Each chunk of plaintext is emitted via the `data_intercepted` signal, which the Qt main thread receives and displays in the TLS tab table.

---

## Prerequisites

- Run SharkPy as root (Linux) or Administrator (Windows).
- Generate the SharkPy CA (TLS tab → **Generate CA**) before starting interception.
- Install the SharkPy CA certificate as a trusted root in the browser or OS trust store you want to intercept (see below).

---

## Browser and OS Setup

### Chrome / Chromium (Linux)

Chrome on Linux reads the NSS shared database (`~/.pki/nssdb`), not the system trust store.

```bash
# Install certutil if needed
sudo apt-get install libnss3-tools

# Export the SharkPy CA
# (TLS tab → Export CA → save as ~/sharkpy-ca.crt)

# Import into Chrome's NSS database
certutil -d sql:$HOME/.pki/nssdb -A -t "CT,," -n "SharkPy CA" -i ~/sharkpy-ca.crt

# Restart Chrome
```

Alternatively: Chrome → Settings → Privacy and security → Security → Manage certificates → Authorities → Import.

### Chrome / Edge (Windows)

Windows Certificate Store (shared by Chrome, Edge, and Internet Explorer):

1. Double-click `ca.crt`.
2. Click **Install Certificate**.
3. Select **Local Machine** → Next.
4. Select **Place all certificates in the following store** → Browse → **Trusted Root Certification Authorities**.
5. Finish. Restart Chrome / Edge.

### Firefox (all platforms)

Firefox uses its own certificate store, independent of the OS.

1. Open `about:preferences#privacy`.
2. Scroll to **Certificates** → click **View Certificates**.
3. Select the **Authorities** tab → click **Import**.
4. Select `ca.crt`, check **Trust this CA to identify websites**, click OK.
5. Restart Firefox.

### System-Wide Trust (Linux)

Installs the CA for all applications that use the system trust store (curl, wget, Python `ssl` module with default context, etc.). Note that Chrome and Firefox maintain their own stores (see above).

```bash
# Debian / Ubuntu / Kali
sudo cp ca.crt /usr/local/share/ca-certificates/sharkpy.crt
sudo update-ca-certificates

# Fedora / RHEL / CentOS
sudo cp ca.crt /etc/pki/ca-trust/source/anchors/sharkpy.crt
sudo update-ca-trust

# Arch Linux
sudo trust anchor --store ca.crt
```

### Removing the CA When Done

Always remove the SharkPy CA from your trust store after testing. The private key (`~/.sharkpy/ca/ca.key`) allows forging certificates for any domain — it must not remain trusted.

```bash
# Remove from Chrome NSS database (Linux)
certutil -d sql:$HOME/.pki/nssdb -D -n "SharkPy CA"

# Remove from system store (Debian/Ubuntu)
sudo rm /usr/local/share/ca-certificates/sharkpy.crt
sudo update-ca-certificates --fresh
```

---

## Limitations

| Limitation | Details |
|---|---|
| Certificate pinning | Applications that pin their TLS certificate (e.g. many mobile apps, some desktop Electron apps) will reject the forged certificate. SharkPy cannot intercept these without modifying the application. |
| HSTS preload | Browsers with HSTS preload entries for a domain will refuse to connect via HTTP even if redirected. TLS interception still works; pure HTTP downgrade does not. |
| HTTP/2 (h2) | SharkPy's relay is byte-transparent but does not parse HTTP/2 framing. Payloads are displayed as raw bytes for h2 connections. HTTP/1.1 payloads display as readable text. |
| IPv6 | The iptables REDIRECT rules target IPv4 (`-p tcp`). IPv6 TLS traffic (via `ip6tables`) is not currently redirected. |
| Non-port-443 TLS | The default iptables rule intercepts port 443 only. Other TLS ports (465 SMTPS, 993 IMAPS, 8443, etc.) are not intercepted unless you modify `p_firewall.tls_intercept()` to target additional ports. |
| Windows TLS interception | The iptables-based redirect is Linux-only. On Windows, TLS interception is not yet implemented via WinDivert; the TLS tab captures data from connections explicitly routed through the proxy. |
| Client certificate authentication | If the server requires a client certificate, SharkPy cannot provide one and the connection to the origin server will fail. |

---

## Security Warning

Installing a custom root CA in your browser or OS trust store is a significant security action. Anyone who obtains the SharkPy CA private key (`~/.sharkpy/ca/ca.key`) can forge certificates for any domain that your browser trusts — including your bank, email provider, and anything else.

- Only install the SharkPy CA in a **dedicated test browser profile** or a **disposable virtual machine**.
- **Remove the CA** from your trust store as soon as you finish testing.
- **Never use SharkPy TLS interception on networks or devices you do not own or have explicit written permission to test.**

---

## Troubleshooting

**Browser shows a certificate error / "Your connection is not private"**

The SharkPy CA has not been imported into this browser's trust store, or it was imported but the browser needs to be restarted. Follow the appropriate steps in the Browser and OS Setup section above.

**"Connection refused" or the TLS tab shows no data**

1. Verify SharkPy is running as root / Administrator.
2. Check that you clicked **Start Interception** in the TLS tab (not just **Generate CA**).
3. Verify the iptables rule is in place:
   ```bash
   sudo iptables -t nat -L PREROUTING -n -v | grep 443
   ```
   You should see a REDIRECT rule for port 443 → 8443.
4. Check that nothing else is listening on port 8443:
   ```bash
   sudo ss -tlnp | grep 8443
   ```

**Connections time out after TLS starts**

The `--uid-owner` exclusion rule may not match if SharkPy was launched differently (e.g., via sudo with a different UID). Check `iptables -t nat -L OUTPUT -n -v` for the exclusion rule.

**Stopping SharkPy left iptables rules in place**

Run `sudo iptables -t nat -F` to flush the nat table, and `sudo iptables -F` to flush all standard chains. SharkPy's `atexit` handler normally does this automatically, but it may not run if the process is killed with SIGKILL.
