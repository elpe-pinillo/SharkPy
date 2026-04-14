# Running SharkPy on Windows

This guide covers Windows-specific installation, limitations, building a standalone executable, and common troubleshooting steps.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Python 3.11 or 3.12** | 3.11/3.12 are recommended. Avoid 3.13+ until all dependencies publish compatible wheels. Install from [python.org](https://www.python.org/downloads/) and check "Add Python to PATH". |
| **Npcap** | Required for passive sniff mode. Download from [npcap.com](https://npcap.com/#download). During installation, check **"Install Npcap in WinPcap API-compatible Mode"**. |
| **Administrator privileges** | Required for WinDivert intercept mode and for installing Npcap. Run PowerShell or Command Prompt as Administrator. |
| **Visual C++ Redistributable** | Usually already installed. Required by Npcap and some Python native extensions. Install from [Microsoft](https://aka.ms/vs/17/release/vc_redist.x64.exe) if you see DLL errors. |

WinDivert (used for packet intercept on Windows) is bundled inside the `pydivert` Python package. You do **not** need to install it separately.

---

## Installation

1. Open **PowerShell as Administrator** (right-click → Run as administrator).

2. Clone the repository:
   ```powershell
   git clone https://github.com/YourUser/SharkPy.git
   cd SharkPy
   ```

3. Run the installer:
   ```powershell
   .\install.ps1
   ```

   The installer will:
   - Verify Python is available.
   - Check whether Npcap is installed and prompt you to install it if not.
   - Install `netifaces2` (a pre-built drop-in replacement for `netifaces` that does not require C++ build tools).
   - Run `pip install .` to install SharkPy and all Python dependencies.
   - Optionally install PyInstaller if you want to build `SharkPy.exe`.

4. Run SharkPy:
   ```powershell
   python Sharkpy\main.py
   ```
   An Administrator terminal is required for intercept mode.

---

## Known Limitations vs Linux

| Feature | Linux | Windows |
|---|---|---|
| Passive sniff | AsyncSniffer via Npcap | AsyncSniffer via Npcap |
| Packet intercept (modify/drop) | NFQUEUE (netfilterqueue) | WinDivert (pydivert) |
| TLS interception | iptables REDIRECT → TLS proxy | Not yet implemented |
| Auto-Replacer | Intercept mode (NFQUEUE) | Intercept mode (WinDivert) |
| iptables integration | Full (PREROUTING, OUTPUT, FORWARD) | Not available |

**TLS Interception:** On Linux, SharkPy inserts `iptables REDIRECT` rules that transparently redirect port 443 traffic to the TLS proxy. The equivalent on Windows would use WinDivert to intercept and redirect individual packets; this is planned but not yet implemented. On Windows, the TLS tab is present but the Start Interception button requires the proxy to be reached via explicit proxy configuration.

**NFQUEUE vs WinDivert:** The core intercept logic is the same — hold a packet, allow SharkPy to modify it, then reinject — but the underlying driver is platform-specific. WinDivert intercept mode is fully functional for packet capture and modification.

---

## Building SharkPy.exe

The `SharkPy.spec` PyInstaller spec bundles the entire application, WinDivert drivers, and all Python dependencies into a single `.exe`. The `.exe` requests UAC elevation automatically at launch.

**Important: PyInstaller must run as a normal (non-Administrator) user.** Running PyInstaller as Administrator causes it to embed an Admin-only manifest that prevents the built `.exe` from launching on non-admin accounts. The UAC elevation comes from the `uac_admin=True` flag in the spec, not from running PyInstaller as Admin.

```bat
REM Close your Administrator PowerShell.
REM Open a normal (non-admin) Command Prompt or PowerShell.

cd path\to\SharkPy
build.bat
```

`build.bat` runs:
```bat
pyinstaller SharkPy.spec
```

The output is `dist\SharkPy.exe`. Double-click it — Windows will prompt for UAC elevation.

---

## Troubleshooting

### `error: Microsoft Visual C++ 14.0 or greater is required`

You are trying to install `netifaces` (not `netifaces2`). The `install.ps1` script installs `netifaces2` first to avoid this. If you see this error, run:

```powershell
pip install netifaces2
pip install .
```

Do **not** install `netifaces` on Windows; use `netifaces2` instead. SharkPy's `core.py` imports `netifaces2` as a fallback when `netifaces` is not available.

### `SyntaxError: source code string cannot contain null bytes` (PyInstaller)

This is caused by a corrupt `packaging` installation, which is a known issue on some Windows Python setups. Fix it with:

```powershell
pip install --force-reinstall packaging
pyinstaller SharkPy.spec
```

The `install.ps1` script applies this fix automatically if you choose to install PyInstaller.

### `WinDivert driver failed to load` / `Access is denied`

WinDivert requires Administrator rights to load its kernel driver. Make sure you are running SharkPy (or `build.bat`) from an Administrator terminal. The bundled `.exe` handles this automatically via the UAC manifest.

### Npcap not detected / sniff mode shows no packets

- Verify Npcap is installed: check `C:\Windows\System32\Npcap\wpcap.dll` exists.
- Ensure Npcap was installed with **WinPcap API-Compatible Mode** checked.
- Try uninstalling and reinstalling Npcap.
- If using a virtual machine, ensure the VM network adapter is in bridged mode (not NAT) for physical network traffic, or NAT mode for host-only traffic.

### PyQt5 fails to import / display window

PyQt5 requires the Visual C++ Redistributable. Download and install `vc_redist.x64.exe` from Microsoft if you see errors referencing `VCRUNTIME140.dll` or similar.

### Antivirus flags SharkPy.exe

Some antivirus products flag SharkPy.exe as suspicious because it embeds the WinDivert kernel driver and requests UAC elevation. This is a false positive. You can verify the build by compiling from source with `build.bat`. Consider adding an exclusion for your SharkPy build directory in your AV settings.
