# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for SharkPy — Windows single-file .exe
#
# Build:
#   pyinstaller SharkPy.spec
#
# The resulting exe is in dist/SharkPy.exe
# It embeds the WinDivert driver (via pydivert) and requests UAC elevation
# automatically so intercept mode works without "run as admin" right-click.

from PyInstaller.utils.hooks import collect_data_files, collect_submodules
import os

block_cipher = None

# ── Collect scapy — it uses heavy dynamic imports ─────────────────────────────
scapy_datas   = collect_data_files('scapy')
scapy_hidden  = collect_submodules('scapy')

# ── Collect pydivert — bundles WinDivert64.dll / WinDivert.sys ───────────────
pydivert_datas = collect_data_files('pydivert')

# ── Collect qtmodern themes / assets ─────────────────────────────────────────
qtmodern_datas = collect_data_files('qtmodern')

# ── App source files that aren't Python packages ─────────────────────────────
extra_datas = [
    (os.path.join('Sharkpy', 'gui', 'packetshark.ui'), 'gui'),
]

a = Analysis(
    [os.path.join('Sharkpy', 'main.py')],
    # Add Sharkpy/ to the path so bare imports (from gui import …, from core import …) resolve
    pathex=[os.path.abspath('Sharkpy')],
    binaries=[],
    datas=scapy_datas + pydivert_datas + qtmodern_datas + extra_datas,
    hiddenimports=scapy_hidden + [
        # Scapy layers that are loaded dynamically
        'scapy.layers.all',
        'scapy.arch.windows',
        'scapy.arch.windows.native',
        # pydivert / WinDivert
        'pydivert',
        'pydivert.windivert',
        # App modules (resolved via pathex but listed explicitly as a safety net)
        'gui.qt_ui',
        'core',
        'protocol_parser',
        # Misc
        'netifaces',
        'qtmodern',
        'qtmodern.windows',
        'qtmodern.styles',
        'pkg_resources.py2_compat',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Not needed on Windows
        'netfilterqueue',
        'p_firewall',
        # Keep the binary lean
        'matplotlib',
        'numpy',
        'pandas',
        'tkinter',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='SharkPy',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,           # compress with UPX if available (reduces size ~30%)
    upx_exclude=[
        # Don't compress these — UPX breaks some PE-signed / driver-adjacent DLLs
        'WinDivert64.dll',
        'WinDivert.dll',
        'vcruntime*.dll',
        'msvcp*.dll',
    ],
    runtime_tmpdir=None,
    console=False,      # no terminal window — it's a GUI app
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # Request UAC elevation automatically at launch (needed for WinDivert intercept mode)
    uac_admin=True,
    # Optional: set icon if you have one
    # icon='assets/sharkpy.ico',
)
