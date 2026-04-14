import sys
from setuptools import setup, find_packages

common = [
    "PyQt5>=5.15",
    "scapy",
    "qtmodern",
    "cryptography",
]

if sys.platform == "win32":
    # netifaces has no pre-built Windows wheel and requires C++ Build Tools to compile.
    # netifaces2 is a drop-in replacement with pre-built wheels for all platforms.
    platform_deps = ["pydivert", "netifaces2"]
else:
    platform_deps = ["netfilterqueue", "netifaces"]

setup(
    name="SharkPy",
    version="1.0.0",
    description="Network packet interceptor and editor — Wireshark UI, Burp Suite workflow",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=common + platform_deps,
    entry_points={
        "console_scripts": [
            "sharkpy=Sharkpy.main:main",
        ],
    },
)
