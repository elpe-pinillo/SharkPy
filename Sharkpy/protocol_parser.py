from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, Ether

# ── Optional layers ───────────────────────────────────────────────────────────
try:
    from scapy.layers.dot11 import (Dot11, RadioTap, Dot11Beacon, Dot11ProbeReq,
                                    Dot11ProbeResp, Dot11Auth, Dot11AssoReq,
                                    Dot11AssoResp, Dot11ReassoReq, Dot11Deauth,
                                    Dot11Disas, Dot11Elt)
    _DOT11 = True
except ImportError:
    _DOT11 = False

try:
    from scapy.layers.bluetooth import HCI_Hdr, L2CAP_Hdr, HCI_ACL_Hdr, HCI_Event_Hdr
    _BT = True
except ImportError:
    _BT = False

try:
    from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_DATA
    _BTLE = True
except ImportError:
    _BTLE = False

try:
    from scapy.layers.can import CAN
    _CAN = True
except ImportError:
    _CAN = False

# ── TCP / UDP port → application protocol ─────────────────────────────────────
_TCP_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 137: "NetBIOS",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 514: "Syslog", 1194: "OpenVPN", 1433: "MSSQL",
    1521: "OracleDB", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
    5060: "SIP", 5432: "PostgreSQL",
}

_UDP_PORTS = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 123: "NTP",
    161: "SNMP", 500: "IKE", 1194: "OpenVPN",
    443: "QUIC", 80: "QUIC",
}

# ── 802.11 frame type/subtype descriptions ────────────────────────────────────
_DOT11_MGMT_SUBTYPES = {
    0: "Assoc Req", 1: "Assoc Resp", 2: "ReAssoc Req", 3: "ReAssoc Resp",
    4: "Probe Req", 5: "Probe Resp", 8: "Beacon", 9: "ATIM",
    10: "Disassoc", 11: "Auth", 12: "Deauth", 13: "Action",
}


def get_protocol(packet):
    # ── 802.11 / WiFi ────────────────────────────────────────────────────────
    if _DOT11 and packet.haslayer(Dot11):
        d = packet[Dot11]
        ftype = d.type
        if ftype == 0:   # Management
            sub = _DOT11_MGMT_SUBTYPES.get(d.subtype, f"Mgmt/{d.subtype}")
            return f"802.11 {sub}"
        if ftype == 1:
            return "802.11 Ctrl"
        if ftype == 2:
            return "802.11 Data"
        return "802.11"

    # ── Bluetooth Classic ────────────────────────────────────────────────────
    if _BT and packet.haslayer(HCI_Hdr):
        if packet.haslayer(L2CAP_Hdr):
            return "BT L2CAP"
        if packet.haslayer(HCI_Event_Hdr):
            return "BT HCI Event"
        return "BT HCI"

    # ── Bluetooth Low Energy ─────────────────────────────────────────────────
    if _BTLE and packet.haslayer(BTLE):
        if packet.haslayer(BTLE_ADV):
            return "BLE Adv"
        return "BLE"

    # ── CAN Bus ──────────────────────────────────────────────────────────────
    if _CAN and packet.haslayer(CAN):
        return "CAN"

    # ── IP / IPv6 ────────────────────────────────────────────────────────────
    if packet.haslayer(IP) or packet.haslayer(IPv6):
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            return _TCP_PORTS.get(tcp.dport) or _TCP_PORTS.get(tcp.sport) or "TCP"
        if packet.haslayer(UDP):
            udp = packet[UDP]
            return _UDP_PORTS.get(udp.dport) or _UDP_PORTS.get(udp.sport) or "UDP"
        if packet.haslayer(ICMP):
            return "ICMP"
        return "IPv6" if packet.haslayer(IPv6) else "IP"

    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(Ether):
        return "Ethernet"
    return "Unknown"


def packet_src(pkt):
    if _DOT11 and pkt.haslayer(Dot11):
        return pkt[Dot11].addr2 or "—"
    if _BT and pkt.haslayer(HCI_Hdr):
        return "localhost"
    if _BTLE and pkt.haslayer(BTLE):
        adv = pkt.getlayer(BTLE_ADV) if _BTLE else None
        if adv and hasattr(adv, 'AdvA'):
            return adv.AdvA
        return "—"
    if pkt.haslayer(IP):
        return pkt[IP].src
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src
    if pkt.haslayer(ARP):
        return pkt[ARP].psrc
    if pkt.haslayer(Ether):
        return pkt[Ether].src
    return "N/A"


def packet_dst(pkt):
    if _DOT11 and pkt.haslayer(Dot11):
        return pkt[Dot11].addr1 or "—"
    if _BT and pkt.haslayer(HCI_Hdr):
        return "adapter"
    if _BTLE and pkt.haslayer(BTLE):
        return "broadcast"
    if pkt.haslayer(IP):
        return pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].dst
    if pkt.haslayer(ARP):
        return pkt[ARP].pdst
    if pkt.haslayer(Ether):
        return pkt[Ether].dst
    return "N/A"


def packet_len(pkt):
    if pkt.haslayer(IP):
        return pkt[IP].len
    if pkt.haslayer(IPv6):
        return pkt[IPv6].plen
    return len(pkt)


def dot11_ssid(pkt):
    """Extract SSID string from a Dot11 packet, or empty string."""
    if not (_DOT11 and pkt.haslayer(Dot11Elt)):
        return ""
    elt = pkt[Dot11Elt]
    while elt:
        if elt.ID == 0:
            try:
                return elt.info.decode(errors='replace')
            except Exception:
                return ""
        elt = elt.payload if hasattr(elt, 'payload') and isinstance(elt.payload, Dot11Elt) else None
    return ""


def dot11_signal(pkt):
    """Extract signal strength (dBm) from RadioTap header, or None."""
    if not (_DOT11 and pkt.haslayer(RadioTap)):
        return None
    rt = pkt[RadioTap]
    if hasattr(rt, 'dBm_AntSignal'):
        return rt.dBm_AntSignal
    return None


def bt_info(pkt):
    """Return a short human-readable summary for a Bluetooth packet."""
    if _BTLE and pkt.haslayer(BTLE):
        if pkt.haslayer(BTLE_ADV):
            adv = pkt[BTLE_ADV]
            pdu = getattr(adv, 'PDU_type', '?')
            addr = getattr(adv, 'AdvA', '—')
            return f"ADV PDU={pdu} addr={addr}"
        return pkt.summary()
    if _BT and pkt.haslayer(HCI_Hdr):
        return pkt.summary()
    return pkt.summary()
