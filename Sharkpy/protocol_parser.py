from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, Ether

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
}


def get_protocol(packet):
    if packet.haslayer(IP) or packet.haslayer(IPv6):
        ip = packet.getlayer(IP) or packet.getlayer(IPv6)
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            return (_TCP_PORTS.get(tcp.dport) or _TCP_PORTS.get(tcp.sport) or "TCP")
        if packet.haslayer(UDP):
            udp = packet[UDP]
            return (_UDP_PORTS.get(udp.dport) or _UDP_PORTS.get(udp.sport) or "UDP")
        if packet.haslayer(ICMP):
            return "ICMP"
        return "IPv6" if packet.haslayer(IPv6) else "IP"
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(Ether):
        return "Ethernet"
    return "Unknown"


def packet_src(pkt):
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
