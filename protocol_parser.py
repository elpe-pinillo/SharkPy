from scapy.all import *

def get_protocol(packet):
        if packet.haslayer(IP):
            ip_packet = packet[IP]
            if ip_packet.haslayer(TCP):
                tcp_packet = ip_packet[TCP]
                if tcp_packet.dport == 80 or tcp_packet.sport == 80:
                    return "HTTP"
                elif tcp_packet.dport == 443 or tcp_packet.sport == 443:
                    return "HTTPS"
                elif tcp_packet.dport == 22 or tcp_packet.sport == 22:
                    return "SSH"
                elif tcp_packet.dport == 23 or tcp_packet.sport == 23:
                    return "Telnet"
                elif tcp_packet.dport == 21 or tcp_packet.sport == 21:
                    return "FTP"
                elif tcp_packet.dport == 25 or tcp_packet.sport == 25:
                    return "SMTP"
                elif tcp_packet.dport == 53 or tcp_packet.sport == 53:
                    return "DNS"
                elif tcp_packet.dport == 110 or tcp_packet.sport == 110:
                    return "POP3"
                elif tcp_packet.dport == 143 or tcp_packet.sport == 143:
                    return "IMAP"
                elif tcp_packet.dport == 3306 or tcp_packet.sport == 3306:
                    return "MySQL"
                elif tcp_packet.dport == 5432 or tcp_packet.sport == 5432:
                    return "PostgreSQL"
                elif tcp_packet.dport == 3389 or tcp_packet.sport == 3389:
                    return "RDP"
                elif tcp_packet.dport == 1194 or tcp_packet.sport == 1194:
                    return "OpenVPN"
                elif tcp_packet.dport == 5060 or tcp_packet.sport == 5060:
                    return "SIP"
                elif tcp_packet.dport == 67 or tcp_packet.sport == 67:
                    return "DHCP"
                elif tcp_packet.dport == 161 or tcp_packet.sport == 161:
                    return "SNMP"
                elif tcp_packet.dport == 69 or tcp_packet.sport == 69:
                    return "TFTP"
                elif tcp_packet.dport == 161 or tcp_packet.sport == 161:
                    return "SNMP"
                elif tcp_packet.dport == 137 or tcp_packet.sport == 137:
                    return "NetBIOS"
                elif tcp_packet.dport == 139 or tcp_packet.sport == 139:
                    return "NetBIOS"
                elif tcp_packet.dport == 389 or tcp_packet.sport == 389:
                    return "LDAP"
                elif tcp_packet.dport == 1433 or tcp_packet.sport == 1433:
                    return "MSSQL"
                elif tcp_packet.dport == 1521 or tcp_packet.sport == 1521:
                    return "OracleDB"
                elif tcp_packet.dport == 514 or tcp_packet.sport == 514:
                    return "Syslog"
                elif tcp_packet.dport == 445 or tcp_packet.sport == 445:
                    return "SMB"
                elif tcp_packet.dport == 2049 or tcp_packet.sport == 2049:
                    return "NFS"
                # Agrega más protocolos y puertos TCP según tus necesidades aquí
            elif ip_packet.haslayer(UDP):
                udp_packet = ip_packet[UDP]
                if udp_packet.dport == 53 or udp_packet.sport == 53:
                    return "DNS (UDP)"
                elif udp_packet.dport == 67 or udp_packet.sport == 67:
                    return "DHCP (UDP)"
                # Agrega más protocolos y puertos UDP según tus necesidades aquí
            elif packet.haslayer(ICMP):
                return "ICMP"
        # Agrega más protocolos en capa 2 según tus necesidades aqu
        return "Desconocido"


