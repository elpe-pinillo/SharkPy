import subprocess
import netifaces
import atexit
import logging

logger = logging.getLogger(__name__)

_rules_active = False


def _run_iptables(*args, silent=False):
    cmd = ['iptables'] + list(args)
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        if not silent:
            logger.error("iptables command failed: %s\n%s", ' '.join(cmd), e.stderr.decode())
        raise


def _run_ip6tables(*args, silent=False):
    cmd = ['ip6tables'] + list(args)
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        if not silent:
            logger.warning("ip6tables command failed (may not be supported): %s\n%s",
                           ' '.join(cmd), e.stderr.decode())


def filter(mitm, i):
    global _rules_active
    # Validate interface name against known interfaces to prevent injection
    valid_interfaces = netifaces.interfaces() + ['Any...']
    if i not in valid_interfaces:
        raise ValueError(f"Unknown interface: {i!r}")

    flush()

    if mitm:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1\n')

    if i == "Any...":
        _run_iptables('-I', 'INPUT', '-j', 'NFQUEUE', '--queue-num', '0')
        _run_iptables('-I', 'OUTPUT', '-j', 'NFQUEUE', '--queue-num', '0')
        _run_iptables('-A', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', '0')
        _run_ip6tables('-I', 'INPUT', '-j', 'NFQUEUE', '--queue-num', '0')
        _run_ip6tables('-I', 'OUTPUT', '-j', 'NFQUEUE', '--queue-num', '0')
        _run_ip6tables('-A', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', '0')
    elif i == "lo":
        _run_iptables('-I', 'INPUT', '-i', i, '-j', 'NFQUEUE', '--queue-num', '0')
        _run_ip6tables('-I', 'INPUT', '-i', i, '-j', 'NFQUEUE', '--queue-num', '0')
    else:
        _run_iptables('-I', 'INPUT', '-i', i, '-j', 'NFQUEUE', '--queue-num', '0')
        _run_iptables('-I', 'OUTPUT', '-o', i, '-j', 'NFQUEUE', '--queue-num', '0')
        _run_iptables('-A', 'FORWARD', '-i', i, '-j', 'NFQUEUE', '--queue-num', '0')
        _run_ip6tables('-I', 'INPUT', '-i', i, '-j', 'NFQUEUE', '--queue-num', '0')
        _run_ip6tables('-I', 'OUTPUT', '-o', i, '-j', 'NFQUEUE', '--queue-num', '0')
        _run_ip6tables('-A', 'FORWARD', '-i', i, '-j', 'NFQUEUE', '--queue-num', '0')

    _rules_active = True


def flush():
    global _rules_active
    for cmd in ['iptables', 'ip6tables']:
        for args in [['--flush'], ['-t', 'nat', '--flush']]:
            try:
                subprocess.run([cmd] + args, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                if cmd == 'iptables':
                    logger.error("%s %s failed: %s", cmd, ' '.join(args), e.stderr.decode())
                else:
                    logger.warning("%s %s failed (may not be supported): %s",
                                   cmd, ' '.join(args), e.stderr.decode())
    _rules_active = False


def _atexit_flush():
    if _rules_active:
        logger.info("Flushing iptables rules on exit")
        flush()


atexit.register(_atexit_flush)


# ── TLS interception rules ────────────────────────────────────────────────────

def _parse_ports(ports_arg):
    """Accept int, str, or list of ints/strs; return list of int port numbers."""
    if isinstance(ports_arg, int):
        return [ports_arg]
    if isinstance(ports_arg, str):
        return [int(p.strip()) for p in ports_arg.split(',') if p.strip()]
    return [int(p) for p in ports_arg]


def tls_intercept(intercept_ports=443, proxy_port: int = 8443):
    """Redirect TLS traffic on one or more ports to the SharkPy TLS proxy.
    intercept_ports may be an int, a comma-separated string, or a list."""
    import os
    uid = str(os.getuid())
    for port in _parse_ports(intercept_ports):
        _run_iptables('-t', 'nat', '-A', 'PREROUTING',
                      '-p', 'tcp', '--dport', str(port),
                      '-j', 'REDIRECT', '--to-port', str(proxy_port))
        _run_iptables('-t', 'nat', '-A', 'OUTPUT',
                      '-p', 'tcp', '--dport', str(port),
                      '-m', 'owner', '!', '--uid-owner', uid,
                      '-j', 'REDIRECT', '--to-port', str(proxy_port))
        _run_ip6tables('-t', 'nat', '-A', 'PREROUTING',
                       '-p', 'tcp', '--dport', str(port),
                       '-j', 'REDIRECT', '--to-port', str(proxy_port))
        _run_ip6tables('-t', 'nat', '-A', 'OUTPUT',
                       '-p', 'tcp', '--dport', str(port),
                       '-m', 'owner', '!', '--uid-owner', uid,
                       '-j', 'REDIRECT', '--to-port', str(proxy_port))
        logger.info("TLS intercept rule: port %d -> %d", port, proxy_port)


def tls_flush(intercept_ports=443, proxy_port: int = 8443):
    """Remove TLS interception iptables rules."""
    import os
    uid = str(os.getuid())
    for port in _parse_ports(intercept_ports):
        for args in [
            ('-t', 'nat', '-D', 'PREROUTING',
             '-p', 'tcp', '--dport', str(port),
             '-j', 'REDIRECT', '--to-port', str(proxy_port)),
            ('-t', 'nat', '-D', 'OUTPUT',
             '-p', 'tcp', '--dport', str(port),
             '-m', 'owner', '!', '--uid-owner', uid,
             '-j', 'REDIRECT', '--to-port', str(proxy_port)),
        ]:
            try:
                _run_iptables(*args, silent=True)
            except Exception:
                pass
            try:
                _run_ip6tables(*args, silent=True)
            except Exception:
                pass
    logger.info("TLS intercept rules removed")


def tcp_intercept(intercept_ports, proxy_port: int = 8080):
    """Redirect plaintext TCP traffic on one or more ports to the TCP proxy."""
    import os
    uid = str(os.getuid())
    for port in _parse_ports(intercept_ports):
        _run_iptables('-t', 'nat', '-A', 'PREROUTING',
                      '-p', 'tcp', '--dport', str(port),
                      '-j', 'REDIRECT', '--to-port', str(proxy_port))
        _run_iptables('-t', 'nat', '-A', 'OUTPUT',
                      '-p', 'tcp', '--dport', str(port),
                      '-m', 'owner', '!', '--uid-owner', uid,
                      '-j', 'REDIRECT', '--to-port', str(proxy_port))
        _run_ip6tables('-t', 'nat', '-A', 'PREROUTING',
                       '-p', 'tcp', '--dport', str(port),
                       '-j', 'REDIRECT', '--to-port', str(proxy_port))
        _run_ip6tables('-t', 'nat', '-A', 'OUTPUT',
                       '-p', 'tcp', '--dport', str(port),
                       '-m', 'owner', '!', '--uid-owner', uid,
                       '-j', 'REDIRECT', '--to-port', str(proxy_port))
        logger.info("TCP intercept rule: port %d -> %d", port, proxy_port)


def tcp_flush(intercept_ports, proxy_port: int = 8080):
    """Remove plaintext TCP interception iptables rules."""
    import os
    uid = str(os.getuid())
    for port in _parse_ports(intercept_ports):
        for args in [
            ('-t', 'nat', '-D', 'PREROUTING',
             '-p', 'tcp', '--dport', str(port),
             '-j', 'REDIRECT', '--to-port', str(proxy_port)),
            ('-t', 'nat', '-D', 'OUTPUT',
             '-p', 'tcp', '--dport', str(port),
             '-m', 'owner', '!', '--uid-owner', uid,
             '-j', 'REDIRECT', '--to-port', str(proxy_port)),
        ]:
            try:
                _run_iptables(*args, silent=True)
            except Exception:
                pass
            try:
                _run_ip6tables(*args, silent=True)
            except Exception:
                pass
    logger.info("TCP intercept rules removed")


# ── QUIC / HTTP3 blocking ─────────────────────────────────────────────────────

def quic_block(ports=(443,)):
    """Drop outbound UDP on the given ports to force browsers off QUIC/HTTP3."""
    for port in _parse_ports(ports):
        _run_iptables('-I', 'OUTPUT', '-p', 'udp', '--dport', str(port), '-j', 'DROP')
        _run_ip6tables('-I', 'OUTPUT', '-p', 'udp', '--dport', str(port), '-j', 'DROP')
        logger.info("QUIC block rule added: UDP %d dropped", port)


def quic_unblock(ports=(443,)):
    """Remove the QUIC-blocking UDP DROP rules."""
    for port in _parse_ports(ports):
        try:
            _run_iptables('-D', 'OUTPUT', '-p', 'udp', '--dport', str(port), '-j', 'DROP',
                          silent=True)
        except Exception:
            pass
        try:
            _run_ip6tables('-D', 'OUTPUT', '-p', 'udp', '--dport', str(port), '-j', 'DROP',
                           silent=True)
        except Exception:
            pass
        logger.info("QUIC block rule removed: UDP %d", port)
