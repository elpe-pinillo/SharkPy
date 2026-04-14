import subprocess
import netifaces
import atexit
import logging

logger = logging.getLogger(__name__)

_rules_active = False


def _run_iptables(*args):
    cmd = ['iptables'] + list(args)
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        logger.error("iptables command failed: %s\n%s", ' '.join(cmd), e.stderr.decode())
        raise


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
    elif i == "lo":
        _run_iptables('-I', 'INPUT', '-i', i, '-j', 'NFQUEUE', '--queue-num', '0')
    else:
        _run_iptables('-I', 'INPUT', '-i', i, '-j', 'NFQUEUE', '--queue-num', '0')
        _run_iptables('-I', 'OUTPUT', '-o', i, '-j', 'NFQUEUE', '--queue-num', '0')
        _run_iptables('-A', 'FORWARD', '-i', i, '-j', 'NFQUEUE', '--queue-num', '0')

    _rules_active = True


def flush():
    global _rules_active
    try:
        subprocess.run(['iptables', '--flush'], check=True, capture_output=True)
        _rules_active = False
    except subprocess.CalledProcessError as e:
        logger.error("iptables flush failed: %s", e.stderr.decode())


def _atexit_flush():
    if _rules_active:
        logger.info("Flushing iptables rules on exit")
        flush()


atexit.register(_atexit_flush)


# ── TLS interception rules ────────────────────────────────────────────────────

def tls_intercept(intercept_port: int = 443, proxy_port: int = 8443):
    """Redirect TLS traffic to the SharkPy proxy port.
    Excludes the proxy process's own outbound connections to avoid looping."""
    import os
    uid = str(os.getuid())
    # Forwarded / inbound traffic
    _run_iptables('-t', 'nat', '-A', 'PREROUTING',
                  '-p', 'tcp', '--dport', str(intercept_port),
                  '-j', 'REDIRECT', '--to-port', str(proxy_port))
    # Local outbound — exclude our own process so we don't loop
    _run_iptables('-t', 'nat', '-A', 'OUTPUT',
                  '-p', 'tcp', '--dport', str(intercept_port),
                  '-m', 'owner', '!', '--uid-owner', uid,
                  '-j', 'REDIRECT', '--to-port', str(proxy_port))
    logger.info("TLS intercept rules added: port %d -> %d", intercept_port, proxy_port)


def tls_flush(intercept_port: int = 443, proxy_port: int = 8443):
    """Remove TLS interception iptables rules."""
    import os
    uid = str(os.getuid())
    for args in [
        ('-t', 'nat', '-D', 'PREROUTING',
         '-p', 'tcp', '--dport', str(intercept_port),
         '-j', 'REDIRECT', '--to-port', str(proxy_port)),
        ('-t', 'nat', '-D', 'OUTPUT',
         '-p', 'tcp', '--dport', str(intercept_port),
         '-m', 'owner', '!', '--uid-owner', uid,
         '-j', 'REDIRECT', '--to-port', str(proxy_port)),
    ]:
        try:
            _run_iptables(*args)
        except Exception:
            pass
    logger.info("TLS intercept rules removed")
