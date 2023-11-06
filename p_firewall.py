import os

def filter(mitm, i):
    flush()
    if mitm:
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    if i == "Any...":
        os.system('sudo iptables -I INPUT -j NFQUEUE --queue-num 0')
        os.system('sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0')
    elif i == "lo":
        os.system('sudo iptables -I INPUT -i ' + i + ' -j NFQUEUE --queue-num 0')
        # os.system('sudo iptables -I OUTPUT -o ' + i + ' -j NFQUEUE --queue-num 0')
    else:
        os.system('sudo iptables -I INPUT -i ' + i + ' -j NFQUEUE --queue-num 0')
        os.system('sudo iptables -I OUTPUT -o ' + i + ' -j NFQUEUE --queue-num 0')
    return

def flush():
    os.system('iptables --flush')
    return
