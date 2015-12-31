#!/usr/bin/env python

import logging
import logging.handlers
import re
import sys
import subprocess

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import Ether, ARP, srp1


def get_arp_cache(addr, dev):
    command = '/sbin/ip neigh show to %s dev %s' % (addr, dev)
    proc = subprocess.Popen(
        command,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    stdout_data, stderr_data = proc.communicate()

    if proc.returncode != 0:
        output = (
            'subprocess exited with return code (%s), ' % proc.returncode +
            'command: (%s), ' % command +
            'stdout: (%s), ' % stdout_data.replace('\n', '') +
            'stderr: (%s)' % stderr_data.replace('\n', ''))
        print(output)
        sys.exit(3)

    p = re.compile(r'%s lladdr ([0-9a-f:]{17}) ([A-Z]+)' % addr)
    m = p.match(stdout_data)
    if m:
        dstmac = m.group(1)
        nud_state = m.group(2)
        return (dstmac, nud_state)
    else:
        return (None, None)


def set_or_update_arp_cache(addr, lladdr, dev, nud_state):
    command = '/sbin/ip neigh replace %s lladdr %s nud %s dev %s' % (
        addr, lladdr, nud_state, dev)
    proc = subprocess.Popen(
        command,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    stdout_data, stderr_data = proc.communicate()

    if proc.returncode != 0:
        output = (
            'subprocess exited with return code (%s), ' % proc.returncode +
            'command: (%s), ' % command +
            'stdout: (%s), ' % stdout_data.replace('\n', '') +
            'stderr: (%s)' % stderr_data.replace('\n', ''))
        print(output)
        sys.exit(3)


def arp_broadcast(pdst, iface, timeout):
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=pdst)
    reply = srp1(request, iface=iface, timeout=timeout, verbose=0)
    return reply


def arp_unicast(dstmac, pdst, iface, timeout):
    request = Ether(dst=dstmac) / ARP(op=1, pdst=pdst)
    reply = srp1(request, iface=iface, timeout=timeout, verbose=0)
    return reply


def arp_floody(dstmac, pdst, hwsrc, iface, timeout):
    request = Ether(dst=dstmac) / ARP(op=1, pdst=pdst, hwsrc=hwsrc)
    reply = srp1(request, iface=iface, timeout=timeout, verbose=0)
    return reply


pdst = sys.argv[1]
hwsrc = "00:50:56:be:ee:ef"
iface = "vlan1001"
timeout = 3

logger = logging.getLogger('flooder')
logger.setLevel(logging.ERROR)
syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
syslog_handler.setFormatter(logging.Formatter('%(process)d %(message)s'))
logger.addHandler(syslog_handler)

logger.info('begin %s' % pdst)

dstmac, nud_state = get_arp_cache(pdst, iface)

if dstmac is None:
    reply = arp_broadcast(pdst, iface, timeout)
    if reply is None:
        print('%s: no arp reply received' % pdst)
        sys.exit(2)
    else:
        dstmac = reply[ARP].hwsrc
        set_or_update_arp_cache(pdst, dstmac, iface, 'reachable')

elif nud_state != 'REACHABLE':
    reply = arp_unicast(dstmac, pdst, iface, timeout)
    if reply is None:
        print('%s: was-at %s on kernel arp cache but gone' % (pdst, dstmac))
        sys.exit(2)
    else:
        set_or_update_arp_cache(pdst, dstmac, iface, 'reachable')

reply = arp_floody(dstmac, pdst, hwsrc, iface, timeout)
if reply:
    print('%s: is-at %s' % (reply[ARP].psrc, reply[ARP].hwsrc))
    exit(0)
else:
    print('%s: is-at %s but no floody arp reply received' % (
        pdst, dstmac))
    exit(2)
