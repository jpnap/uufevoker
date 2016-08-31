#!/usr/bin/env python

import getopt
import logging
import logging.handlers
import netaddr
from netaddr import IPAddress, EUI
import netifaces
import re
import sys
import subprocess

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import conf, Ether, IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, srp1


def get_ip_and_mac(dev):
    mac = netifaces.ifaddresses(dev)[netifaces.AF_LINK][0]['addr']
    ip = netifaces.ifaddresses(dev)[netifaces.AF_INET6][0]['addr']
    return (mac, ip)


def get_arp_cache(addr, dev):
    command = '/sbin/ip neigh show to %s dev %s' % (addr, dev)
    stdout_data, stderr_data = _run_ip_command(command)

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
    _run_ip_command(command)


def flush_arp_cache(addr, dev):
    command = '/sbin/ip neigh flush to %s dev %s' % (addr, dev)
    _run_ip_command(command)


def _run_ip_command(command):
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

    return (stdout_data, stderr_data)


def nd_broadcast(srcmac, psrc, pdst, iface, timeout):
    request = Ether() / IPv6(src=psrc) / ICMPv6ND_NS(tgt=pdst) / ICMPv6NDOptSrcLLAddr(lladdr=srcmac)
    reply = srp1(request, iface=iface, timeout=timeout)
    return reply


def nd_unicast(srcmac, dstmac, psrc, pdst, iface, timeout):
    request = Ether(src=srcmac, dst=dstmac) / IPv6(src=psrc, dst=pdst) / ICMPv6ND_NS(tgt=pdst) / ICMPv6NDOptSrcLLAddr(lladdr=srcmac)
    reply = srp1(request, iface=iface, timeout=timeout)
    return reply


def nd_trick(srcmac, dstmac, hwsrc, psrc, pdst, iface, timeout):
    request = Ether(src=srcmac, dst=dstmac) / IPv6(src=psrc, dst=pdst) / ICMPv6ND_NS(tgt=pdst) / ICMPv6NDOptSrcLLAddr(lladdr=hwsrc)
    reply = srp1(request, iface=iface, timeout=timeout)
    return reply


def usage():
    print('TBD')


iface = None
pdst = None
hwsrc = '02:00:00:be:ee:ef'
psrc = None
timeout = 3

# parse options
try:
    opts, args = getopt.getopt(sys.argv[1:], 'hi:d:S:s:t:', [
        'help',
        'interface=',
        'pdst=',
        'hwsrc=',
        'psrc=',
        'timeout='])
except getopt.GetoptError as err:
    print(err)
    usage()
    sys.exit(3)
for o, a in opts:
    if o in ('-h', '--help'):
        usage()
        sys.exit()
    elif o in ('-i', '--interface'):
        iface = a
    elif o in ('-d', '--pdst'):
        pdst = str(IPAddress(a))
    elif o in ('-S', '--hwsrc'):
        hwsrc = str(EUI(a, dialect=netaddr.mac_unix))
    elif o in ('-s', '--psrc'):
        psrc = str(IPAddress(a))
    elif o in ('-t', '--timeout'):
        timeout = int(a)
    else:
        assert False, 'unhandled option'


logger = logging.getLogger('uufevoker')
logger.setLevel(logging.ERROR)
syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
syslog_handler.setFormatter(logging.Formatter('%(process)d %(message)s'))
logger.addHandler(syslog_handler)

logger.info('begin %s' % pdst)

my_mac, my_ip = get_ip_and_mac(iface)

dstmac, nud_state = get_arp_cache(pdst, iface)

if dstmac is None:
    reply = nd_broadcast(my_mac, my_ip, pdst, iface, timeout)
    if reply is None:
        print('%s: no arp reply received' % pdst)
        sys.exit(2)
    else:
        dstmac = reply[Ether].src
        set_or_update_arp_cache(pdst, dstmac, iface, 'reachable')

elif nud_state != 'REACHABLE':
    reply = nd_unicast(my_mac, dstmac, my_ip, pdst, iface, timeout)
    if reply is None:
        flush_arp_cache(pdst, iface)
        print('%s: was-at %s on kernel arp cache but gone' % (pdst, dstmac))
        sys.exit(2)
    else:
        set_or_update_arp_cache(pdst, dstmac, iface, 'reachable')

reply = nd_trick(my_mac, dstmac, hwsrc, psrc, pdst, iface, timeout)
if reply:
    set_or_update_arp_cache(pdst, dstmac, iface, 'reachable')
    print('%s: is-at %s' % (reply[IPv6].src, reply[Ether].src))
    exit(0)
else:
    flush_arp_cache(pdst, iface)
    set_or_update_arp_cache(pdst, dstmac, iface, 'stale')
    print('%s: is-at %s but no trick arp reply received' % (
        pdst, dstmac))
    exit(2)
