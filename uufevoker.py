#!/usr/bin/env python

import getopt
import logging
import logging.handlers
import netaddr
from netaddr import IPAddress, EUI
import netifaces
import os
import re
import sys
import subprocess

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import conf, Ether, ARP, srp1
from scapy.all import IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr


def get_ip_and_mac(af, dev):
    mac = netifaces.ifaddresses(dev)[netifaces.AF_LINK][0]['addr']
    ip = None
    if af == 4:
        ip = netifaces.ifaddresses(dev)[netifaces.AF_INET][0]['addr']
    elif af == 6:
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


def arp_broadcast(srcmac, psrc, pdst, iface, timeout, verbose=0):
    ether_layer = Ether(src=srcmac, dst='ff:ff:ff:ff:ff:ff')
    arp_layer = ARP(op=1, hwsrc=srcmac, psrc=psrc, pdst=pdst)
    request = ether_layer / arp_layer
    f = (
        'ether dst %s and ' % srcmac +
        'arp and ' +
        'arp[6:2] = 0x0002 and ' +  # op: is-at(2)
        'arp[14:4] = 0x%x and ' % IPAddress(pdst) +  # psrc
        'arp[24:4] = 0x%x' % IPAddress(psrc))  # pdst
    conf.iface = iface
    reply = srp1(request, iface=iface, filter=f, timeout=timeout, verbose=verbose)
    return reply


def arp_unicast(srcmac, dstmac, psrc, pdst, iface, timeout, verbose=0):
    ether_layer = Ether(src=srcmac, dst=dstmac)
    arp_layer = ARP(op=1, hwsrc=srcmac, psrc=psrc, pdst=pdst)
    request = ether_layer / arp_layer
    f = (
        'ether src %s and ' % dstmac +
        'ether dst %s and ' % srcmac +
        'arp and ' +
        'arp[6:2] = 0x0002 and ' +  # op: is-at(2)
        'arp[14:4] = 0x%x and ' % IPAddress(pdst) +  # psrc
        'arp[24:4] = 0x%x' % IPAddress(psrc))  # pdst
    conf.iface = iface
    reply = srp1(request, iface=iface, filter=f, timeout=timeout, verbose=verbose)
    return reply


def arp_trick(srcmac, dstmac, hwsrc, psrc, pdst, iface, timeout, verbose=0):
    ether_layer = Ether(src=srcmac, dst=dstmac)
    arp_layer = ARP(op=1, hwsrc=hwsrc, psrc=psrc, pdst=pdst)
    request = ether_layer / arp_layer
    f = (
        'ether src %s and ' % dstmac +
        'ether dst %s and ' % hwsrc +
        'arp and ' +
        'arp[6:2] = 0x0002 and ' +  # op: is-at(2)
        'arp[14:4] = 0x%x and ' % IPAddress(pdst) +  # psrc
        'arp[24:4] = 0x%x' % IPAddress(psrc))  # pdst
    conf.iface = iface
    reply = srp1(request, iface=iface, filter=f, timeout=timeout, verbose=verbose)
    return reply


def nd_broadcast(srcmac, psrc, pdst, iface, timeout, verbose=0):
    request = Ether() / IPv6(src=psrc) / ICMPv6ND_NS(tgt=pdst) / ICMPv6NDOptSrcLLAddr(lladdr=srcmac)
    reply = srp1(request, iface=iface, timeout=timeout, verbose=verbose)
    return reply


def nd_unicast(srcmac, dstmac, psrc, pdst, iface, timeout, verbose=0):
    request = Ether(src=srcmac, dst=dstmac) / IPv6(src=psrc, dst=pdst) / ICMPv6ND_NS(tgt=pdst) / ICMPv6NDOptSrcLLAddr(lladdr=srcmac)
    reply = srp1(request, iface=iface, timeout=timeout, verbose=verbose)
    return reply


def nd_trick(srcmac, dstmac, hwsrc, psrc, pdst, iface, timeout, verbose=0):
    request = Ether(src=srcmac, dst=dstmac) / IPv6(src=psrc, dst=pdst) / ICMPv6ND_NS(tgt=pdst) / ICMPv6NDOptSrcLLAddr(lladdr=hwsrc)
    reply = srp1(request, iface=iface, timeout=timeout, verbose=verbose)
    return reply


def resolve_broadcast(af, srcmac, psrc, pdst, iface, timeout, verbose=0):
    resolved_mac = None
    if af == 4:
        reply = arp_broadcast(srcmac, psrc, pdst, iface, timeout, verbose)
        if reply:
            resolved_mac = reply[ARP].hwsrc
    elif af == 6:
        reply = nd_broadcast(srcmac, psrc, pdst, iface, timeout, verbose)
        if reply:
            resolved_mac = reply[ICMPv6NDOptDstLLAddr].lladdr

    return resolved_mac


def resolve_unicast(af, srcmac, dstmac, psrc, pdst, iface, timeout, verbose=0):
    reply = None
    if af == 4:
        reply = arp_unicast(srcmac, dstmac, psrc, pdst, iface, timeout, verbose)
    elif af == 6:
        reply = nd_unicast(srcmac, dstmac, psrc, pdst, iface, timeout, verbose)

    return reply


def send_trick(af, srcmac, dstmac, hwsrc, psrc, pdst, iface, timeout, verbose=0):
    reply = None
    if af == 4:
        reply = arp_trick(srcmac, dstmac, hwsrc, psrc, pdst, iface, timeout, verbose)
    elif af == 6:
        reply = nd_trick(srcmac, dstmac, hwsrc, psrc, pdst, iface, timeout, verbose)

    return reply



def usage():
    print('TBD')


iface = None
pdst = None
hwsrc = '02:00:00:be:ee:ef'
psrc = None
timeout = 3
verbose = 0
af = 4 # default IPv4

# parse options
try:
    opts, args = getopt.getopt(sys.argv[1:], 'h46i:d:S:s:t:v', [
        'help',
        'ipv4',
        'ipv6',
        'interface=',
        'pdst=',
        'hwsrc=',
        'psrc=',
        'timeout=',
        'verbose'])
except getopt.GetoptError as err:
    print(err)
    usage()
    sys.exit(3)
for o, a in opts:
    if o in ('-h', '--help'):
        usage()
        sys.exit()
    elif o in ('-4', '--ipv4'):
        af = 4
    elif o in ('-6', '--ipv6'):
        af = 6
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
    elif o in ('-v', '--verbose'):
        verbose = 256
    else:
        assert False, 'unhandled option'


logger = logging.getLogger('uufevoker')
logger.setLevel(logging.DEBUG)

syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
syslog_handler.setFormatter(logging.Formatter('%(name)s %(thread)X %(message)s'))
logger.addHandler(syslog_handler)

class StreamToLogger(object):
   def __init__(self, logger, log_level=logging.INFO):
      self.logger = logger
      self.log_level = log_level

   def write(self, buf):
      for line in buf.rstrip().splitlines():
         self.logger.log(self.log_level, line.rstrip())

sys.stdout = StreamToLogger(logger, logging.INFO)

my_mac, my_ip = get_ip_and_mac(af, iface)

dstmac, nud_state = get_arp_cache(pdst, iface)

if dstmac is None:
    resolved_mac = resolve_broadcast(af, my_mac, my_ip, pdst, iface, timeout, verbose)
    if resolved_mac is None:
        os.write(1, '%s: no arp reply received\n' % pdst)
        sys.exit(2)
    else:
        dstmac = resolved_mac
        set_or_update_arp_cache(pdst, dstmac, iface, 'reachable')

elif nud_state != 'REACHABLE':
    reply = resolve_unicast(af, my_mac, dstmac, my_ip, pdst, iface, timeout, verbose)
    if reply is None:
        flush_arp_cache(pdst, iface)
        os.write(1, '%s: was-at %s on kernel arp cache but gone\n' % (
            pdst, dstmac))
        sys.exit(2)
    else:
        set_or_update_arp_cache(pdst, dstmac, iface, 'reachable')

reply = send_trick(af, my_mac, dstmac, hwsrc, psrc, pdst, iface, timeout, verbose)
if reply:
    set_or_update_arp_cache(pdst, dstmac, iface, 'reachable')
    os.write(1, '%s: is-at %s\n' % (pdst, dstmac))
    exit(0)
else:
    flush_arp_cache(pdst, iface)
    set_or_update_arp_cache(pdst, dstmac, iface, 'stale')
    os.write(1, '%s: is-at %s but no trick arp reply received\n' % (
        pdst, dstmac))
    exit(2)
