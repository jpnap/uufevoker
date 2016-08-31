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
from scapy.all import conf, Ether, ARP, sendp, sniff
from scapy.all import IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr

dev = 'vlan1001'

def pkt_callback(pkt):
    pkt.show() # debug statement
    if ICMPv6ND_NS in pkt:
        srcmac = netifaces.ifaddresses(dev)[netifaces.AF_LINK][0]['addr']
        #srcmac = pkt[Ether].dst
        dstmac = pkt[Ether].src
        dstip = pkt[IPv6].src
        srcip = pkt[IPv6].dst

        request = Ether(src=srcmac, dst=dstmac) / IPv6(src=srcip, dst=dstip) / ICMPv6ND_NA(tgt=srcip, R=0, S=1, O=0)
        sendp(request, iface=dev)


conf.iface = dev
sniff(iface=dev, prn=pkt_callback, filter='ether dst 02:00:00:be:ee:f6', store=0)
