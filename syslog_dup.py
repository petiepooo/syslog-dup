#!/usr/bin/env python
''' sniffs syslogs and duplicates payload for another syslog daemon

    Copyright (C) 2015, all rights reserved
    Author Pete Nelson petiepooo@gmail.com
'''

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import sys
import argparse

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

#import pcapy
from scapy.layers.inet import IP, UDP
from scapy.all import sniff
from scapy.all import conf
from scapy.all import send
#import scapy.all as scapy

def main(params):
    'main function: called when invoked from the commandline'

    own_ip = [x[4] for x in conf.route.routes if x[2] != '0.0.0.0'][0]

    # parsing arguments
    parser = argparse.ArgumentParser(description='syslog duplicator - '
                                     'sniffs syslog packets and resends '
                                     'them to a new logger')
    parser.add_argument('-d', '--debug', action='count', default=0,
                        help='enable debug messages')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='suppress output messages')
    parser.add_argument('-n', '--no-output', action='store_true',
                        help='suppress output packets')
    parser.add_argument('-c', '--count', default=0, type=int,
                        help='number of packets to capture before exit')
    parser.add_argument('-s', '--src', default='source', metavar='IP',
                        nargs='?', help='source address (unspecified: use '
                        + own_ip + '; default: IP in sniffed packet)')
    parser.add_argument('-o', '--sport', type=int, metavar='PORT',
                        help='source port to use in output '
                        '(default: port in sniffed packet')
    parser.add_argument('-i', '--iface', metavar='IF', required=True,
                        help='interface to sniff')
    parser.add_argument('dst', type=str, help='destination host')
    parser.add_argument('dport', type=int, help='destination port')
    parser.add_argument('bpf', nargs=argparse.REMAINDER, metavar='...',
                        help='bpf expression (default: udp and port 514)')
    args = parser.parse_args()

    params.quiet = args.quiet
    bpf = 'udp and port 514'
    if args.bpf:
        bpf = ' '.join(args.bpf)

    def dprint(level, *pargs):
        'wrapper for print that checks debug level first'
        if args.debug > level:
            print(*pargs)

    def dshow(level, pkt):
        'wrapper for show that checks debug level first'
        if args.debug > level:
            pkt[IP].show()

    dprint(0, args)
    dprint(0, vars(params))
    dprint(0, 'bpf filter:', bpf)

    def process_packet(pkt):
        'callback from scapy sniff for each packet to be processed'

        params.pkts_rcvd += 1
        dprint(1, 'pkts_rcvd = ', params.pkts_rcvd)
        dprint(3, '------------- received packet ------------')
        dshow(3, pkt)

        # scapy bug: sometimes we see a few unfiltered packets on start
        # for now, override provided filter so we can reject
        # TODO: verify first 5-10 packets by other means
        if not pkt.haslayer(UDP) or \
                not pkt[UDP].dport == 514 and not pkt[UDP].sport == 514:
            return

        new_pkt = pkt[IP]
        # little known fact: deleting chksum causes them to regen on send
        del new_pkt[UDP].chksum
        del new_pkt[IP].chksum
        if args.src == None:		# -s with no IP entered, use own IP
            new_pkt[IP].src = own_ip
        elif args.src != 'source':	# -s with IP entered, use it
            new_pkt[IP].src = args.src
	# else no -s option; use source packet's IP
        if args.sport:
            new_pkt[UDP].sport = args.sport
        new_pkt[IP].dst = args.dst
        new_pkt[UDP].dport = args.dport

        dprint(2, '========== constructed packet ============')
        dshow(2, new_pkt)
        dprint(2, '==========================================')

        if args.no_output:
            dprint(1, 'packet not sent')

        else:
            send(new_pkt, verbose=False)
            params.pkts_sent += 1
            dprint(1, 'pkts_sent = ', params.pkts_sent)

    sniff(iface=args.iface, count=args.count, filter=bpf,
          prn=process_packet, store=0)

    return 0

class Globals(object):
    'a place to store my global variables to pass by reference'
    def __init__(self):
        'initialize global variables'
        self.pkts_rcvd = 0
        self.pkts_sent = 0
        self.quiet = True

    def sent_str(self):
        'returns "" or "s" depending on pkts_sent value'
        if self.pkts_sent == 1:
            return ''
        return 's'

    def rcvd_str(self):
        'returns "" or "s" depending on pkts_rcvd value'
        if self.pkts_rcvd == 1:
            return ''
        return 's'

GLOBALS = Globals()

if __name__ == '__main__':
    try:
        sys.exit(main(GLOBALS))
    except KeyboardInterrupt:
        pass
    finally:
        if not GLOBALS.quiet:
            print(' {} packet{} received, {} packet{} sent.'
                  .format(GLOBALS.pkts_rcvd,
                          GLOBALS.rcvd_str(),
                          GLOBALS.pkts_sent,
                          GLOBALS.sent_str()))

