from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division

from decimal import Decimal

import dpkt


class PcapCompare(object):
    """Class containing stats derived from pcap files for analysis."""
    # TODO Test replacing hash() with murmur if cpp
    def __init__(self, mask=(None, None), max_offset=Decimal(0.5)):
        self._mask = mask
        self._pkt_hash = {}
        self._hdr_hash = {}
        self._dirty = set()
        self._max_offset = max_offset

    def process_file(self, fh):
        pcap = dpkt.pcap.Reader(fh)  # TODO BPF Filtering?
        for ts, buf in pcap:
            try:
                frame = dpkt.ethernet.Ethernet(buf)
            except dpkt.UnpackError:
                print("Invalid packet!")
                # TODO LOG SOMETHING
                continue

            if not isinstance(frame.data, dpkt.ip.IP):
                print("Not an IP packet!")
                # TODO LOG SOMETHING
                continue

            if not hasattr(frame, 'vlan_tags'):
                frame.vlan_tags = []

            ip = frame.data

            if not isinstance(ip.data, (dpkt.udp.UDP, dpkt.tcp.TCP)):
                print("Not a TCP/UDP packet!")
                # TODO LOG SOMETHING
                continue

            src_tuple = (tuple(frame.vlan_tags), frame.src, frame.dst,
                         ip.src, ip.dst, ip.data.sport, ip.data.dport)

            src_hash = hash(src_tuple)
            if self._hdr_hash.get(src_hash, None) is None:
                self._hdr_hash.update({
                    src_hash: {
                        "eth.vlan": frame.vlan_tags,
                        "eth.src": frame.src,
                        "eth.dst": frame.dst,
                        "ip.src": ip.src,
                        "ip.dst": ip.dst,
                        "sport": ip.data.sport,
                        "dport": ip.data.dport,
                    },
                })
            buf_hash = hash(ip.data.data[slice(*self._mask)])
            if self._pkt_hash.get(buf_hash, None) is None:
                self._pkt_hash.update({
                    buf_hash: {
                        'start_time': ts,
                        'pkt_list': {
                            src_hash: Decimal(0),
                        },
                    },
                })
            else:
                if ts - self._pkt_hash[buf_hash]['start_time'] < 0 or abs(
                        ts - self._pkt_hash[buf_hash]['start_time']) > self._max_offset:
                    self._dirty.add(buf_hash)

                self._pkt_hash[buf_hash]['pkt_list'].update(
                    {src_hash: ts - self._pkt_hash[buf_hash]['start_time']})

    @property
    def pkt_hash(self):
        if self._dirty:
            self.__clean()
        return self._pkt_hash

    def __clean(self):
        while self._dirty:
            # Get bucket to work on
            this_hash = self._dirty.pop()
            next_hash = this_hash + 1
            to_check = self._pkt_hash.pop(this_hash)
            # Get lowest offset from timestamp
            shift = sorted(to_check['pkt_list'].values())[0]
            # shift this bucket's start time (Might shift 0)
            to_check['start_time'] = to_check['start_time'] + shift
            this_bucket = {'start_time': to_check['start_time'], 'pkt_list': {}}
            next_bucket = {'start_time': to_check['start_time'], 'pkt_list': {}}
            # Rework the packet list
            while to_check['pkt_list']:
                hsh, offset = to_check['pkt_list'].popitem()
                new_offset = offset - shift
                if abs(new_offset) > self._max_offset:
                    next_bucket['pkt_list'].update({hsh: new_offset})
                else:
                    this_bucket['pkt_list'].update({hsh: new_offset})
            if len(this_bucket['pkt_list']) > 0:
                self._pkt_hash.update({this_hash: this_bucket})
            if len(next_bucket['pkt_list']) > 0:
                self._dirty.add(next_hash)
                self._pkt_hash.update({next_hash: next_bucket})
        self._dirty = set()
