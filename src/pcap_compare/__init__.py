from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division

from decimal import Decimal

import dpkt


class PcapCompare(object):
    """Class containing stats derived from pcap files for analysis."""
    # TODO Test replacing hash() with murmur if cpp
    def __init__(self):
        self.mask = (None, None)  # Slice tuple
        self._pkt_hash = {}
        self.hdr_hash = {}
        self.dirty = set()
        self.max_offset = 0.5

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

            src_tuple = (tuple(frame.vlan_tags), frame.src, frame.dst, ip.src, ip.dst, ip.data.sport, ip.data.dport)

            src_hash = hash(src_tuple)
            if self.hdr_hash.get(src_hash, None) is None:
                self.hdr_hash.update({
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
            buf_hash = hash(ip.data.data[slice(*self.mask)])
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
                if ts - self._pkt_hash[buf_hash]['start_time'] < 0 or abs(ts - self._pkt_hash[buf_hash]['start_time']) > self.max_offset:
                    self.dirty.add(buf_hash)

                self._pkt_hash[buf_hash]['pkt_list'].update({src_hash: ts - self._pkt_hash[buf_hash]['start_time']})

    @property
    def pkt_hash(self):
        if self.dirty:
            self.__clean()
        return self._pkt_hash

    def __clean(self):
        while self.dirty:
            to_check = self.dirty.pop()
            shift = sorted(self._pkt_hash[to_check]['pkt_list'].values())[0]
            self._pkt_hash[to_check]['start_time'] += shift
            for hsh, offset in self._pkt_hash[to_check]['pkt_list'].items():
                self._pkt_hash[to_check]['pkt_list'].update({hsh: offset + shift})
        self.dirty = set()
