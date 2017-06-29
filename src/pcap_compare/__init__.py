from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division

import dpkt


class PcapCompare(object):
    """Class containing stats derived from pcap files for analysis."""
    # TODO Test replacing hash() with murmur if cpp
    def __init__(self):
        self.mask = (None, None)  # Slice tuple
        self.pkt_hash = {}
        self.hdr_hash = {}

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
                        "src_port": ip.data.sport,
                        "dst_port": ip.data.dport,
                    },
                })
            buf_hash = hash(buf[slice(*self.mask)])
            if self.pkt_hash.get(buf_hash, None) is None:
                self.pkt_hash.update({
                    buf_hash: []
                })
            self.pkt_hash.get(buf_hash).append((ts, src_hash))

    def process_stats(self, max_offset=0.5):
        lose_by = {k: [] for k in self.hdr_hash.keys()}
        while self.pkt_hash:
            # Get next `unique` payload
            h, pkt_list = self.pkt_hash.popitem()
            # Sort by arrival time
            pkt_list.sort(key=lambda tup: tup[0])
            # Record first arrival time
            start_time = pkt_list[0][0]
            while pkt_list:
                # Grab the next arrival
                ts, src_hash = pkt_list.pop(0)
                if ts - start_time > max_offset:
                    # Greater than offset, treat remaining as `new` payload
                    pkt_list.insert(0, (ts, src_hash))
                    self.pkt_hash.update({h: pkt_list})
                else:
                    lose_by.get(src_hash).append(ts - start_time)
        return lose_by
