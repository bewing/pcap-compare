from decimal import Decimal
import dpkt
from io import BytesIO

from pcap_compare import PcapCompare
from pcap_compare import util

EXAMPLE_VLAN = []  # TODO: FIGURE THIS SHIT OUT
EXAMPLE_IP = b'\xC0\x00\x02\x01'  # 192.0.2.1
EXAMPLE_MAC = b'\x00\x00\x5E\x00\x00\x00'  # 00:00:5E:00:00:00
EXAMPLE_NANOSTAMP = Decimal('1454725786.010203045')  # 02/06/2016 02:29 UTC


def test_pcap_compare():
    pc = PcapCompare()
    fobj = BytesIO()
    writer = dpkt.pcap.Writer(fobj, nano=True)
    test_frame, src = _create_udp_frame()
    src['ip.src'] = util.increment_bytestring(src['ip.src'])
    test_frame2, _ = _create_udp_frame(signature=src)
    test_frame3, src = _create_udp_frame(b'bar')
    src['ip.src'] = util.increment_bytestring(src['ip.src'])
    test_frame4, _ = _create_udp_frame(b'bar', signature=src)
    writer.writepkt(test_frame, ts=EXAMPLE_NANOSTAMP)
    writer.writepkt(test_frame2, ts=(EXAMPLE_NANOSTAMP + Decimal('1E-9')))
    writer.writepkt(test_frame3, ts=EXAMPLE_NANOSTAMP)
    writer.writepkt(test_frame4, ts=(EXAMPLE_NANOSTAMP + Decimal('1E-9')))
    fobj.flush()
    fobj.seek(0)
    pc.process_file(fobj)
    while pc.pkt_hash:
        k, v = pc.pkt_hash.popitem()
        # TODO:  Assert key
        ret = sorted(v['pkt_list'].values())
        assert ret[1] - ret[0] == Decimal('1E-9')


def test_pcap_misordered():
    pc = PcapCompare()
    fobj = BytesIO()
    writer = dpkt.pcap.Writer(fobj, nano=True)
    test_frame, src = _create_udp_frame()
    src['ip.src'] = util.increment_bytestring(src['ip.src'])
    test_frame2, _ = _create_udp_frame(signature=src)
    writer.writepkt(test_frame, ts=EXAMPLE_NANOSTAMP)
    writer.writepkt(test_frame2, ts=(EXAMPLE_NANOSTAMP - Decimal('1E-9')))
    fobj.flush()
    fobj.seek(0)
    pc.process_file(fobj)
    k, v = pc.pkt_hash.popitem()
    ret = sorted(v['pkt_list'].values())
    assert ret[1] - ret[0] == Decimal('0.000000001')


def test_pcap_mask():
    pc = PcapCompare(mask=(1, None))
    fobj = BytesIO()
    writer = dpkt.pcap.Writer(fobj, nano=True)
    test_frame, src = _create_udp_frame()
    src['ip.src'] = util.increment_bytestring(src['ip.src'])
    test_frame2, _ = _create_udp_frame(payload=b'B' + b'A'*99, signature=src)
    writer.writepkt(test_frame, ts=EXAMPLE_NANOSTAMP)
    writer.writepkt(test_frame2, ts=(EXAMPLE_NANOSTAMP + Decimal('1E-9')))
    fobj.flush()
    fobj.seek(0)
    pc.process_file(fobj)
    k, v = pc.pkt_hash.popitem()
    # TODO:  Assert key
    ret = sorted(v['pkt_list'].values())
    assert ret[1] - ret[0] == Decimal('0.000000001')


def test_pcap_offset():
    pc = PcapCompare(max_offset=Decimal('1E-9'))
    fobj = BytesIO()
    writer = dpkt.pcap.Writer(fobj, nano=True)
    test_frame, src = _create_udp_frame()
    src['ip.src'] = util.increment_bytestring(src['ip.src'])
    test_frame2, _ = _create_udp_frame(signature=src)
    writer.writepkt(test_frame, ts=EXAMPLE_NANOSTAMP)
    writer.writepkt(test_frame2, ts=EXAMPLE_NANOSTAMP + Decimal('2E-9'))
    fobj.flush()
    fobj.seek(0)
    pc.process_file(fobj)
    while pc.pkt_hash:
        k, v = pc.pkt_hash.popitem()
        assert len(v['pkt_list']) == 1


def _create_udp_frame(payload=b'A'*100, signature={}):
    """Helper method to create UDP packets for testing."""
    sig = {
        'eth.vlan': EXAMPLE_VLAN,
        'eth.src': EXAMPLE_MAC,
        'eth.dst': EXAMPLE_MAC,
        'ip.src': EXAMPLE_IP,
        'ip.dst': EXAMPLE_IP,
        'sport': 1025,
        'dport': 1025,
    }
    sig.update(signature)
    udp = dpkt.udp.UDP(sport=sig['sport'], dport=sig['dport'])
    udp.data = payload
    udp.ulen += len(udp.data)
    ip = dpkt.ip.IP(src=sig['ip.src'], dst=sig['ip.dst'], p=17, data=udp)
    frame = dpkt.ethernet.Ethernet(
        src=sig['eth.src'], dst=sig['eth.dst'], vlan_tags=sig['eth.vlan'], data=ip)

    return frame, sig
