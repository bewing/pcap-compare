import pytest
from click.testing import CliRunner

from pcap_compare import PcapCompare
from pcap_compare.cli import main


def test_pcap_compare():
    pc = PcapCompare()
    pytest.skip()


def test_main():
    runner = CliRunner()
    result = runner.invoke(main, [])

    assert result.output == '()\n'
    assert result.exit_code == 0
