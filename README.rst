========
Overview
========

.. start-badges

.. list-table::
    :stub-columns: 1

    * - docs
      - |docs|
    * - tests
      - | |travis| |requires|
        | |coveralls|
    * - package
      - | |version| |wheel| |supported-versions| |supported-implementations|
        | |commits-since|

.. |docs| image:: https://readthedocs.org/projects/pcap-compare/badge/?style=flat
    :target: https://readthedocs.org/projects/pcap-compare
    :alt: Documentation Status

.. |travis| image:: https://travis-ci.org/bewing/pcap-compare.svg?branch=master
    :alt: Travis-CI Build Status
    :target: https://travis-ci.org/bewing/pcap-compare

.. |requires| image:: https://requires.io/github/bewing/pcap-compare/requirements.svg?branch=master
    :alt: Requirements Status
    :target: https://requires.io/github/bewing/pcap-compare/requirements/?branch=master

.. |coveralls| image:: https://coveralls.io/repos/github/bewing/pcap-compare/badge.svg?branch=master
    :alt: Coveralls Status
    :target: https://coveralls.io/github/bewing/pcap-compare?branch=master

.. |version| image:: https://img.shields.io/pypi/v/pcap-compare.svg
    :alt: PyPI Package latest release
    :target: https://pypi.python.org/pypi/pcap-compare

.. |commits-since| image:: https://img.shields.io/github/commits-since/bewing/pcap-compare/v0.1.0.svg
    :alt: Commits since latest release
    :target: https://github.com/bewing/pcap-compare/compare/v0.1.0...master

.. |wheel| image:: https://img.shields.io/pypi/wheel/pcap-compare.svg
    :alt: PyPI Wheel
    :target: https://pypi.python.org/pypi/pcap-compare

.. |supported-versions| image:: https://img.shields.io/pypi/pyversions/pcap-compare.svg
    :alt: Supported versions
    :target: https://pypi.python.org/pypi/pcap-compare

.. |supported-implementations| image:: https://img.shields.io/pypi/implementation/pcap-compare.svg
    :alt: Supported implementations
    :target: https://pypi.python.org/pypi/pcap-compare


.. end-badges

Library to analyze timestamp data for "*identical*" (air-quotes) packets in pcap files

* Free software: BSD license

Installation
============

::

    pip install git+https://github.com/bewing/pcap-compare.git

Documentation
=============

Read the source

Development
===========

To run the all tests run::

    tox
