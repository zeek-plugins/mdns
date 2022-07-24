:orphan:

========================================
Zeek Package Documentation: Multicast DNS (mDNS) Protocol Analyzer for Zeek IDS
========================================

Package README
==============

The top-level README has information on how to install and test this Zeek Package.

.. toctree::
   :maxdepth: 2

   README.rst

Package Index
=============

For Zeek scripting details, such as options, functions and events, see the auto-generated documentation:

.. include:: build/packages/package_index.rst

Script Index
=============

This Zeek Package installs the following Zeek scripts:

.. include:: scripts/index.rst

Load Order
==========

How scripts get loaded is non-trivial. A quick summary follows.

The following steps *always* happen, regardless of whether the plugin gets loaded or not.

1. Zeek startup
2. Plugin activation
3. :doc:`__preload__.zeek </scripts/__preload__.zeek>` always gets loaded
   The preload mechanism is primarily for loading types, defined in :doc:`types.zeek </scripts/types.zeek>` which the rest of the scripts depend on.
4. :doc:`__load__.zeek </scripts/__load__.zeek>` always gets loaded

If the plugin is explicitly loaded (:code:`@load IoT/mdns`), the load process continues:

5. :doc:`IoT/mdns/__load__.zeek </scripts/IoT/mdns/__load__.zeek>` then loads the rest of the scripts.

Reference
=========

.. toctree::
   
   genindex
