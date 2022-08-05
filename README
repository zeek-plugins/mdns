Multicast DNS (mDNS) package for Zeek IDS
================================================


This repository contains a `Zeek <https://zeek.org/>`_ package for the `Multicast DNS (mDNS) protocol <https://en.wikipedia.org/wiki/Multicast_DNS>`_.
The package can be easily installed with `Zeek Package Manager <https://docs.zeek.org/projects/package-manager/en/stable/>`_.

Please consult the following RFCs for additional information about the Multicast DNS protocol:
- DNS: `RFC 1035 <https://datatracker.ietf.org/doc/html/rfc1035>`_
- Multicast DNS: `RFC 6762 <https://datatracker.ietf.org/doc/html/rfc6762>`_


Prerequisites
-------------

Before trying to install the package, make sure you have the following tools installed:

- `Zeek <https://zeek.org/>`_
- `Zeek Package Manager <https://docs.zeek.org/projects/package-manager/en/stable/>`_ command :code:`zkg`

Everything should be installed correctly if you install the latest `Zeek <https://zeek.org/>`_ version.


Installation
----------

To run unit tests and install the package, run:
.. code-block:: bash

      zkg install https://github.com/zeek-plugins/mdns  # to install as super user
      zkg --user install https://github.com/zeek-plugins/mdns  # to install in user space


You might have to update the `ZEEKPATH` and `ZEEK_PLUGIN_PATH` environmental variables.
To see which value they should take, run the following commands:
.. code-block:: bash

      zkg env         # For the super user
      zkg --user env  # For a normal user


To confirm that installation was successful, you can run the following command:
.. code-block:: bash

      zeek -NN | grep mDNS


If the command's output shows something similar to:
.. code-block:: bash

      IoT::mDNS - Multicast DNS (mDNS) package for Zeek (dynamic, version 1.0.0)

the package was correctly installed, and you have access to the mDNS package.

In the case of any installation problems, please check the `Zeek Package Manager <https://docs.zeek.org/projects/package-manager/en/stable/>`_ documentation.


License
-------

This project is licensed under the BSD license. See the `COPYING <COPYING>`_ file for details.


Contributors
------------


- François De Keersmaeker
  - GitHub: `@fdekeers <https://github.com/fdekeers>`_
  - Email: francois.dekeersmaeker@uclouvain.be

Thanks to the ESnet team for `Zeek Package Cookie Cutter <https://github.com/esnet/cookiecutter-zeekpackage>`_.
