rproxy
======

A super simple HTTP/1.1 proxy, with TLS and Let's Encrypt support.

rproxy takes care of your Let's Encrypt certificates, automatically renewing them.
This is done by the excellent `txacme <https://github.com/mithrandi/txacme>`_ library.

Install from PyPI:

.. code::

    $ pip install rproxy

Make a directory to store your certificates:

.. code::

    $ mkdir my-certs

Make a ``rproxy.ini``:

.. code::

    [rproxy]
    certificates=my-certs
    http_ports=80
    https_ports=443

    [hosts]
    mysite.com_port=8080

Then run it:

.. code::

   sudo twistd -u nobody -g nobody -n rproxy


This will start the server, drop permissions (setting the effective uid/guid to nobody), and will proxy incoming requests to ``mysite.com`` to ``localhost:8080``.
You can configure it further:

.. code::

    [rproxy]
    certificates=my-certs
    http_ports=80,8080
    https_ports=443
    clacks=true

    [hosts]
    mysite.com_port=8080
    mysite.com_host=otherserver
    mysite.com_onlysecure=True
    mysite.com_proxysecure=True

    myothersite.net_port=8081


This config will:

- connect to ``https://otherserver:8080`` as the proxied server for ``mysite.com``, and only allow HTTPS connections to the proxy for this site
- connect to ``http://localhost:8081`` as the proxied server for ``myothersite.net``, and allow HTTP or HTTPS connections.


General Config
--------------

- ``http_ports`` -- comma-separated list of numerical ports to listen on for HTTP connections.
- ``https_ports`` -- comma-separated list of numerical ports to listen on for HTTPS connections.
- ``certificates`` -- directory where certificates are kept.
- ``clacks`` -- Enable ``X-Clacks-Overhead`` for requests.


Hosts Config
------------

- ``<host>_onlysecure`` -- enforce HTTPS connections. If not set, or set to False, it will allow HTTP and HTTPS connections.
- ``<host>_proxysecure`` -- connect to the proxied server by HTTPS. If not set, or set to False, it will connect over HTTP.
- ``<host>_port`` -- The port of the proxied server that this proxy should connect to.
- ``<host>_host`` -- the hostname/IP of the server to proxy to.
- ``<host>_sendhsts`` -- send HSTS headers on HTTPS connections.
- ``<host>_wwwtoo`` -- match ``www`` too.
