# (C) Amber Brown. See LICENSE for details.

from __future__ import absolute_import, division

import ConfigParser

from zope.interface import implementer

from urllib import urlencode
from urlparse import urlparse

from twisted.application import service, strports
from twisted.application.service import Service
from twisted.internet import reactor
from twisted.internet.defer import Deferred, succeed
from twisted.internet.protocol import Protocol
from twisted.python import usage
from twisted.python.filepath import FilePath
from twisted.web import server, http
from twisted.web.client import Agent, HTTPConnectionPool
from twisted.web.iweb import IBodyProducer
from twisted.web.resource import Resource, EncodingResourceWrapper

from ._version import __version__



class Downloader(Protocol):
    def __init__(self, finished, write):
        self.finished = finished
        self._write = write

    def dataReceived(self, bytes):
        self._write(bytes)

    def connectionLost(self, reason):
        self.finished.callback(None)


@implementer(IBodyProducer)
class StringProducer(object):

    def __init__(self, body):
        self.body = body.read()
        self.length = len(self.body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass


class RProxyResource(Resource):

    isLeaf = True

    def __init__(self, hosts, clacks, pool, reactor, extraHeaders, anonymous):
        self._clacks = clacks
        self._hosts = hosts
        self._agent = Agent(reactor, pool=pool)
        self._extraHeaders = extraHeaders
        self._anonymous = anonymous

    def render(self, request):

        host = self._hosts.get(request.getRequestHostname().lower())

        if not host and request.getRequestHostname().lower().startswith("www."):
            host = self._hosts.get(request.getRequestHostname().lower()[4:])

            # The non-www host doesn't want to match to www.
            if not host["wwwtoo"]:
                host = None

        if not host:
            request.code = 404
            request.responseHeaders.setRawHeaders("Server",
                                                  [__version__.package + " " + __version__.base()])
            return b"I can't seem to find a domain by that name. Look behind the couch?"

        if host["onlysecure"] and not request.isSecure():
            urlpath = request.URLPath()
            urlpath.scheme = "https"
            request.redirect(str(urlpath))
            return b""

        url = "{}://{}:{}/{}".format(
            "https" if host["proxysecure"] else "http",
            host["host"], host["port"], request.path[1:])

        urlFragments = urlparse(request.uri)

        if urlFragments.query:
            url += "?" + urlFragments.query

        for x in [b'content-length', b'connection', b'keep-alive', b'te',
            b'trailers', b'transfer-encoding', b'upgrade',
            b'proxy-connection']:
            request.requestHeaders.removeHeader(x)

        prod = StringProducer(request.content)

        d = self._agent.request(request.method, url,
                                request.requestHeaders, prod)

        def write(res):

            request.code = res.code
            old_headers = request.responseHeaders
            request.responseHeaders = res.headers
            request.responseHeaders.setRawHeaders(
                'content-encoding',
                old_headers.getRawHeaders('content-encoding', []))
            if not self._anonymous:
                request.responseHeaders.addRawHeader("X-Proxied-By",
                                                     __version__.package + " " + __version__.base())

            if request.isSecure() and host["sendhsts"]:
                request.responseHeaders.setRawHeaders("Strict-Transport-Security",
                                                      ["max-age=31536000"])

            if self._clacks:
                request.responseHeaders.addRawHeader("X-Clacks-Overhead",
                                                     "GNU Terry Pratchett")

            for name, values in self._extraHeaders:
                request.responseHeaders.setRawHeaders(name, values)

            f = Deferred()
            res.deliverBody(Downloader(f, request.write))
            f.addCallback(lambda _: request.finish())
            return f

        def failed(res):
            request.setResponseCode(http.INTERNAL_SERVER_ERROR)
            for name, values in self._extraHeaders:
                request.responseHeaders.setRawHeaders(name, values)
            request.write(str(res))
            request.finish()
            return res

        d.addCallback(write)
        d.addErrback(failed)

        return server.NOT_DONE_YET


class Options(usage.Options):
    optParameters = [
        ['config', None, 'rproxy.ini', 'Config.']
    ]


def makeService(config):

    ini = ConfigParser.RawConfigParser()
    ini.read(config['config'])

    configPath = FilePath(config['config']).parent()

    rproxyConf = dict(ini.items("rproxy"))
    hostsConf = dict(ini.items("hosts"))

    hosts = {}

    for k, v in hostsConf.items():

        k = k.lower()
        hostname, part = k.rsplit("_", 1)

        if hostname not in hosts:
            hosts[hostname] = {}

        hosts[hostname][part] = v

    if not hosts:
        raise ValueError("No hosts configured.")

    for i in hosts:

        if "port" not in hosts[i]:
            raise ValueError("All hosts need a port.")

        if "host" not in hosts[i]:
            print("%s does not have a host, making localhost" % (i,))
            hosts[i]["host"] = "localhost"

        if "onlysecure" not in hosts[i]:
            print("%s does not have an onlysecure setting, making False" % (i,))
            hosts[i]["onlysecure"] = False

        if "wwwtoo" not in hosts[i]:
            print("%s does not have an wwwtoo setting, making True" % (i,))
            hosts[i]["wwwtoo"] = "True"

        if "proxysecure" not in hosts[i]:
            print("%s does not have an proxysecure setting, making False" % (i,))
            hosts[i]["proxysecure"] = False

        if "sendhsts" not in hosts[i]:
            print("%s does not have an sendhsts setting, making the value of onlysecure" % (i,))
            hosts[i]["sendhsts"] = hosts[i]["onlysecure"]

        hosts[i]["onlysecure"] = True if hosts[i]["onlysecure"]=="True" else False
        hosts[i]["proxysecure"] = True if hosts[i]["proxysecure"]=="True" else False
        hosts[i]["sendhsts"] = True if hosts[i]["sendhsts"]=="True" else False
        hosts[i]["wwwtoo"] = True if hosts[i]["wwwtoo"]=="True" else False

        if hosts[i]["onlysecure"] and not hosts[i]["proxysecure"]:
            if not hosts[i].get("iamokwithalocalnetworkattackerpwningmyusers", "False") == "True":
                raise ValueError("%s has onlysecure==True, but proxysecure==False. This will mean TLS protected requests will not be TLS-protected between the proxy and the proxied server. If this is okay (e.g., if it's going over localhost), set %s_iamokwithalocalnetworkattackerpwningmyusers=True in your config." % (i, i))

        if hosts[i]["proxysecure"] and not hosts[i]["onlysecure"]:
            if not hosts[i].get("iamokwithlyingtomyproxiedserverthatheuserisoverhttps", "False") == "True":
                raise ValueError("%s has onlysecure==False, but proxysecure==True. This means that the connection may not be TLS protected between the user and this proxy, only the proxy and the proxied server. This can trick your proxied server into thinking the user is being served over HTTPS. If this is okay (I can't imagine why it is), set %s_iamokwithlyingtomyproxiedserverthatheuserisoverhttps=True in your config." % (i, i))

    from twisted.internet import reactor
    pool = HTTPConnectionPool(reactor)

    resource = EncodingResourceWrapper(
        RProxyResource(hosts, rproxyConf.get("clacks"), pool, reactor, {}, False),
        [server.GzipEncoderFactory()])

    site = server.Site(resource)
    multiService = service.MultiService()
    certificates = rproxyConf.get("certificates", None)

    if certificates:
        try:
            configPath.child(certificates).makedirs()
        except:
            pass

        certificates = configPath.child(certificates).path
        for i in rproxyConf.get("https_ports").split(","):
            print("Starting HTTPS on port " + i)
            multiService.addService(strports.service('le:' + certificates + ':tcp:' + i, site))

        for host in hosts.keys():
            with open(FilePath(certificates).child(host + ".pem").path, 'w'):
                # Open it so that txacme can find it
                pass
            if hosts[host]["wwwtoo"]:
                with open(FilePath(certificates).child("www." + host + ".pem").path, 'w'):
                    # Open it so that txacme can find it
                    pass

    for i in rproxyConf.get("http_ports", "").split(","):
        print("Starting HTTP on port " + i)
        multiService.addService(strports.service('tcp:' + i, site))

    return multiService


__all__ = ["__version__", "makeService"]
