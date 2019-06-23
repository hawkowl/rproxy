# (C) Amber Brown. See LICENSE for details.

from __future__ import absolute_import, division

from six.moves import configparser

from zope.interface import implementer

from six.moves.urllib.parse import urlencode, urlparse

from twisted.python.url import URL

from twisted.application import service, strports
from twisted.application.service import Service
from twisted.internet import reactor
from twisted.internet.defer import Deferred, succeed
from twisted.internet.protocol import Protocol
from twisted.python import usage
from twisted.python.filepath import FilePath
from twisted.web import server, http, static
from twisted.web.client import Agent, HTTPConnectionPool, ContentDecoderAgent, GzipDecoder
from twisted.web.iweb import IBodyProducer
from twisted.web.resource import Resource, EncodingResourceWrapper

from josepy.jwa import RS256

from txacme.challenges import HTTP01Responder
from txacme.client import Client
from txacme.endpoint import load_or_create_client_key
from txacme.service import AcmeIssuingService
from txacme.store import DirectoryStore
from txacme.urls import LETSENCRYPT_DIRECTORY

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

def movedTo(request, url):
    """
    Permanently redirect C{request} to C{url}.

    @param request: The L{twisted.web.server.Reqeuest} to redirect.

    @param url: The new URL to which to redirect the request.
    @type url: L{bytes}

    @return: The redirect HTML page.
    @rtype: L{bytes}
    """
    request.setResponseCode(http.MOVED_PERMANENTLY)
    request.setHeader(b"location", url)
    return ("""
<html>
    <head>
        <meta http-equiv=\"refresh\" content=\"0;URL=%(url)s\">
    </head>
    <body bgcolor=\"#FFFFFF\" text=\"#000000\">
    <a href=\"%(url)s\">click here</a>
    </body>
</html>
""" % {'url': url}).encode('ascii')

class RespondToHTTP01AndRedirectToHTTPS(Resource):
    """
    Allow an L{HTTP01Responder} to handle requests for
    C{.well_known/acme-challenges} only.  Redirect any other requests
    to their HTTPS equivalent.
    """
    def __init__(self, responderResource):
        Resource.__init__(self)
        wellKnown = Resource()
        wellKnown.putChild(b'acme-challenge', responderResource)
        self.putChild(b'.well-known', wellKnown)
        self.putChild(b'check', static.Data(b'OK', 'text/plain'))

    def render(self, request):
        # request.args can include URL encoded bodies, so extract the
        # query from request.uri
        _, _, query = request.uri.partition(b'?')
        # Assume HTTPS is served over 443
        httpsURL = URL(
            scheme=u'https',
            # I'm sure ASCII will be fine.
            host=request.getRequestHostname().decode('ascii'),
            path=tuple(segment.decode('ascii')
                       for segment in request.prepath + request.postpath),

        )
        httpsLocation = httpsURL.asText().encode('ascii')
        if query:
            httpsLocation += (b'?' + query)
        return movedTo(request, httpsLocation)

    def getChild(self, path, request):
        return self


class EnsureHTTPS(Resource):
    """
    Wrap a resource so that all requests that are not over HTTPS are
    redirected to HTTPS.
    """
    def __init__(self, wrappedResource, responderResource):
        """
        Initialize L{EnsureHTTPS}.

        @param wrappedResource: A resource representing the root of a web site.
        @type wrappedResource: L{twisted.web.resource.Resource}
        """
        self._wrappedResource = wrappedResource
        self._httpResource = RespondToHTTP01AndRedirectToHTTPS(
                responderResource)

    def getChildWithDefault(self, path, request):
        if request.isSecure():
            return self._wrappedResource
        else:
            return self._httpResource.getChildWithDefault(path, request)


class RProxyResource(Resource):

    isLeaf = True

    def __init__(self, hosts, clacks, pool, reactor, extraHeaders, anonymous):
        self._clacks = clacks
        self._hosts = hosts
        self._agent = ContentDecoderAgent(Agent(reactor, pool=pool), [(b'gzip', GzipDecoder)])
        self._extraHeaders = extraHeaders
        self._anonymous = anonymous

    def render(self, request):

        host = self._hosts.get(request.getRequestHostname().lower())

        if not host and request.getRequestHostname().lower().startswith(b"www."):
            host = self._hosts.get(request.getRequestHostname().lower()[4:])

            # The non-www host doesn't want to match to www.
            if not host["wwwtoo"]:
                host = None

        if not host:
            request.code = 404
            request.responseHeaders.setRawHeaders("Server",
                                                  [__version__.package + " " + __version__.base()])
            return b"I can't seem to find a domain by that name. Look behind the couch?"

        url = b"%s://%s:%s/%s" % (
            b"https" if host["proxysecure"] else b"http",
            host["host"], host["port"], request.path[1:])

        urlFragments = urlparse(request.uri)

        if urlFragments.query:
            url += b"?" + urlFragments.query

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

    ini = configparser.RawConfigParser()
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

        if "wwwtoo" not in hosts[i]:
            print("%s does not have an wwwtoo setting, making True" % (i,))
            hosts[i]["wwwtoo"] = "True"

        if "proxysecure" not in hosts[i]:
            print("%s does not have an proxysecure setting, making False" % (i,))
            hosts[i]["proxysecure"] = False

        hosts[i]["wwwtoo"] = True if hosts[i]["wwwtoo"]=="True" else False
        hosts[i]["proxysecure"] = True if hosts[i]["proxysecure"]=="True" else False
        hosts[i]["sendhsts"] = True if hosts[i].get("sendhsts")=="True" else False


    from twisted.internet import reactor
    pool = HTTPConnectionPool(reactor)

    resource = EncodingResourceWrapper(
        RProxyResource(hosts, rproxyConf.get("clacks"), pool, reactor, {}, False),
        [server.GzipEncoderFactory()])

    responder = HTTP01Responder()
    site = server.Site(EnsureHTTPS(resource, responder.resource),)
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
            multiService.addService(strports.service('txsni:' + certificates + ':tcp:' + i, site))

        for host in hosts.keys():
            with open(FilePath(certificates).child(host + ".pem").path, 'r+'):
                # Open it so that txacme can find it
                pass
            if hosts[host]["wwwtoo"]:
                with open(FilePath(certificates).child("www." + host + ".pem").path, 'r+'):
                    # Open it so that txacme can find it
                    pass

    for i in rproxyConf.get("http_ports", "").split(","):
        print("Starting HTTP on port " + i)
        multiService.addService(strports.service('tcp:' + i, site))

    issuingService = AcmeIssuingService(
        cert_store=DirectoryStore(FilePath(certificates)),
        client_creator=(lambda: Client.from_url(
            reactor=reactor,
            url=LETSENCRYPT_DIRECTORY,
            key=load_or_create_client_key(FilePath(certificates)),
            alg=RS256,
        )),
        clock=reactor,
        responders=[responder],
    )

    issuingService.setServiceParent(multiService)

    return multiService


__all__ = ["__version__", "makeService"]
