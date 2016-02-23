from twisted.application.service import ServiceMaker

rproxy = ServiceMaker(
    "rproxy",
    "rproxy",
    ("HTTP/1.1 reverse proxy, with TLS support."),
    "rproxy")
