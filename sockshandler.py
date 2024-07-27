#!/usr/bin/env python3
"""
SocksiPy + urllib.request handler

version: 0.4
author: e<e@tr0ll.in>

This module provides a Handler that you can use with urllib.request to tunnel your connection through a SOCKS proxy, without monkey patching the original socket.
"""

import ssl
import urllib.request as urllib2
import http.client as httplib
import socks  # $ pip install PySocks
from typing import Optional, Dict, Any

def merge_dict(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge two dictionaries into one.
    """
    d = a.copy()
    d.update(b)
    return d

class SocksiPyConnection(httplib.HTTPConnection):
    def __init__(self, proxytype: int, proxyaddr: str, proxyport: Optional[int] = None,
                 rdns: bool = True, username: Optional[str] = None, password: Optional[str] = None,
                 *args, **kwargs):
        self.proxyargs = (proxytype, proxyaddr, proxyport, rdns, username, password)
        super().__init__(*args, **kwargs)

    def connect(self):
        self.sock = socks.socksocket()
        self.sock.set_proxy(*self.proxyargs)
        if isinstance(self.timeout, (int, float)):
            self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))

class SocksiPyConnectionS(httplib.HTTPSConnection):
    def __init__(self, proxytype: int, proxyaddr: str, proxyport: Optional[int] = None,
                 rdns: bool = True, username: Optional[str] = None, password: Optional[str] = None,
                 *args, **kwargs):
        self.proxyargs = (proxytype, proxyaddr, proxyport, rdns, username, password)
        super().__init__(*args, **kwargs)

    def connect(self):
        sock = socks.socksocket()
        sock.set_proxy(*self.proxyargs)
        if isinstance(self.timeout, (int, float)):
            sock.settimeout(self.timeout)
        sock.connect((self.host, self.port))
        self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file)

class SocksiPyHandler(urllib2.HTTPHandler, urllib2.HTTPSHandler):
    def __init__(self, proxytype: int, proxyaddr: str, proxyport: Optional[int] = None,
                 rdns: bool = True, username: Optional[str] = None, password: Optional[str] = None,
                 *args, **kwargs):
        self.proxyargs = (proxytype, proxyaddr, proxyport, rdns, username, password)
        super().__init__()

    def http_open(self, req: urllib2.Request) -> urllib2.HTTPResponse:
        def build(host: str, port: Optional[int] = None, timeout: float = 0, **kwargs: Any) -> SocksiPyConnection:
            kw = merge_dict(self.proxyargs, kwargs)
            return SocksiPyConnection(*self.proxyargs, host=host, port=port, timeout=timeout, **kw)
        return self.do_open(build, req)

    def https_open(self, req: urllib2.Request) -> urllib2.HTTPResponse:
        def build(host: str, port: Optional[int] = None, timeout: float = 0, **kwargs: Any) -> SocksiPyConnectionS:
            kw = merge_dict(self.proxyargs, kwargs)
            return SocksiPyConnectionS(*self.proxyargs, host=host, port=port, timeout=timeout, **kw)
        return self.do_open(build, req)

if __name__ == "__main__":
    import sys
    try:
        port = int(sys.argv[1])
    except (ValueError, IndexError):
        port = 9050

    try:
        opener = urllib2.build_opener(SocksiPyHandler(socks.PROXY_TYPE_SOCKS5, "localhost", port))
        http_response = opener.open("http://httpbin.org/ip").read().decode()
        https_response = opener.open("https://httpbin.org/ip").read().decode()
        print(f"HTTP: {http_response}")
        print(f"HTTPS: {https_response}")
    except Exception as e:
        print(f"An error occurred: {e}")