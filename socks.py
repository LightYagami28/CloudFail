"""
PySocks - Python SOCKS module.
Version 1.5.7

Copyright 2006 Dan-Haim. All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of Dan Haim nor the names of his contributors may be used
   to endorse or promote products derived from this software without specific
   prior written permission.

THIS SOFTWARE IS PROVIDED BY DAN HAIM "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
EVENT SHALL DAN HAIM OR HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

This module provides a standard socket-like interface for Python
for tunneling connections through SOCKS proxies.

===============================================================================

Modifications made by Anorov (https://github.com/Anorov)
- Forked and renamed to PySocks
- Fixed issue with HTTP proxy failure checking
- Improved exception handling and output
- Fixed Python 3 bytestring handling
- Added SOCKS5 authentication support
- Various small bug fixes
"""

__version__ = "1.5.7"

import socket
import struct
from io import BytesIO
from base64 import b64encode
from collections.abc import Callable

PROXY_TYPE_SOCKS4 = SOCKS4 = 1
PROXY_TYPE_SOCKS5 = SOCKS5 = 2
PROXY_TYPE_HTTP = HTTP = 3

PROXY_TYPES = {"SOCKS4": SOCKS4, "SOCKS5": SOCKS5, "HTTP": HTTP}
PRINTABLE_PROXY_TYPES = {v: k for k, v in PROXY_TYPES.items()}

class ProxyError(IOError):
    def __init__(self, msg, socket_err=None):
        super().__init__(msg)
        self.socket_err = socket_err
        if socket_err:
            self.args = (f"{msg}: {socket_err}",)

class GeneralProxyError(ProxyError): pass
class ProxyConnectionError(ProxyError): pass
class SOCKS5AuthError(ProxyError): pass
class SOCKS5Error(ProxyError): pass
class SOCKS4Error(ProxyError): pass
class HTTPError(ProxyError): pass

SOCKS4_ERRORS = {
    0x5B: "Request rejected or failed",
    0x5C: "Request rejected because SOCKS server cannot connect to identd on the client",
    0x5D: "Request rejected because the client program and identd report different user-ids"
}

SOCKS5_ERRORS = {
    0x01: "General SOCKS server failure",
    0x02: "Connection not allowed by ruleset",
    0x03: "Network unreachable",
    0x04: "Host unreachable",
    0x05: "Connection refused",
    0x06: "TTL expired",
    0x07: "Command not supported, or protocol error",
    0x08: "Address type not supported"
}

DEFAULT_PORTS = {
    SOCKS4: 1080,
    SOCKS5: 1080,
    HTTP: 8080
}

def set_default_proxy(proxy_type=None, addr=None, port=None, rdns=True, username=None, password=None):
    """
    Sets a default proxy which all further socksocket objects will use.
    """
    socksocket.default_proxy = (proxy_type, addr, port, rdns,
                                username.encode() if username else None,
                                password.encode() if password else None)

def get_default_proxy():
    """
    Returns the default proxy set by set_default_proxy.
    """
    return socksocket.default_proxy

def wrap_module(module):
    """
    Replaces a module's socket library with a SOCKS socket. Must set
    a default proxy using set_default_proxy(...) first.
    """
    if socksocket.default_proxy:
        module.socket.socket = socksocket
    else:
        raise GeneralProxyError("No default proxy specified")

def create_connection(dest_pair, proxy_type=None, proxy_addr=None,
                      proxy_port=None, proxy_rdns=True,
                      proxy_username=None, proxy_password=None,
                      timeout=None, source_address=None,
                      socket_options=None):
    """
    Like socket.create_connection(), but connects to proxy
    before returning the socket object.
    """
    remote_host, remote_port = dest_pair
    remote_host = remote_host.strip('[]') if remote_host.startswith('[') else remote_host
    proxy_addr = proxy_addr.strip('[]') if proxy_addr and proxy_addr.startswith('[') else proxy_addr

    err = None

    for r in socket.getaddrinfo(proxy_addr, proxy_port, 0, socket.SOCK_STREAM):
        family, socket_type, proto, canonname, sa = r
        sock = None
        try:
            sock = socksocket(family, socket_type, proto)
            if socket_options:
                for opt in socket_options:
                    sock.setsockopt(*opt)
            if isinstance(timeout, (int, float)):
                sock.settimeout(timeout)
            if proxy_type is not None:
                sock.set_proxy(proxy_type, proxy_addr, proxy_port, proxy_rdns,
                               proxy_username, proxy_password)
            if source_address is not None:
                sock.bind(source_address)
            sock.connect((remote_host, remote_port))
            return sock
        except socket.error as e:
            err = e
            if sock:
                sock.close()

    if err:
        raise err

    raise socket.error("gai returned empty list.")

class _BaseSocket(socket.socket):
    """Base socket class to handle method delegation."""

    def __init__(self, *pos, **kw):
        super().__init__(*pos, **kw)
        self._savedmethods = {name: getattr(self, name) for name in self._savenames}
        for name in self._savenames:
            delattr(self, name)  # Allows normal overriding mechanism to work

    _savenames = []

def _makemethod(name):
    return lambda self, *pos, **kw: self._savedmethods[name](*pos, **kw)

for name in ("sendto", "send", "recvfrom", "recv"):
    if not isinstance(getattr(_BaseSocket, name, None), Callable):
        _BaseSocket._savenames.append(name)
        setattr(_BaseSocket, name, _makemethod(name))

class socksocket(_BaseSocket):
    """SOCKS enabled socket."""

    default_proxy = None

    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, *args, **kwargs):
        if type not in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            raise ValueError(f"Socket type must be stream or datagram, not {type!r}")

        super().__init__(family, type, proto, *args, **kwargs)
        self._proxyconn = None
        self.proxy = self.default_proxy if self.default_proxy else (None, None, None, None, None, None)
        self.proxy_sockname = None
        self.proxy_peername = None

    def _readall(self, file, count):
        """Receive EXACTLY the number of bytes requested."""
        data = b""
        while len(data) < count:
            d = file.read(count - len(data))
            if not d:
                raise GeneralProxyError("Connection closed unexpectedly")
            data += d
        return data

    def set_proxy(self, proxy_type=None, addr=None, port=None, rdns=True, username=None, password=None):
        """Sets the proxy to be used."""
        self.proxy = (proxy_type, addr, port, rdns,
                      username.encode() if username else None,
                      password.encode() if password else None)

    def bind(self, *pos, **kw):
        """Implements proxy connection for UDP sockets."""
        proxy_type, proxy_addr, proxy_port, rdns, username, password = self.proxy
        if not proxy_type or self.type != socket.SOCK_DGRAM:
            return super().bind(*pos, **kw)

        if self._proxyconn:
            raise socket.error(EINVAL, "Socket already bound to an address")
        if proxy_type != SOCKS5:
            raise socket.error(EOPNOTSUPP, "UDP only supported by SOCKS5 proxy type")
        super().bind(*pos, **kw)

        _, port = self.getsockname()
        dst = ("0", port)
        self._proxyconn = socket.socket()
        self._proxyconn.connect((proxy_addr, proxy_port))
        UDP_ASSOCIATE = b"\x03"
        _, relay = self._SOCK

# If the given destination address is an IP address
        if not rdns:
            family = socket.AF_INET if ':' not in host else socket.AF_INET6
            addr_type = family_to_byte.get(family, b"\x01")
            file.write(addr_type)
            if family == socket.AF_INET:
                file.write(struct.pack('!4B', *map(int, host.split('.'))))
            elif family == socket.AF_INET6:
                file.write(socket.inet_pton(family, host))
        else:
            # Address is DNS, use the domain name
            file.write(b"\x03")
            file.write(bytes([len(host)]))
            file.write(host.encode())

        file.write(struct.pack('!H', port))

    def _read_SOCKS5_address(self, file):
        """
        Reads and returns the SOCKS5 address and port from the given file object.
        """
        addr_type = file.read(1)
        if addr_type == b"\x01":
            # IPv4
            addr = file.read(4)
            addr = '.'.join(map(str, struct.unpack('!4B', addr)))
        elif addr_type == b"\x04":
            # IPv6
            addr = file.read(16)
            addr = socket.inet_ntop(socket.AF_INET6, addr)
        elif addr_type == b"\x03":
            # Domain name
            length = ord(file.read(1))
            addr = file.read(length).decode()
        else:
            raise GeneralProxyError("Unsupported address type")

        port = struct.unpack('!H', file.read(2))[0]
        return addr, port

    def _proxy_addr(self):
        """
        Returns the proxy address as a tuple (host, port).
        """
        return self.proxy[1], self.proxy[2]

class SOCKSProxyServer:
    """
    Simple SOCKS proxy server implementation. This class provides an example
    of how to create a basic SOCKS proxy server.
    """
    def __init__(self, host='localhost', port=1080):
        self.host = host
        self.port = port

    def start(self):
        """
        Start the SOCKS proxy server.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind((self.host, self.port))
            server.listen()
            print(f"SOCKS proxy server running on {self.host}:{self.port}")

            while True:
                client_socket, _ = server.accept()
                # Handle the client connection
                # This is where you would implement the SOCKS protocol handling
                # For simplicity, this example does not include the full implementation
                self.handle_client(client_socket)

    def handle_client(self, client_socket):
        """
        Handle a client connection to the SOCKS proxy server.
        """
        with client_socket:
            # Read and handle the SOCKS request from the client
            # This is where you would process the SOCKS handshake and commands
            # For simplicity, this example does not include the full implementation
            pass

if __name__ == "__main__":
    proxy_server = SOCKSProxyServer()
    proxy_server.start()