# The content of this file was copied from
# asyncio.base_events and asyncio.selector_events.
# If only asyncio would allow to pass custom SSLProtocol factory
# and SocketTransport factory that would allow to not duplicate this code.

import collections
import itertools
import socket
import ssl
import asyncio
from logging import getLogger

_HAS_IPv6 = hasattr(socket, 'AF_INET6')
_logger = getLogger('fastnet')


async def create_connection(
        loop: asyncio.AbstractEventLoop,
        protocol_factory, host=None, port=None,
        *, ssl=None, family=0,
        proto=0, flags=0, sock=None,
        local_addr=None, server_hostname=None,
        ssl_handshake_timeout=None,
        ssl_shutdown_timeout=None,
        happy_eyeballs_delay=None, interleave=None,
        all_errors=False):
    """Connect to a TCP server.

    Create a streaming transport connection to a given internet host and
    port: socket family AF_INET or socket.AF_INET6 depending on host (or
    family if specified), socket type SOCK_STREAM. protocol_factory must be
    a callable returning a protocol instance.

    This method is a coroutine which will try to establish the connection
    in the background.  When successful, the coroutine returns a
    (transport, protocol) pair.
    """
    if server_hostname is not None and not ssl:
        raise ValueError('server_hostname is only meaningful with ssl')

    if server_hostname is None and ssl:
        # Use host as default for server_hostname.  It is an error
        # if host is empty or not set, e.g. when an
        # already-connected socket was passed or when only a port
        # is given.  To avoid this error, you can pass
        # server_hostname='' -- this will bypass the hostname
        # check.  (This also means that if host is a numeric
        # IP/IPv6 address, we will attempt to verify that exact
        # address; this will probably fail, but it is possible to
        # create a certificate for a specific IP address, so we
        # don't judge it here.)
        if not host:
            raise ValueError('You must set server_hostname '
                             'when using ssl without a host')
        server_hostname = host

    if ssl_handshake_timeout is not None and not ssl:
        raise ValueError(
            'ssl_handshake_timeout is only meaningful with ssl')

    if ssl_shutdown_timeout is not None and not ssl:
        raise ValueError(
            'ssl_shutdown_timeout is only meaningful with ssl')

    if sock is not None:
        _check_ssl_socket(sock)

    if happy_eyeballs_delay is not None and interleave is None:
        # If using happy eyeballs, default to interleave addresses by family
        interleave = 1

    if host is not None or port is not None:
        if sock is not None:
            raise ValueError(
                'host/port and sock can not be specified at the same time')

        infos = await _ensure_resolved(
            (host, port), family=family,
            type=socket.SOCK_STREAM, proto=proto, flags=flags, loop=loop)
        if not infos:
            raise OSError('getaddrinfo() returned empty list')

        if local_addr is not None:
            laddr_infos = await _ensure_resolved(
                local_addr, family=family,
                type=socket.SOCK_STREAM, proto=proto,
                flags=flags, loop=loop)
            if not laddr_infos:
                raise OSError('getaddrinfo() returned empty list')
        else:
            laddr_infos = None

        if interleave:
            infos = _interleave_addrinfos(infos, interleave)

        exceptions = []
        if happy_eyeballs_delay is None:
            # not using happy eyeballs
            for addrinfo in infos:
                try:
                    sock = await _connect_sock(
                        loop, exceptions, addrinfo, laddr_infos)
                    break
                except OSError:
                    continue
        else:  # using happy eyeballs
            # TODO: wtf? fix asyncio.staggered private import
            sock = (await asyncio.staggered.staggered_race(
                (
                    # can't use functools.partial as it keeps a reference
                    # to exceptions
                    lambda addrinfo=addrinfo: _connect_sock(
                        loop, exceptions, addrinfo, laddr_infos
                    )
                    for addrinfo in infos
                ),
                happy_eyeballs_delay,
                loop=loop,
            ))[0]  # can't use sock, _, _ as it keeks a reference to exceptions

        if sock is None:
            exceptions = [exc for sub in exceptions for exc in sub]
            try:
                if all_errors:
                    raise ExceptionGroup("create_connection failed", exceptions)
                if len(exceptions) == 1:
                    raise exceptions[0]
                elif exceptions:
                    # If they all have the same str(), raise one.
                    model = str(exceptions[0])
                    if all(str(exc) == model for exc in exceptions):
                        raise exceptions[0]
                    # Raise a combined exception so the user can see all
                    # the various error messages.
                    raise OSError('Multiple exceptions: {}'.format(
                        ', '.join(str(exc) for exc in exceptions)))
                else:
                    # No exceptions were collected, raise a timeout error
                    raise TimeoutError('create_connection failed')
            finally:
                exceptions = None

    else:
        if sock is None:
            raise ValueError(
                'host and port was not specified and no sock specified')
        if sock.type != socket.SOCK_STREAM:
            # We allow AF_INET, AF_INET6, AF_UNIX as long as they
            # are SOCK_STREAM.
            # We support passing AF_UNIX sockets even though we have
            # a dedicated API for that: create_unix_connection.
            # Disallowing AF_UNIX in this method, breaks backwards
            # compatibility.
            raise ValueError(
                f'A Stream Socket was expected, got {sock!r}')

    transport, protocol = await _create_connection_transport(
        loop,
        sock, protocol_factory, ssl, server_hostname,
        ssl_handshake_timeout=ssl_handshake_timeout,
        ssl_shutdown_timeout=ssl_shutdown_timeout)
    if loop.get_debug():
        # Get the socket from the transport because SSL transport closes
        # the old socket and creates a new SSL socket
        sock = transport.get_extra_info('socket')
        _logger.debug("%r connected to %s:%r: (%r, %r)",
                      sock, host, port, transport, protocol)
    return transport, protocol


async def _ensure_resolved(address, *,
                           family=0, type=socket.SOCK_STREAM,
                           proto=0, flags=0, loop):
    host, port = address[:2]
    info = _ipaddr_info(host, port, family, type, proto, *address[2:])
    if info is not None:
        # "host" is already a resolved IP.
        return [info]
    else:
        return await loop.getaddrinfo(host, port, family=family, type=type,
                                      proto=proto, flags=flags)


def _ipaddr_info(host, port, family, type, proto, flowinfo=0, scopeid=0):
    # Try to skip getaddrinfo if "host" is already an IP. Users might have
    # handled name resolution in their own code and pass in resolved IPs.
    if not hasattr(socket, 'inet_pton'):
        return

    if proto not in {0, socket.IPPROTO_TCP, socket.IPPROTO_UDP} or \
            host is None:
        return None

    if type == socket.SOCK_STREAM:
        proto = socket.IPPROTO_TCP
    elif type == socket.SOCK_DGRAM:
        proto = socket.IPPROTO_UDP
    else:
        return None

    if port is None:
        port = 0
    elif isinstance(port, bytes) and port == b'':
        port = 0
    elif isinstance(port, str) and port == '':
        port = 0
    else:
        # If port's a service name like "http", don't skip getaddrinfo.
        try:
            port = int(port)
        except (TypeError, ValueError):
            return None

    if family == socket.AF_UNSPEC:
        afs = [socket.AF_INET]
        if _HAS_IPv6:
            afs.append(socket.AF_INET6)
    else:
        afs = [family]

    if isinstance(host, bytes):
        host = host.decode('idna')
    if '%' in host:
        # Linux's inet_pton doesn't accept an IPv6 zone index after host,
        # like '::1%lo0'.
        return None

    for af in afs:
        try:
            socket.inet_pton(af, host)
            # The host has already been resolved.
            if _HAS_IPv6 and af == socket.AF_INET6:
                return af, type, proto, '', (host, port, flowinfo, scopeid)
            else:
                return af, type, proto, '', (host, port)
        except OSError:
            pass

    # "host" is not an IP address.
    return None


async def _connect_sock(loop, exceptions, addr_info, local_addr_infos=None):
    """Create, bind and connect one socket."""
    my_exceptions = []
    exceptions.append(my_exceptions)
    family, type_, proto, _, address = addr_info
    sock = None
    try:
        try:
            sock = socket.socket(family=family, type=type_, proto=proto)
            sock.setblocking(False)
            if local_addr_infos is not None:
                for lfamily, _, _, _, laddr in local_addr_infos:
                    # skip local addresses of different family
                    if lfamily != family:
                        continue
                    try:
                        sock.bind(laddr)
                        break
                    except OSError as exc:
                        msg = (
                            f'error while attempting to bind on '
                            f'address {laddr!r}: {str(exc).lower()}'
                        )
                        exc = OSError(exc.errno, msg)
                        my_exceptions.append(exc)
                else:  # all bind attempts failed
                    if my_exceptions:
                        raise my_exceptions.pop()
                    else:
                        raise OSError(f"no matching local address with {family=} found")
            await loop.sock_connect(sock, address)
            return sock
        except OSError as exc:
            my_exceptions.append(exc)
            raise
    except:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                # An error when closing a newly created socket is
                # not important, but it can overwrite more important
                # non-OSError error. So ignore it.
                pass
        raise
    finally:
        exceptions = my_exceptions = None


async def _create_connection_transport(
        loop,
        sock, protocol_factory, ssl,
        server_hostname, server_side=False,
        ssl_handshake_timeout=None,
        ssl_shutdown_timeout=None):
    sock.setblocking(False)

    protocol = protocol_factory()
    waiter = loop.create_future()
    if ssl:
        sslcontext = None if isinstance(ssl, bool) else ssl
        transport = _make_ssl_transport(
            loop,
            sock, protocol, sslcontext, waiter,
            server_side=server_side, server_hostname=server_hostname,
            ssl_handshake_timeout=ssl_handshake_timeout,
            ssl_shutdown_timeout=ssl_shutdown_timeout)
    else:
        transport = _make_socket_transport(loop, sock, protocol, waiter)

    try:
        await waiter
    except:
        transport.close()
        raise

    return transport, protocol


def _check_ssl_socket(sock):
    if isinstance(sock, ssl.SSLSocket):
        raise TypeError("Socket cannot be of type SSLSocket")


def _interleave_addrinfos(addrinfos, first_address_family_count=1):
    """Interleave list of addrinfo tuples by family."""
    # Group addresses by family
    addrinfos_by_family = collections.OrderedDict()
    for addr in addrinfos:
        family = addr[0]
        if family not in addrinfos_by_family:
            addrinfos_by_family[family] = []
        addrinfos_by_family[family].append(addr)
    addrinfos_lists = list(addrinfos_by_family.values())

    reordered = []
    if first_address_family_count > 1:
        reordered.extend(addrinfos_lists[0][:first_address_family_count - 1])
        del addrinfos_lists[0][:first_address_family_count - 1]
    reordered.extend(
        a for a in itertools.chain.from_iterable(
            itertools.zip_longest(*addrinfos_lists)
        ) if a is not None)
    return reordered


def _make_ssl_transport(
        loop, rawsock, protocol, sslcontext, waiter=None,
        *, server_side=False, server_hostname=None,
        extra=None, server=None,
        ssl_handshake_timeout=60.0,
        ssl_shutdown_timeout=30.0,
):
    ssl_protocol = sslproto.SSLProtocol(
        loop, protocol, sslcontext, waiter,
        server_side, server_hostname,
        ssl_handshake_timeout=ssl_handshake_timeout,
        ssl_shutdown_timeout=ssl_shutdown_timeout
    )
    _SelectorSocketTransport(self, rawsock, ssl_protocol,
                             extra=extra, server=server)
    return ssl_protocol._app_transport


def _make_socket_transport(loop, sock, protocol, waiter=None, *,
                           extra=None, server=None):
    return _SelectorSocketTransport(self, sock, protocol, waiter,
                                    extra, server)
