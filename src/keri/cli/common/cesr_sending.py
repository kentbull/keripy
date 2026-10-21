"""Bounded direct transport shared by native and legacy operator commands.

The send-buffer boundary follows app.agenting.TCPMessenger; HTTP request and
child ownership were extracted from the native IPEX command adapter.
"""
from urllib.parse import urlsplit
from hio.core import http, tcp
from keri.app.httping import CESR_CONTENT_TYPE
from keri.kering import ConfigurationError


def send(doer, url, body, timeout):
    """Send exact CESR bytes with bounded, cooperatively scheduled transport.

    ``doer`` is the scheduling DoDoer; ``timeout`` bounds its clock.
    ``url`` selects HTTP(S) intake or a raw TCP host and explicit port;
    ``body`` is the already authenticated message stream. HTTP returns the
    response after checking its status. TCP returns only a transport marker
    after its send buffer drains, never a receiver acceptance assertion.
    The caller must observe authenticated protocol or application results.
    All child sockets close on completion, failure, or cancellation.
    """
    target = urlsplit(url)
    if target.scheme == 'tcp':
        if (not target.hostname or not target.port or target.username or
                target.password or target.path not in ('', '/') or
                target.query or target.fragment):
            raise ConfigurationError('TCP intake requires tcp://host:port')
        client = tcp.clienting.Client(host=target.hostname, port=target.port)
        owner = tcp.clienting.ClientDoer(client=client)
        doer.extend([owner])
        try:
            # Match KERIpy TCPMessenger's tx-buffer completion boundary.
            # A drained buffer is not evidence of application acceptance.
            client.tx(body)
            deadline = doer.tyme + timeout
            while not client.connected or client.txbs:
                if client.cutoff:
                    raise ConnectionError('CESR TCP peer closed before send completed')
                if doer.tyme >= deadline:
                    raise TimeoutError('CESR TCP send timed out')
                yield doer.tock
            return {'transport': 'tcp', 'sent': len(body)}
        finally:
            doer.remove([owner])
            client.close()
    if (target.scheme not in ('http', 'https') or not target.hostname
            or target.username or target.password or target.fragment):
        raise ConfigurationError('an HTTP(S) or TCP endpoint is required')
    client = http.clienting.Client(scheme=target.scheme, hostname=target.hostname,
        port=target.port or (443 if target.scheme == 'https' else 80))
    owner = http.clienting.ClientDoer(client=client)
    doer.extend([owner])
    try:
        client.request(method='POST', path=(target.path or '/') + ('?' + target.query if target.query else ''), body=body,
                       headers={'Content-Type': CESR_CONTENT_TYPE})
        deadline = doer.tyme + timeout
        while not client.responses and doer.tyme < deadline:
            yield doer.tock
        if not client.responses:
            raise TimeoutError('CESR HTTP request timed out')
        response = client.responses.popleft()
        if not 200 <= response['status'] < 300:
            raise ConfigurationError(f"CESR HTTP status {response['status']}")
        return response
    finally:
        doer.remove([owner])
        client.close()
