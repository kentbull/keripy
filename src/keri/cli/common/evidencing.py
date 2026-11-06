"""Optional selected registry acquisition; public evidence never authorizes Admit."""
from dataclasses import asdict
import ipaddress
import json
from pathlib import Path
import ssl
from urllib.parse import urlsplit

from hio.core.http.clienting import Client

from ... import Kinds, Vrsn_2_0
from ...app.httping import CESR_CONTENT_TYPE
from ...core import Kevery, Number, Parser, SerderACDC, SerderKERI, query
from ...kering import ConfigurationError, ValidationError


def options(parser):
    parser.add_argument('--evidence-url', help='explicit HTTPS observer endpoint for selected v2 ACDC registry evidence')
    parser.add_argument('--evidence-ca', help='CA PEM file for --evidence-url')
    parser.add_argument('--evidence-hostname', help='certificate hostname override, allowed only for an IP URL')


def settings(args):
    """Validate explicit source and TLS identity before a selected operation starts."""
    url, ca, hostname = (getattr(args, name, None) for name in
                         ('evidence_url', 'evidence_ca', 'evidence_hostname'))
    if not url:
        if ca or hostname:
            raise ConfigurationError('evidence TLS options require --evidence-url')
        return None
    try:
        parts = urlsplit(url)
        parts.port
    except ValueError as error:
        raise ConfigurationError('--evidence-url requires a valid HTTPS host and port') from error
    if (parts.scheme != 'https' or not parts.hostname or parts.username or parts.password
            or parts.fragment or parts.query):
        raise ConfigurationError('--evidence-url requires HTTPS without credentials, query or fragment')
    if not ca or not Path(ca).is_file():
        raise ConfigurationError('--evidence-url requires an existing --evidence-ca PEM file')
    if hostname:
        try:
            ipaddress.ip_address(parts.hostname)
        except ValueError:
            raise ConfigurationError('--evidence-hostname may override only an IP URL') from None
        if any(char in hostname for char in '/:@?#') or any(char.isspace() for char in hostname):
            raise ConfigurationError('--evidence-hostname requires one certificate hostname')
    context = ssl.create_default_context(cafile=ca)
    return parts, context, hostname or parts.hostname


def receive(hby, rgy, registry, raw, headers):
    """Accept only a complete authenticated selected TEL, then compare accepted v2 ACDC heads.

    A valid older prefix is not rollback or readiness. Response headers carry no
    freshness authority. Unsupported frames and conflicts fail before dispatch.
    """
    if headers.get('content-type', '').split(';')[0].strip() != CESR_CONTENT_TYPE:
        raise ValidationError('registry evidence must have CESR content type')
    stream, messages, events = bytearray(raw), [], []
    reader = Parser(version=Vrsn_2_0)
    while stream:
        message = reader.parseOneBare(ims=stream, processive=False, local=False)
        event = message.serder
        if isinstance(event, SerderACDC):
            if (event.ilk not in ('rip', 'bup') or
                    (event.said if event.ilk == 'rip' else event.regid) != registry):
                raise ValidationError('response contains unrelated registry evidence')
            if any(value for key, value in vars(message).items()
                   if key not in ('serder', 'sscs', 'ssts', 'local')):
                raise ValidationError('registry evidence carries unsupported attachments')
            events.append(event)
        elif (not isinstance(event, SerderKERI)
              or event.ilk not in ('icp', 'dip', 'rot', 'drt', 'ixn', 'rct')
              or any(getattr(message, key) for key in ('nests', 'bsqs', 'bsss', 'tdcs', 'tmqs', 'ptds', 'essrs'))):
            raise ValidationError('response contains unsupported public evidence')
        messages.append(message)
    if not events or [Number(numh=event.sad['n']).num for event in events] != list(range(len(events))):
        raise ValidationError('response requires one complete ordered selected TEL from inception')
    for sn, event in enumerate(events):
        accepted = rgy.store.seqEvent(registry, sn)
        if accepted is not None and accepted.said != event.said:
            raise ValidationError('response conflicts with accepted registry evidence')
    kvy = Kevery(db=hby.db, lax=False, local=False)
    parser = Parser(kvy=kvy, rgy=rgy, version=Vrsn_2_0)
    for message in messages:
        parser.msgProcess(asdict(message), kvy=kvy, tvy=None, exc=None, rvy=None, vry=None)
    kvy.processEscrows()
    rgy.processEscrows()
    for message in messages:
        event = message.serder
        if isinstance(event, SerderKERI):
            if hby.db.kels.getLast(keys=event.pre, on=event.sn) != event.said:
                raise ValidationError('public KEL evidence did not reach local acceptance')
            if event.ilk != 'rct' and not hby.db.fullyWitnessed(event):
                raise ValidationError('public KEL evidence is not fully witnessed')
        else:
            accepted = rgy.store.seqEvent(registry, Number(numh=event.sad['n']).num)
            if accepted is None or accepted.said != event.said:
                raise ValidationError('registry evidence did not reach local acceptance')
    head = rgy.store.headEvent(registry)
    tip = events[-1]
    if head is None or Number(numh=head.sad['n']).num < Number(numh=tip.sad['n']).num:
        raise ValidationError('response head did not reach local acceptance')
    if Number(numh=head.sad['n']).num == Number(numh=tip.sad['n']).num:
        if head.said != tip.said:
            raise ValidationError('response head conflicts with accepted registry evidence')
        return True
    return False


def acquire(owner, registries, operation, xid, source):
    """One in-flight HTTPS request; each cooperative wait rechecks live v2 IPEX authority."""
    if source is None:
        return
    parts, context, hostname = source
    for registry in dict.fromkeys(registries):
        reported = None
        while True:
            owner.check()
            operation.complete(xid)  # May return False; its original lifetime checks still apply.
            request = query(pre=owner.hab.pre, route='tels', query=dict(i=registry),
                            pvrsn=Vrsn_2_0, kind=Kinds.json)
            body = bytes(owner.hab.endorse(request, last=True, framed=False, gvrsn=Vrsn_2_0))
            client = Client(scheme='https', hostname=parts.hostname, port=parts.port or 443,
                context=context, certedhost=hostname, redirectable=False, reconnectable=False)
            client.wind(owner.tymth)
            try:
                if not client.reopen():
                    raise ConfigurationError('could not open evidence HTTPS client')
                client.request(method='POST', path=parts.path or '/', body=body,
                    headers={'Content-Type': CESR_CONTENT_TYPE, 'Accept': CESR_CONTENT_TYPE})
                while not client.responses:
                    owner.check()
                    operation.complete(xid)
                    client.service()
                    if getattr(client.connector, 'error', None):
                        raise client.connector.error
                    if client.connector.cutoff and not client.responses:
                        client.respondent.close()
                        client.serviceResponse()  # Settle a valid EOF-delimited response before refusing closure.
                        if not client.responses:
                            raise ConnectionError('evidence HTTPS connection closed before a response')
                    if not client.responses:
                        owner.check()
                        operation.complete(xid)
                        yield owner.tock
                response = client.responses.popleft()
            finally:
                client.close()
            owner.check()
            operation.complete(xid)
            status = response['status']
            if response.get('errored'):
                raise ValidationError('malformed evidence HTTP response')
            if status == 200:
                if receive(owner.hby, owner.rgy, registry, response['body'], response['headers']):
                    break
                waiting = 'older_prefix'
            elif status not in (404, 503):
                raise ConfigurationError(f'evidence source returned HTTP {status}')
            else:
                waiting = f'HTTP {status}'
            if waiting != reported:
                print(json.dumps(dict(phase='evidence_waiting', grant=owner.args.said,
                    xid=xid, registry=registry, reason=waiting)), flush=True)
                reported = waiting
            delay = owner.tyme + 0.25
            while owner.tyme < delay:
                owner.check()
                operation.complete(xid)
                yield owner.tock
    owner.check()
    operation.complete(xid)
