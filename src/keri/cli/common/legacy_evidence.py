"""Serve authentic v1 registry replay/TSNs from one existing issuer environment.

This is evidence publication, not credential authoring or verifier policy. The
service authenticates queries before invoking the conventional legacy Tevery
query/cue contract, then signs normal replies with its existing controller.
"""
from dataclasses import asdict
import json
import math
from urllib.parse import urlsplit

import falcon
from hio.base import doing
from hio.core import http

from keri import Vrsn_1_0, Kinds
from keri.app import HaberyDoer, Keeper, GroupHab
from keri.app.httping import CESR_CONTENT_TYPE
from keri.app.indirecting import createHttpServer
from keri.cli.common import setupHby, cesr_sending
from keri.core import Parser, SerderKERI, Kevery, Number, Diger, Prefixer
from keri.kering import ConfigurationError, ValidationError, AuthError, KeriError
from keri.peer.exchanging import verifyAttachments
from keri.vdr import Regery, Tevery


class Source(doing.DoDoer):
    """Own a bounded reply queue over an existing accepted legacy registry."""

    def __init__(self, hby, rgy, hab, registry, readers, replyTo, timeout=5.0):
        """Compose existing owners and fixed delivery policy; open no listener.

        hby/rgy/hab and registry belong to the caller. readers is an explicit AID
        allowlist; replyTo is one operator-configured HTTP(S) URL. timeout bounds
        each delivery. Return None. Invalid timeout/URL raises ValueError. This
        source must restart after external authoring to reload its public cache.
        """
        target = urlsplit(replyTo)
        port = target.port  # validate configured port syntax before scheduling delivery
        if ((port is not None and not 1 <= port <= 65535)
                or target.scheme not in ('http', 'https') or not target.hostname
                or target.username or target.password or target.fragment):
            raise ValueError('reply destination requires a fixed HTTP(S) URL')
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError('timeout must be positive and finite')
        self.hby, self.rgy, self.hab, self.registry = hby, rgy, hab, registry
        self.readers, self.replyTo, self.timeout = set(readers), replyTo, timeout
        self.kvy = Kevery(db=hby.db, lax=False, local=False)
        self.tvy = Tevery(db=hby.db, reger=rgy.reger)
        self.parser = Parser(version=Vrsn_1_0)
        self.outbox = []
        self.app = falcon.App()
        self.app.add_route('/', QueryEnd(self))
        self.app.add_route('/health', HealthEnd())
        super().__init__(doers=[doing.doify(self.deliver)])

    def signer(self, dom):
        """Return the unique allowlisted authenticated query signer.

        dom is one parsed v1 qry frame. Normal last-establishment signatures,
        explicit establishment groups and nontransferable signatures use the
        existing attachment verifier and accepted KEL threshold. Return a Prefixer.
        Invalid, missing, extra unsupported or unauthorized factors raise AuthError.
        No query field or claimed sender supplies authority.
        """
        if (dom.sigers or dom.wigers or dom.frcs or dom.sscs or dom.ssts
                or dom.tdcs or dom.bsqs or dom.bsss or dom.tmqs or dom.essrs
                or dom.ptds or dom.nests):
            raise AuthError('unsupported query authentication attachments')
        groups = list(dom.tsgs)
        for prefixer, sigers in dom.lsgs:
            if prefixer.qb64 not in self.hby.kevers:
                raise AuthError('query signer key state is unavailable')
            kever = self.hby.kevers[prefixer.qb64]
            groups.append((prefixer, Number(num=kever.lastEst.s),
                           Diger(qb64=kever.lastEst.d), sigers))
        tsgs, cigars, seals, invalid, missing = verifyAttachments(
            self.hby, dom.serder, tsgs=groups, cigars=dom.cigars)
        signers = {item[0].qb64 for item in tsgs} | {item.verfer.qb64 for item in cigars}
        if invalid or missing or seals or len(signers) != 1 or not signers <= self.readers:
            raise AuthError('query signature or reader authorization failed')
        return Prefixer(qb64=next(iter(signers)))

    def ingest(self, raw):
        """Authenticate bounded v1 query frames and queue actual legacy source cues.

        raw is a complete CESR body, possibly preceded by normal KEL introductions.
        Return queued message count. Only tels/tsn for this registry and known
        credential state are served. Validation/framing errors propagate; no query
        URL controls delivery and no request writes accepted registry rows. KEL
        introductions use ordinary Kevery and only explicit reader AIDs are allowed.
        At most 32 frames, 64 queued responses and an operational 4 MiB per-response
        limit apply. Size limits do not determine protocol validity; overload raises
        OverflowError.
        """
        if not raw or len(raw) > 65536:
            raise ValidationError('query body must contain at most 65536 bytes')
        remaining, pending, frames = bytearray(raw), [], 0
        while remaining:
            before = len(remaining)
            # A completed HTTP body cannot supply more bytes after a parser
            # shortage. One cooperative wait therefore means truncation here.
            parser = self.parser.onceParsator(ims=remaining, processive=False, local=False)
            try:
                try:
                    next(parser)
                except StopIteration as done:
                    dom = done.value
                else:
                    raise ValidationError('truncated legacy evidence frame')
            finally:
                parser.close()
            frames += 1
            if (dom is None or not isinstance(dom.serder, SerderKERI)
                    or dom.serder.pvrsn != Vrsn_1_0 or len(remaining) >= before or frames > 32):
                raise ValidationError('expected complete v1 KERI message frames')
            event = dom.serder
            if event.ilk in ('icp', 'dip', 'rot', 'drt', 'ixn'):
                if event.pre not in self.readers:
                    raise AuthError('KEL introduction is not an allowed reader')
                self.parser.msgProcess(asdict(dom), kvy=self.kvy, tvy=None,
                                       exc=None, rvy=None, vry=None)
                continue
            if event.ilk != 'qry' or event.route not in ('tels', 'tsn'):
                raise ValidationError('only legacy tels/tsn queries are supported')
            source = self.signer(dom)
            query = event.sad['q']
            if not isinstance(query, dict) or any(not isinstance(query.get(key), str)
                                                   for key in ('ri', 'src', 'i')):
                raise ValidationError('query requires string registry/source/credential fields')
            if (query.get('ri') != self.registry.regk or query.get('src') != self.hab.pre
                    or 'i' not in query):
                raise ValidationError('query does not select this registry source')
            if query['i'] and self.registry.tever.vcState(query['i']) is None:
                raise ValidationError('credential state is unknown')
            if len(self.outbox) + len(pending) >= 62:
                raise OverflowError('evidence reply queue is full')
            # Legacy Tevery intentionally does not authenticate queries itself.
            # Its normal query/cue contract is called only after the gate above.
            try:
                self.tvy.processQuery(event, source=source)
            finally:
                # Own and drain this entire cue batch before serialization, so
                # one oversized reply cannot leak a later cue into a new request.
                cues = list(self.tvy.cues)
                self.tvy.cues.clear()
            for cue in cues:
                stream = bytearray(self.hab.replay(gvrsn=Vrsn_1_0))
                if cue['kin'] == 'replay':
                    # Tevery's conventional cue uses the library's default
                    # cloner genus. This explicitly v1 endpoint reserializes the
                    # same accepted requested events through the core v1 writer.
                    for pre in (self.registry.regk, query['i']):
                        if pre:
                            stream.extend(b''.join(self.rgy.reger.clonePreIter(
                                pre=pre, gvrsn=Vrsn_1_0)))
                elif cue['kin'] == 'reply':
                    stream.extend(self.hab.reply(route=cue['route'] + '/' + self.hab.pre,
                        data=cue['data'], version=Vrsn_1_0, gvrsn=Vrsn_1_0, kind=Kinds.json))
                else:
                    raise ValidationError('unexpected legacy source cue')
                if len(stream) > 4 * 1024 * 1024:
                    raise OverflowError('stored evidence exceeds the 4 MiB reply limit')
                pending.append(bytes(stream))
        # A refused HTTP body must not publish a reply from an earlier frame.
        # Ordinary accepted KEL introductions retain their processor semantics.
        self.outbox.extend(pending)
        return len(pending)

    def deliver(self, tymth, tock=0.03125, **kwa):
        """Attempt each queued reply once through the ordinary finite sender.

        ``tymth`` and ``tock`` supply HIO scheduling. Transport failure is reported
        without requeueing or interpreting it as receiver acceptance. A subsequent
        authenticated query may request evidence again through the normal path.
        Cancellation unwinds the sender's HTTP owner; no retry policy is added.
        """
        self.wind(tymth)
        yield tock
        while True:
            if not self.outbox:
                yield tock
                continue
            raw = self.outbox.pop(0)
            try:
                yield from cesr_sending.send(self, self.replyTo, raw, self.timeout)
                print(json.dumps(dict(evidenceTransmitted=True, bytes=len(raw))), flush=True)
            except (OSError, TimeoutError, ConfigurationError) as error:
                print(json.dumps(dict(evidenceTransmitted=False, error=str(error))), flush=True)
            yield tock


class QueryEnd:
    """Expose only authenticated v1 evidence queries on the source listener."""

    def __init__(self, source):
        """Retain source's processors/queue; return None and open no resources."""
        self.source = source

    def on_post(self, req, rep):
        """Queue req's signed query and return 202, or a concrete HTTP refusal.

        req/rep are Falcon request/response. Append the standard CESR-ATTACHMENT
        header when present. Return None; transport/framing/authorization failures
        become 400/401/413/415/503 and never signify accepted evidence at a client.
        """
        if (req.content_type or '').split(';')[0] != CESR_CONTENT_TYPE:
            raise falcon.HTTPUnsupportedMediaType()
        if req.get_header('CESR-Genus') not in (None, '1'):
            raise falcon.HTTPBadRequest(description='source requires CESR genus 1')
        if req.content_length is not None and req.content_length > 65536:
            raise falcon.HTTPContentTooLarge()
        raw = req.bounded_stream.read(65537)
        attachment = req.get_header('CESR-ATTACHMENT') or ''
        try:
            count = self.source.ingest(raw + attachment.encode('ascii'))
        except OverflowError as error:
            raise falcon.HTTPServiceUnavailable(description=str(error)) from error
        except AuthError as error:
            raise falcon.HTTPUnauthorized(description=str(error)) from error
        except (KeriError, ValueError, KeyError) as error:
            raise falcon.HTTPBadRequest(description=str(error)) from error
        rep.status = falcon.HTTP_202
        rep.media = dict(queued=count)


class HealthEnd:
    """Report listener readiness without exposing private or registry state."""

    def on_get(self, req, rep):
        """Set rep's ready JSON for req and return None; no storage is accessed."""
        rep.media = dict(ready=True)


def serve(args):
    """Open existing v1 owners and return finite-owned HTTP/source lifecycle doers.

    args supplies identity, one registry, readers, fixed reply URL and listener.
    Return HIO doers. Wrong protocol/alias/registry or authentication raises before
    listener use. Cancellation closes server and stores. Restart after external
    issuance/revocation is explicit; this service invents no cache coherence.
    """
    if args.version != Vrsn_1_0:
        raise ConfigurationError('legacy evidence service requires --version 1.0')
    keeper = Keeper(name=args.name, base=args.base, reopen=True)
    try:
        aeid = keeper.gbls.get('aeid')
        if aeid is None:
            raise ConfigurationError('existing Keeper is required')
    finally:
        keeper.close()
    hby = setupHby(args.name, args.base, args.bran if aeid else None,
                   noPrompt=True, version=Vrsn_1_0)
    rgy = server = None
    try:
        hab = hby.habByName(args.alias)
        if hab is None or isinstance(hab, GroupHab) or hab.kever.serder.pvrsn != Vrsn_1_0:
            raise ConfigurationError('source requires an existing individual v1 alias')
        rgy = Regery(hby=hby, name=args.name, base=args.base)
        registry = rgy.registryByName(args.registry_name)
        if registry is None or registry.hab.pre != hab.pre:
            raise ConfigurationError('registry is not controlled by this source')
        source = Source(hby, rgy, hab, registry, args.reader, args.reply_to, args.timeout)
        server = createHttpServer(args.host, args.port, source.app)
        if not server.reopen():
            raise OSError('source listener could not bind')
        server.servant.eha = server.servant.ha
        # Scheduler exit reverses this order: source HTTP children, listener,
        # registry, then identity. No live child retains a closed store.
        return [HaberyDoer(habery=hby), Closing(rgy),
                http.ServerDoer(server=server), source]
    except BaseException:
        if server is not None:
            server.close()
        if rgy is not None:
            rgy.close()
        hby.close()
        raise


class Closing(doing.Doer):
    """Close an owned legacy registry after scheduled source children unwind."""

    def __init__(self, rgy):
        """Retain caller-owned rgy for lifecycle exit; return None, open nothing."""
        self.rgy = rgy
        super().__init__()

    def exit(self):
        """Close the retained Regery on cancellation; return None, errors propagate."""
        self.rgy.close()
