"""A released KERIpy issuer/source speaking its own legacy protocol over HTTP.

This file intentionally imports only APIs shipped in keri 1.2.14 and 1.3.6.
No current-checkout modules, receiver rows, or synthetic accepted replies are used.
"""
from dataclasses import asdict
import importlib.metadata
import json
import platform
from pathlib import Path
from urllib.parse import urlsplit

import falcon
from hio.base import doing
from hio.core import http, tcp

import keri
from keri.app import habbing
from keri.core import coring, counting, eventing, parsing, scheming
from keri.vc import proving, protocoling
from keri.vdr import eventing as veventing, viring



class Peer(doing.DoDoer):
    def __init__(self, hby):
        self.hby = hby
        self.hab = hby.makeHab(name='issuer')
        self.reger = viring.Reger(name='legacy-source', temp=True)
        self.tvy = veventing.Tevery(db=hby.db, reger=self.reger)
        self.parser = parsing.Parser(kvy=hby.kvy, tvy=self.tvy)
        self.registry = veventing.incept(self.hab.pre, cnfg=['NB'])
        self.anchor(self.registry)
        self.schema = scheming.Schemer(sed={
            '$id': '', '$schema': 'http://json-schema.org/draft-07/schema#',
            'type': 'object', 'properties': {'a': {'type': 'object',
                'properties': {'status': {'type': 'string'}}}}, 'required': ['a']})
        self.allowed, self.callback, self.client = False, None, None
        self.inflight, self.outbox, self.responses, self.queries = False, [], [], []
        self.tsnAdapterCalls, self.credentialQuery = 0, None
        self.app = falcon.App()
        self.app.add_route('/', QueryEnd(self))
        self.app.add_route('/profile', ProfileEnd(self))
        self.app.add_route('/artifacts', ArtifactsEnd(self))
        self.app.add_route('/control', ControlEnd(self))
        self.app.add_route('/revoke', RevokeEnd(self))
        self.server = http.Server(servant=tcp.Server(ha=('0.0.0.0', 7723)), app=self.app)
        if not self.server.reopen():
            raise RuntimeError('legacy source HTTP bind failed')
        self.server.servant.eha = self.server.servant.ha
        super().__init__(doers=[http.ServerDoer(server=self.server), doing.doify(self.replyDo)])

    def anchor(self, event):
        self.hab.interact(data=[eventing.SealEvent(event.pre, event.snh, event.said)._asdict()])
        self.tvy.processEvent(serder=event,
            seqner=coring.Seqner(sn=self.hab.kever.sn),
            saider=coring.Saider(qb64=self.hab.kever.serder.said))

    def artifacts(self, *, recipient, source, callback):
        self.allowed = False
        if self.callback is not None:
            raise ValueError('one fresh peer process is required per matrix case')
        self.callback = callback
        credential = proving.credential(schema=self.schema.said, issuer=self.hab.pre,
            recipient=recipient, status=self.registry.pre, data={'status': 'authorized'})
        issuance = veventing.issue(credential.said, self.registry.pre)
        self.anchor(issuance)
        # The released registry serializer supplies its real accepted TEL proof.
        vcp = self.reger.cloneTvtAt(self.registry.pre)
        iss = self.reger.cloneTvtAt(credential.said)
        # Released viring.sources uses this exact public source-triple format.
        proof = (counting.Counter(counting.Codens.SealSourceTriples, count=1,
                                  gvrsn=keri.kering.Vrsn_1_0).qb64b
                 + self.registry.pre.encode() + coring.Seqner(sn=0).qb64b
                 + coring.Saider(qb64=issuance.said).qb64b)
        acdc = viring.messagize(credential, proof)
        self.credential, self.issuance = credential, issuance
        self.origin, self.issuanceMsg, self.issuanceAnchor = acdc, iss, self.hab.makeOwnEvent(sn=self.hab.kever.sn)
        self.recipient = recipient
        grant, attachments = self.grant()
        assert self.reger.tevers[self.registry.pre].vcState(credential.said).d == issuance.said
        self.bootstrap = self.hab.replay() + vcp + self.hab.makeLocScheme(url=source)
        self.grantStream = grant.raw + attachments
        return dict(version=keri.__version__, issuer=self.hab.pre,
            credential=credential.said, grant=grant.said, registry=self.registry.pre,
            issuance=issuance.said, schema=self.schema.sed)

    def grant(self):
        return protocoling.ipexGrantExn(self.hab, self.recipient,
            'released legacy peer disclosure', acdc=self.origin,
            iss=self.issuanceMsg, anc=self.issuanceAnchor)

    def revoke(self):
        event = veventing.revoke(self.credential.said, self.registry.pre, self.issuance.said)
        self.anchor(event)
        assert self.reger.tevers[self.registry.pre].vcState(self.credential.said).et == 'rev'
        # Publish only records computed and serialized by the released core.
        self.outbox.append(self.hab.replay()
            + b''.join(self.reger.clonePreIter(self.registry.pre))
            + b''.join(self.reger.clonePreIter(self.credential.said)))
        for route, state in (
                ('/tsn/registry', self.reger.tevers[self.registry.pre].state()),
                ('/tsn/credential', self.reger.tevers[self.registry.pre].vcState(self.credential.said))):
            self.outbox.append(self.hab.reply(route=route + '/' + self.hab.pre, data=asdict(state)))
        # A fresh, genuine grant carrying the old issuance proof must no longer
        # pass the receiver's current-standing gate after revocation arrives.
        grant, attachments = self.grant()
        self.outbox.append(grant.raw + attachments)
        return dict(grant=grant.said, revocation=event.said)

    def replyDo(self, tymth=None, tock=0.01, **kwa):
        yield tock
        while True:
            if self.client is not None:
                while self.client.responses:
                    response = self.client.responses.popleft()
                    self.responses.append(response['status'])
                    self.inflight = False
            if self.allowed:
                while self.tvy.cues:
                    cue = self.tvy.cues.popleft()
                    if cue['kin'] == 'replay':
                        self.outbox.append(b''.join(cue['msgs']))
                    elif cue['kin'] == 'reply':
                        self.outbox.append(self.hab.reply(
                            route=cue['route'] + '/' + self.hab.pre, data=cue['data']))
            if self.outbox:
                if self.client is None:
                    endpoint = urlsplit(self.callback)
                    self.client = http.clienting.Client(hostname=endpoint.hostname,
                        port=endpoint.port, reconnectable=True)
                    self.extend([http.clienting.ClientDoer(client=self.client)])
                if not self.inflight:
                    self.client.request(method='POST', path=urlsplit(self.callback).path,
                        body=self.outbox.pop(0),
                        headers={'Content-Type': 'application/cesr', 'CESR-Genus': '1'})
                    self.inflight = True
            yield tock

    def shutdown(self):
        if self.client is not None:
            self.client.close()
        self.server.close()
        self.reger.close()


class QueryEnd:
    def __init__(self, peer):
        self.peer = peer

    def on_post(self, req, rep):
        raw = req.bounded_stream.read()
        attachment = req.get_header('CESR-ATTACHMENT') or ''
        query = json.loads(raw)
        self.peer.queries.append(query.get('r'))
        self.peer.parser.parse(ims=bytearray(raw + attachment.encode()))
        if query.get('r') == 'tsn' and query['q'].get('i'):
            self.peer.credentialQuery = query['q']
        rep.status = falcon.HTTP_202


class ProfileEnd:
    def __init__(self, peer):
        self.peer = peer

    def on_get(self, req, rep):
        rep.media = dict(version=keri.__version__, module=keri.__file__,
            distribution=importlib.metadata.version('keri'), python=platform.python_version(),
            sourceSha256=json.loads((Path(__file__).parent / 'profiles.json').read_text())[keri.__version__]['sha256'],
            dependencies={dist.metadata['Name']: dist.version for dist in importlib.metadata.distributions()},
            issuer=self.peer.hab.pre, queries=self.peer.queries,
            responses=self.peer.responses, allowed=self.peer.allowed,
            cues=[cue['kin'] for cue in self.peer.tvy.cues],
            outbox=len(self.peer.outbox), inflight=self.peer.inflight,
            credentialTsnAdapterCalls=self.peer.tsnAdapterCalls)


class ArtifactsEnd:
    def __init__(self, peer):
        self.peer = peer

    def on_post(self, req, rep):
        rep.media = self.peer.artifacts(**req.media)


class RevokeEnd:
    def __init__(self, peer):
        self.peer = peer

    def on_post(self, req, rep):
        rep.media = self.peer.revoke()


class ControlEnd:
    def __init__(self, peer):
        self.peer = peer

    def on_post(self, req, rep):
        self.peer.allowed = req.media['allowReplies']
        if req.media.get('sendBootstrap'):
            self.peer.outbox.append(self.peer.bootstrap)
        if req.media.get('sendGrant'):
            self.peer.outbox.append(self.peer.grantStream)
        if req.media.get('completeCredentialNotice'):
            # Both released processQuery implementations call vcState(vcpre=),
            # but their public signature is vcState(vci). The package remains
            # unmodified: compose the missing notice from its actual core state.
            query = self.peer.credentialQuery
            state = self.peer.reger.tevers[query['ri']].vcState(query['i'])
            self.peer.tvy.cues.append(dict(kin='reply', route='/tsn/credential', data=asdict(state)))
            self.peer.tsnAdapterCalls += 1
        rep.media = {'allowed': self.peer.allowed}


if __name__ == '__main__':
    assert keri.__version__ in ('1.2.14', '1.3.6')
    assert '/site-packages/' in keri.__file__
    with habbing.openHby(name='released-peer', temp=True) as hby:
        peer = Peer(hby)
        try:
            print(json.dumps({'version': keri.__version__, 'issuer': peer.hab.pre}), flush=True)
            doing.Doist(real=True, tock=0.01).do(doers=[peer])
        finally:
            peer.shutdown()
