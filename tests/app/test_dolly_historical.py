"""Dolly historical inspection preserves proof validity and reporting policy.

The bound-graph construction adapts test_bound_state_profile's real anchored
history. Independent verifier/observer stores add application policy, retained
disclosure, actual webhook silence, and reopen without replay.
"""
from copy import deepcopy
from dataclasses import asdict
import json

import falcon
from falcon import testing
from hio.base import doing
from hio.core import http, tcp
import pytest

from keri import Kinds, Vrsn_2_0
from keri.acdc import Regery, Registrar, acdcmap, blindate, grant, sectattr
from keri.acdc.regbasing import RegBaser
from keri.acdc.sectioning import SectionBaser
from keri.app.dolly.serving import Context as Dolly, DollyBaser
from keri.app.habbing import openHby
from keri.app.httping import CESR_CONTENT_TYPE
from keri.app.observer.serving import Context as Observer
from keri.app.registrar.serving import Context as Evidence, signedQuery
from keri.core import Blinder, Codens, Compactor, Counter, Diger, Noncer, Number, SealSource, messagize
from keri.kering import MissingChainError, ValidationError
from keri.peer import exchanging
from keri.vdr import eventing as legacy, verifying


def native(*events):
    """Frame public native messages with explicit empty attachment groups."""
    foot = Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b
    return b''.join(event.raw + foot for event in events)


def test_historical_bound_graph_inspection_is_not_current_reporting(tmp_path):
    """Inspect valid historical authority after revocation without issuing a hook.

    Far issuance binds Issuee event 0, near issuance anchors in event 1, and far
    revocation binds event 1. The core establishes that historical relationship;
    Dolly's default still refuses current reporting of the revoked far node.
    Inspection makes no observation/freshness claim and survives a full reopen.
    """
    received = []

    class Hook:
        """Record any attempted acceptance delivery through a real HTTP server."""

        def on_post(self, req, rep):
            """Capture the request so inspection cannot hide an accidental hook."""
            received.append(req.media)
            rep.media = {'received': True}

    app = falcon.App()
    app.add_route('/hook', Hook())
    server = http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=app)
    assert server.reopen()
    server.servant.eha = server.servant.ha
    hook = f'http://127.0.0.1:{server.servant.ha[1]}/hook'
    try:
        with (openHby(name='historical-source', version=Vrsn_2_0) as source,
              openHby(name='historical-observer', version=Vrsn_2_0) as observer):
            authority = source.makeHab(name='authority')
            issuer = source.makeHab(name='issuer')
            rgy = Regery(source, name=source.name, temp=True)
            try:
                registry = Registrar(rgy).makeRegistry(name='authority', prefix=authority.pre)
                rip = rgy.store.event(registry.regk)
                authority.interact(data=[dict(s=rip.sad['n'], d=rip.said)])
                assert registry.anchorMsg(rip.said)
                far = acdcmap(israid=authority.pre, iseaid=issuer.pre, regid=registry.regk,
                              attribute=dict(d='', role='historical delegation'))
                full = acdcmap(israid=issuer.pre, uuid=Noncer().qb64,
                    edge=dict(d='', authority=dict(n=far.said)),
                    attribute={'d': '', 'u': Noncer().qb64,
                        'shown': {'d': '', 'value': 'historically authorized'},
                        'private': {'d': '', 'value': 'not-in-this-grant'}})
                compact = Compactor(mad=deepcopy(full.sad['a']), makify=True, kind=Kinds.json)
                compact.compact(paths=['a/shown/'], root='a')
                near = acdcmap(israid=issuer.pre, uuid=full.sad['u'], schema=full.schema,
                    edge=full.sad['e'], attribute=compact.partials[('a/shown/',)].mad)
                assert near.said == full.said

                def publish(state):
                    """Anchor a real far-state update bound to the Issuee's current KEL event."""
                    keyEvent = issuer.kever.serder
                    opening = Blinder.blind(acdc=far.said, state=state, bound=True,
                                           bsn=keyEvent.sn, bd=keyEvent.said)
                    event = blindate(registry.regk, registry.regd, opening.said,
                                     sn=registry.sn + 1)
                    registry.processEvent(event)
                    authority.interact(data=[dict(s=event.sad['n'], d=event.said)])
                    assert registry.anchorMsg(event.said)
                    return opening, event

                issued, issueEvent = publish('issued')
                issuer.interact(data=[dict(d=near.said)])
                nearSource = SealSource(Number(num=issuer.kever.sn), Diger(qb64=issuer.kever.serder.said))
                revoked, revokeEvent = publish('revoked')
                public = authority.replay(gvrsn=Vrsn_2_0) + issuer.replay(gvrsn=Vrsn_2_0)
                public += native(rip, issueEvent, revokeEvent)
                proofNear = messagize(near, bonds=[nearSource], framed=False, gvrsn=Vrsn_2_0)
                proofFar = messagize(far, bonds=[issued.data, revoked.data], framed=False, gvrsn=Vrsn_2_0)
                plan = {'dp': [[[near.schema['$id'], '/', []],
                                [far.schema['$id'], '/e/authority/_/', []]]]}
                expected = None
                for phase in range(2):
                    with openHby(name='historical-dolly', temp=False,
                                 headDirPath=str(tmp_path), version=Vrsn_2_0) as verifier:
                        dhab = verifier.habByName('dolly') or verifier.makeHab(name='dolly')
                        dolly = Dolly(verifier, dhab, issuers=[issuer.pre, authority.pre],
                            schemas=[near.schema['$id']], fields={'shown': 'a/shown/value',
                            'private': 'a/private/value'}, required=['shown'],
                            observer=f'http://observer-{phase}.test/', webhook=hook,
                            db=DollyBaser(name=verifier.name, headDirPath=str(tmp_path), temp=False),
                            evidence=Evidence(verifier, reger=RegBaser(name=verifier.name,
                                headDirPath=str(tmp_path), temp=False)),
                            legacy=verifying.Verifier(verifier, reger=legacy.Reger(name=verifier.name,
                                headDirPath=str(tmp_path), temp=False)),
                            sections=SectionBaser(name=verifier.name, headDirPath=str(tmp_path), temp=False))
                        try:
                            if phase == 0:
                                dolly.ingest(public)
                                exn, atc = grant(issuer, dhab.pre, 'historical bound graph',
                                    origin=proofNear, artifacts=[proofFar], modifiers=plan)
                                assert dolly.ingest(exn.raw + atc) == [dict(grant=exn.said, state='pending')]
                            assert dolly.native.verifyAccepted(exn.said)
                            assert not dolly.fresh(registry.regk)
                            before = asdict(dolly.db.submissions.get((exn.said,)))
                            inspected = dolly.inspectHistorical(exn.said)
                            assert asdict(dolly.db.submissions.get((exn.said,))) == before
                            assert inspected['purpose'] == 'historical-evidence'
                            assert inspected['proofValidity'] == 'valid'
                            assert inspected['currentStanding'] == 'not-evaluated'
                            assert inspected['business'] == {'shown': 'historically authorized', 'private': None}
                            assert inspected['disclosure']['private'] == 'undisclosed'
                            assert 'not-in-this-grant' not in json.dumps(inspected)
                            assert 'acceptedAt' not in inspected
                            nearRef, farRef = inspected['sources']
                            assert nearRef == dict(credential=near.said, view=Diger(ser=near.raw).qb64,
                                                   boundEvents=[])
                            assert farRef == dict(credential=far.said, view=Diger(ser=far.raw).qb64,
                                boundEvents=[dict(registry=registry.regk, s=event.sad['n'], d=event.said,
                                    blid=proof.said, issuee=issuer.pre,
                                    keyEvent=dict(s=proof.bnh, d=proof.bd))
                                    for proof, event in [(issued, issueEvent), (revoked, revokeEvent)]])
                            if phase == 0:
                                expected = inspected
                                obs = Observer(observer, readers=[dhab.pre], urls=['http://registrar.test/'])
                                try:
                                    obs.ingest(dhab.replay(gvrsn=Vrsn_2_0))
                                    assert not obs.observe('http://registrar.test/', public)['rejected']
                                    response = testing.TestClient(obs.app).simulate_post('/',
                                        body=signedQuery(dhab, 'tels', {'i': registry.regk}),
                                        headers={'Content-Type': CESR_CONTENT_TYPE})
                                    report = dict(status=response.status_code, body=response.content,
                                        headers={key.lower(): value for key, value in response.headers.items()})
                                    assert dolly.observe(registry.regk, report)
                                finally:
                                    obs.close()
                                dolly.process()
                                refused = dolly.db.submissions.get((exn.said,))
                                assert refused.state == 'rejected'
                                assert refused.reason == 'credential is not currently issued'
                                assert refused.payload == {} and not refused.delivered
                                assert dolly.inspectHistorical(exn.said) == expected
                                # Generic EXN authentication retains this real envelope,
                                # but its missing issuance opening cannot prove the graph.
                                incomplete = messagize(far, bonds=[revoked.data],
                                                       framed=False, gvrsn=Vrsn_2_0)
                                invalid, invalidAtc = grant(issuer, dhab.pre, 'incomplete bound graph',
                                    origin=proofNear, artifacts=[incomplete], modifiers=plan)
                                generic = exchanging.Exchanger(verifier, handlers=[])
                                dolly._parser(Vrsn_2_0).parse(ims=bytearray(invalid.raw + invalidAtc), exc=generic)
                                assert generic.complete(invalid.said)
                            else:
                                assert inspected == expected  # No KEL/TEL/grant replay on reopen.
                                with pytest.raises(MissingChainError, match='observer evidence'):
                                    dolly._nativeCredential(exn)
                            with pytest.raises(ValidationError, match='proof or semantics'):
                                dolly.inspectHistorical(invalid.said)
                            assert dolly.db.submissions.get((invalid.said,)) is None
                            # Fuller cached evidence cannot widen historical inspection.
                            dolly.ingest(native(sectattr(full.sad['a'])))
                            assert dolly.inspectHistorical(exn.said) == expected
                            doing.Doist(real=True, tock=0.01, limit=0.2).do(
                                doers=[http.ServerDoer(server=server), dolly])
                            assert received == []
                        finally:
                            dolly.close()
            finally:
                rgy.close()
    finally:
        server.close()
