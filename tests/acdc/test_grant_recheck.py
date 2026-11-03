"""Current rechecks read exact accepted evidence without rewriting observations."""

from types import SimpleNamespace

import pytest

from keri import Vrsn_1_0 as V1, Vrsn_2_0 as V2
from keri.acdc import acdcmap, admit, apply, grant, loadHandlers, sectattr
from keri.acdc import chaining
from keri.acdc.sectioning import retainSections
from keri.app import openHby
from keri.core import Blinder, Compactor, Diger, Number, Parser, messagize
from keri.kering import MissingSignatureError, ValidationError
from keri.peer import Exchanger
from keri.peer.exchanging import loadParsedNestedSubstreams, serializeParsedSubstream
from keri.vc import protocoling
from keri.vdr.eventing import Reger
from tests.acdc.test_pending_presentation import history, present, receive, anchor, signed


def recheck(h, message):
    """Even an idempotent database write or new cue violates this boundary."""
    before = h.hby.db.env.info()['last_txnid'], tuple(h.exc.cues)
    try:
        return h.exc.reverifyGrant(message.said)
    finally:
        assert h.hby.db.env.info()['last_txnid'] == before[0]
        assert tuple(h.exc.cues) == before[1]


def test_current_revoked_observation_and_missing_suffix_preserve_retained_rows(history):
    h = history
    message, atc = present(h, h.proofs[1:])
    receive(h, message, atc)
    saved = h.hby.db.exrs.get((message.said, h.acdc.said))
    nests = tuple(h.hby.db.enst.get((message.said,)))
    body, held, verdict, records = recheck(h, message)
    assert body.raw == message.raw and held[0].serder.raw == h.acdc.raw
    assert verdict.verdict == chaining.Verdicts.valid
    assert records[h.acdc.said].state == 'revoked'  # Authentication is not issued-state policy.
    _, event = h.registrar.vacate(h.registry)
    anchor(h.issuer, h.registry, event)
    _, _, verdict, records = recheck(h, message)
    assert verdict.verdict == chaining.Verdicts.unknown and verdict.retryable
    assert h.acdc.said not in records
    assert h.hby.db.exrs.get((message.said, h.acdc.said)) == saved
    assert tuple(h.hby.db.enst.get((message.said,))) == nests
    assert h.hby.db.epse.get((message.said,)) is None
    assert h.hby.db.exns.get((message.said,)).raw == message.raw


@pytest.mark.parametrize('opener', ['grant', 'apply'])
def test_recheck_after_admit_and_expiry_is_not_auxiliary_authorization(history, fakeHelpingClock, opener):
    h = history
    prior = {}
    if opener == 'apply':
        request, ratc = apply(hab=h.verifier, recp=h.holder.pre, message='request',
            modifiers=dict(dp=[[[h.acdc.schema['$id'], '/', []]]]))
        receive(h, request, ratc)
        prior['apply'] = request
    message, atc = present(h, h.proofs[1:], **prior)
    receive(h, message, atc)
    response, ratc = admit(hab=h.verifier, message='received', grant=message)
    receive(h, response, ratc)
    fakeHelpingClock.advance(seconds=301)
    assert h.exc.presentationContext(message.said, xid=message.sad.get('x') or message.said,
        sender=h.holder.pre, recipient=h.verifier.pre) is None
    _, _, verdict, records = recheck(h, message)
    assert verdict.verdict == chaining.Verdicts.valid and records[h.acdc.said].state == 'revoked'
    # A new process owner gets no operation approval, but can recheck accepted data.
    h.exc = Exchanger(h.hby, handlers=[])
    loadHandlers(h.hby, h.exc, SimpleNamespace(add=lambda **_: None), rgy=h.rgy)
    assert recheck(h, message)[2].verdict == chaining.Verdicts.valid


@pytest.mark.parametrize('fault', ['sender', 'source', 'issuer-opening'])
def test_recheck_refuses_substituted_authentication_without_writes(history, fault):
    h = history
    message, atc = present(h, h.proofs[1:])
    receive(h, message, atc)
    # Deliberately corrupt lower-level retained storage, never ordinary intake.
    if fault == 'sender':
        h.hby.db.esigs.trim((message.said,))
    elif fault == 'source':
        h.hby.db.ests.add((message.said, h.holder.pre),
                         (Number(num=0), Diger(qb64=h.holder.pre)))
    else:
        nests = loadParsedNestedSubstreams(h.hby, message.said)
        nests[0].bsqs[-1] = Blinder.blind(acdc=h.acdc.said, state='issued').data
        h.hby.db.enst.pin((message.said,), [bytes(serializeParsedSubstream(n)) for n in nests])
        assert recheck(h, message)[2].verdict == chaining.Verdicts.invalid
        return
    with pytest.raises(MissingSignatureError):
        recheck(h, message)


def test_pending_presence_cannot_enable_retained_exception(history):
    h = history
    message, atc = present(h)
    receive(h, message, atc)
    assert h.hby.db.epse.get((message.said,)) is not None
    with pytest.raises(ValidationError, match='accepted V2 Grant'):
        recheck(h, message)
    wrong = Diger(ser=b'wrong accepted key').qb64
    h.hby.db.exns.put((wrong,), message)  # Explicitly corrupted lower-level index.
    with pytest.raises(ValidationError, match='accepted V2 Grant'):
        h.exc.reverifyGrant(wrong)


def test_durable_recheck_keeps_exact_partial_view_after_fuller_section_arrival(tmp_path, fakeHelpingClock):
    for phase in range(2):
        with openHby(name='current-partial', temp=False, headDirPath=str(tmp_path), version=V2) as hby:
            exc = Exchanger(hby, handlers=[])
            loadHandlers(hby, exc, SimpleNamespace(add=lambda **_: None))
            h = SimpleNamespace(hby=hby, exc=exc)
            if phase == 0:
                issuer = hby.makeHab(name='issuer')
                holder = hby.makeHab(name='holder')
                verifier = hby.makeHab(name='verifier')
                full = acdcmap(israid=issuer.pre, iseaid=holder.pre,
                    attribute=dict(d='', shown=dict(d='', value='visible'),
                                   hidden=dict(d='', value='not disclosed')))
                sector = Compactor(mad=full.sad['a'], makify=True, kind=full.kind)
                sector.compact(paths=['a/shown/'], root='a')
                partial = acdcmap(israid=issuer.pre, iseaid=holder.pre,
                    attribute=sector.partials[('a/shown/',)].mad)
                assert partial.said == full.said
                message, atc = grant(hab=holder, recp=verifier.pre, message='partial',
                    origin=signed(partial, issuer))
                receive(h, message, atc)
                assert exc.complete(message.said)
                response, ratc = admit(hab=verifier, message='received', grant=message)
                receive(h, response, ratc)
                original = tuple(hby.db.enst.get((message.said,)))
                # Actual independent held material is fuller than this Grant.
                reger = Reger(name=hby.name, headDirPath=str(tmp_path), temp=False)
                try:
                    retainSections(reger, sectattr(full.sad['a']))
                finally:
                    reger.close()
                fakeHelpingClock.advance(seconds=301)
            _, nests, verdict, records = recheck(h, message)
            assert verdict.verdict == chaining.Verdicts.valid and not records
            assert nests[0].serder.raw == partial.raw
            assert isinstance(nests[0].serder.sad['a']['hidden'], str)
            assert tuple(hby.db.enst.get((message.said,))) == original


def test_one_exchanger_selects_real_version_handlers_before_auth_and_escrow():
    class Dual(Exchanger):
        def handlerFor(self, serder):
            return self.legacy if serder.pvrsn == V1 else super().handlerFor(serder)

    with openHby(name='version-ipex', temp=True, version=V2) as hby:
        sender = hby.makeHab(name='sender', icount=2, isith='2', ncount=2, nsith='2')
        receiver = hby.makeHab(name='receiver')
        notice = SimpleNamespace(add=lambda **_: None)
        exc = Dual(hby, handlers=[])
        loadHandlers(hby, exc, notice)
        exc.legacy = protocoling.IpexHandler('/ipex/apply', hby, notice)
        old, _ = protocoling.ipexApplyExn(sender, receiver.pre, 'legacy',
            Diger(ser=b'schema').qb64, {}, version=V1, gvrsn=V1)
        new, _ = apply(hab=sender, recp=receiver.pre, message='native', modifiers=dict(dp=[[]]))
        for message in (old, new):
            signatures = sender.sign(message.raw)
            group = sender.kever.prefixer, Number(num=0), Diger(qb64=sender.pre)
            first = messagize(message, tsgs=[(*group, signatures[:1])], gvrsn=message.pvrsn)
            Parser(version=message.pvrsn).parse(ims=bytearray(first), exc=exc)
            assert hby.db.epse.get((message.said,)) is not None
            # Put the second normal signature into the existing escrow, then
            # exercise its sole owner's replay and version lookup.
            exc.escrowPSEvent(message, tsgs=[(*group, signatures[1:])], pathed=[])
        exc.processEscrow()
        assert all(exc.complete(message.said) for message in (old, new))
        assert all(hby.db.epse.get((message.said,)) is None for message in (old, new))
        assert exc.handlerFor(old) is exc.legacy
        assert exc.handlerFor(new) is exc.routes['/ipex/apply']
