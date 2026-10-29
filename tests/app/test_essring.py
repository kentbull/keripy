"""Authenticated ultimate-member ESSR replies; all attributes are nonsecret."""
from contextlib import ExitStack

import pytest
import pysodium

from keri.app import openCF, openHab, openHby
from keri.app.essring import EssrReplyHandler, envelope
from keri.core import (Bexter, Counter, Codens, Diger, Kramer, Parser, Prefixer, Texter, reply)
from keri.kering import Kinds, Vrsn_1_0, Vrsn_2_0, ValidationError
from keri.peer import Exchanger, specialExchange
from keri.spac import PayloadTyper, PayloadTypes


ROUTE = '/test/registry-salt'


class ReplyOwner:
    def __init__(self, rvy, sender):
        self.rvy, self.sender, self.accepted = rvy, sender, []

    def processReply(self, serder, diger, route, cigars, tsgs):
        if not self.rvy.acceptReply(serder=serder, saider=diger, route=route,
                                    aid=self.sender, cigars=cigars, tsgs=tsgs):
            raise ValidationError('Inner reply signature rejected')
        self.accepted.append(serder.said)


@pytest.fixture(params=[Vrsn_1_0, Vrsn_2_0])
def peers(request):
    version = request.param
    with ExitStack() as stack:
        ahby, alice = stack.enter_context(openHab(name='alice', temp=True, version=version))
        bhby, bob = stack.enter_context(openHab(name='bob', temp=True, version=version))
        _, carol = stack.enter_context(openHab(name='carol', temp=True, version=version))
        parser = Parser(kvy=bhby.kvy, rvy=bhby.rvy, version=version)
        parser.parse(ims=alice.replay(gvrsn=version), local=False)
        parser.parse(ims=carol.replay(gvrsn=version), local=False)
        owner = ReplyOwner(bhby.rvy, alice.pre)
        bhby.rvy.rtr.addRoute(ROUTE, owner)
        handler = EssrReplyHandler(bhby, bob, parser, {ROUTE})
        parser.exc = Exchanger(hby=bhby, handlers=[handler])
        yield version, alice, bob, carol, bhby, parser, owner


def inner(alice, version, route=ROUTE, signer=None):
    serder = reply(route=route, data=dict(i=alice.pre, payload='ciphertext-placeholder'),
                   pre=alice.pre, pvrsn=version, kind=Kinds.json)
    return (signer or alice).endorse(serder=serder, framed=True, gvrsn=version)


def seal(alice, bob, msg, version):
    return envelope(alice, msg, bob.pre, bob.kever.verfers[0], version=version,
                    establishment=(bob.kever.lastEst.s, bob.kever.lastEst.d))


def rewrite_outer(alice, stream, version, *, signer=None, q=None, corrupt=False, ciphertext=None):
    parsed = Parser(version=version).parseOne(ims=bytearray(stream), processive=False)
    ciphertext = parsed.essrs[0].raw if ciphertext is None else ciphertext
    if corrupt:
        ciphertext = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    serder = parsed.serder
    if q is not None:
        serder, _ = specialExchange(sender=alice.pre, route='/essr/req', modifiers=q,
                                    diger=Diger(ser=ciphertext), version=Vrsn_1_0)
    texter = Texter(raw=ciphertext)
    stream = (signer or alice).endorse(serder=serder, framed=True, gvrsn=version)
    stream.extend(Counter(Codens.ESSRPayloadGroup,
                          count=1 if version.major < 2 else len(texter.qb64b) // 4,
                          gvrsn=version).qb64b)
    stream.extend(texter.qb64b)
    return stream


def test_authenticated_ultimate_reply(peers):
    version, alice, bob, carol, bhby, parser, owner = peers
    msg = inner(alice, version)
    stream = seal(alice, bob, msg, version)
    parsed = Parser(version=version).parseOne(ims=bytearray(stream), processive=False)
    assert parsed.serder.ked['q']['dest'] == bob.pre
    assert b'ciphertext-placeholder' not in stream
    plain = bytearray(bob.mgr.decrypt(qb64=parsed.essrs[0].raw, verfers=bob.kever.verfers))
    assert parser.extract(plain, PayloadTyper).type == PayloadTypes.SCS
    assert parser.extract(plain, Prefixer).qb64 == alice.pre
    assert parser.extract(plain, Bexter).bext == ''
    assert plain == msg
    with pytest.raises(Exception):
        carol.mgr.decrypt(qb64=parsed.essrs[0].raw, verfers=carol.kever.verfers)
    parser.parse(ims=bytearray(stream), local=False)
    assert len(owner.accepted) == 1
    assert bhby.db.exns.get(keys=(parsed.serder.said,)) is not None


@pytest.mark.parametrize('fault', ['type', 'source', 'missing-header'])
def test_rejects_authenticated_outer_with_invalid_scs_header(peers, fault):
    """A valid outer signature cannot authorize a different encrypted SCS source."""
    version, alice, bob, carol, bhby, parser, owner = peers
    msg = inner(alice, version)
    wire = seal(alice, bob, msg, version)
    outer = Parser(version=version).parseOne(ims=bytearray(wire), processive=False)
    tag = PayloadTypes.HOP if fault == 'type' else PayloadTypes.SCS
    source = carol.pre if fault == 'source' else alice.pre
    plain = (PayloadTyper(type=tag).qb64b + source.encode() + Bexter(bext='').qb64b + msg)
    if fault == 'missing-header':
        plain = msg
    key = pysodium.crypto_sign_pk_to_box_pk(bob.kever.verfers[0].raw)
    cipher = pysodium.crypto_box_seal(bytes(plain), key)
    changed = rewrite_outer(alice, wire, version, q=outer.serder.sad['q'], ciphertext=cipher)
    parser.parse(ims=changed, local=False)
    assert owner.accepted == []


@pytest.mark.parametrize('fault', ['outer-signer', 'outer-src', 'recipient', 'key-binding',
                                  'ciphertext', 'sealed-other-key', 'inner-signer', 'inner-route',
                                  'inner-unsigned', 'inner-truncated', 'inner-multiple',
                                  'inner-exn'])
def test_rejects_invalid_envelopes_and_inner_replies(peers, fault):
    version, alice, bob, carol, bhby, parser, owner = peers
    msg = inner(alice, version,
                route='/not/allowed' if fault == 'inner-route' else ROUTE,
                signer=carol if fault == 'inner-signer' else None)
    if fault == 'inner-unsigned':
        msg = bytearray(Parser(version=version).parseOne(
            ims=bytearray(msg), processive=False).serder.raw)
    elif fault == 'inner-truncated':
        msg = msg[:-1]
    elif fault == 'inner-multiple':
        msg += inner(alice, version)
    elif fault == 'inner-exn':
        msg = envelope(alice, b'not a reply', bob.pre, bob.kever.verfers[0], version=version)
    stream = seal(alice, bob, msg, version)
    if fault == 'outer-signer':
        stream = rewrite_outer(alice, stream, version, signer=carol)
    elif fault == 'ciphertext':
        stream = rewrite_outer(alice, stream, version, corrupt=True)
    elif fault == 'sealed-other-key':
        parsed = Parser(version=version).parseOne(ims=bytearray(stream), processive=False)
        stream = envelope(alice, msg, carol.pre, carol.kever.verfers[0], version=version)
        stream = rewrite_outer(alice, stream, version, q=parsed.serder.ked['q'])
    elif fault in ('outer-src', 'recipient', 'key-binding'):
        parsed = Parser(version=version).parseOne(ims=bytearray(stream), processive=False)
        q = dict(parsed.serder.ked['q'])
        q[{'outer-src': 'src', 'recipient': 'dest', 'key-binding': 'key'}[fault]] = carol.pre
        stream = rewrite_outer(alice, stream, version, q=q)
    parser.parse(ims=stream, local=False)
    assert owner.accepted == []


def test_retained_recipient_key_and_unrelated_key_rejection(peers):
    version, alice, bob, carol, bhby, parser, owner = peers
    stream = seal(alice, bob, inner(alice, version), version)
    bob.rotate(gvrsn=version)
    parser.parse(ims=stream, local=False)
    assert len(owner.accepted) == 1


def test_inner_v2_owner_denylist_is_preserved(peers):
    version, alice, bob, carol, bhby, parser, owner = peers
    if version.major < 2:
        pytest.skip('V2 owner policy')
    # Outer V1 EXN still verifies; the inner V2 reply must cross owner policy.
    parser.kvy.denyList.add(alice.pre)
    parser.parse(ims=seal(alice, bob, inner(alice, version), version), local=False)
    assert owner.accepted == []


def test_inner_v2_configured_kram_is_preserved(peers):
    version, alice, bob, carol, bhby, parser, owner = peers
    if version.major < 2:
        pytest.skip('V2 owner policy')
    with openCF(name='essr-kram', temp=True) as cf:
        cf.put(dict(kram=dict(enabled=True, denials=[], caches={
            '~': [1000, 5000, 60000, 300000, 5000, 60000, 300000]})))
        parser.kvy.kramer = Kramer(db=bhby.db, cf=cf)
        msg = inner(alice, version)
        said = Parser(version=version).parseOne(ims=bytearray(msg),
                                               processive=False).serder.said
        stream = seal(alice, bob, msg, version)
        parser.parse(ims=bytearray(stream), local=False)
        assert owner.accepted == [said]
        assert bhby.db.kramMSGC.get(keys=(alice.pre, said)) is not None
        parser.parse(ims=bytearray(stream), local=False)
        assert owner.accepted == [said]


def test_requires_local_single_key_individual():
    with openHby(name='many', temp=True) as hby:
        hab = hby.makeHab(name='many', icount=2, isith='2')
        with pytest.raises(ValidationError, match='local individual'):
            EssrReplyHandler(hby, hab, hby.psr, {ROUTE})


def test_missing_private_key_is_explicit(peers):
    version, alice, bob, carol, bhby, parser, owner = peers
    stream = seal(alice, bob, inner(alice, version), version)
    parsed = Parser(version=version).parseOne(ims=stream, processive=False)
    bhby.mgr.ks.pris.rem(keys=bob.kever.verfers[0].qb64)
    with pytest.raises(ValidationError, match='private key is unavailable'):
        parser.exc.routes['/essr/req'].handle(serder=parsed.serder, essr=parsed.essrs[0].raw)
    assert owner.accepted == []


def test_recipient_coordinates_are_canonical_establishment_events(peers):
    version, alice, bob, carol, bhby, parser, owner = peers
    stream = seal(alice, bob, inner(alice, version), version)
    parsed = Parser(version=version).parseOne(ims=stream, processive=False)
    handler = parser.exc.routes['/essr/req']
    for sn in ('-1', '00', '0x0', 'A', 0):
        q = dict(parsed.serder.ked['q'], sn=sn)
        outer = rewrite_outer(alice, seal(alice, bob, inner(alice, version), version),
                              version, q=q)
        outer = Parser(version=version).parseOne(ims=outer, processive=False)
        with pytest.raises(ValidationError, match='Invalid ESSR reply envelope'):
            handler.verify(serder=outer.serder, essr=outer.essrs[0].raw)
    bob.interact(gvrsn=version)
    q = dict(parsed.serder.ked['q'], sn='1', dig=bob.kever.serder.said)
    outer = rewrite_outer(alice, seal(alice, bob, inner(alice, version), version),
                          version, q=q)
    outer = Parser(version=version).parseOne(ims=outer, processive=False)
    with pytest.raises(ValidationError, match='Invalid ESSR reply envelope'):
        handler.verify(serder=outer.serder, essr=outer.essrs[0].raw)
    with pytest.raises(ValidationError, match='allowed routes'):
        EssrReplyHandler(bhby, bob, parser, ROUTE)
