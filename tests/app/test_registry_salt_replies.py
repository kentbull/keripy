"""Exact local salt reply semantics with real KERI reply signing and parsing."""

from copy import deepcopy

import pytest

from keri import Vrsn_1_0, Vrsn_2_0
from keri.acdc.messaging import regcept
from keri.app import openHby, registry_salt_replies as replies, registry_salts
from keri.core import Diger, MtrDex, Parser, SerderKERI, reply
from keri.core.signing import Salter
from keri.kering import Kinds, ValidationError


STAMP = '2026-10-29T00:00:00.000000+00:00'


@pytest.fixture
def parties():
    """Yield real accepted issuer, entitled discloser and unrelated habitats."""
    with openHby(name='registry-salt-replies', version=Vrsn_2_0) as hby:
        yield [hby.makeHab(name=name, version=Vrsn_2_0)
               for name in ('issuer', 'discloser', 'outsider')]


def coordinates(hab):
    """Return the accepted local representative's public establishment coordinate."""
    return dict(s=f'{hab.kever.lastEst.s:x}', d=hab.kever.lastEst.d)


def conversation(parties, starter=0):
    """Build either-direction init/bind, matching roots and issuer confirmation."""
    issuer, discloser, _ = parties
    first, other = parties[starter], parties[1 - starter]
    firstPub, firstSecret = registry_salts.generateKeypair()
    otherPub, otherSecret = registry_salts.generateKeypair()
    rip = regcept(issuer.pre, stamp=STAMP)
    init = replies.initReply(sender=first.pre, issuer=issuer.pre, discloser=discloser.pre,
        rep=first.pre, est=coordinates(first), key=firstPub.qb64, stamp=STAMP)
    bind = replies.bindReply(init, rip, sender=other.pre, rep=other.pre,
        est=coordinates(other), key=otherPub.qb64, stamp=STAMP)
    root = registry_salts.deriveRoot(firstSecret, otherPub, init.raw, bind.raw)
    peerRoot = registry_salts.deriveRoot(otherSecret, firstPub, init.raw, bind.raw)
    assert root.raw == peerRoot.raw
    confirm = replies.confirmReply(init, bind, rip, root, stamp=STAMP)
    return init, bind, confirm, rip, root


def changed(original, *, sender=None, route=None, **changes):
    """Re-SAID one altered public reply through core.reply, without a serializer."""
    data = deepcopy(original.sad['a'])
    data.update(changes)
    return reply(pre=sender or original.pre, route=route or original.route, data=data,
        stamp=original.stamp, version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)


@pytest.mark.parametrize('starter', [0, 1])
def test_both_directions_exact_signed_reply_bodies(parties, starter):
    """Either party initiates, opposite party binds, and issuer confirms exact bytes."""
    init, bind, confirm, rip, root = conversation(parties, starter)
    assert replies.validateInit(init) is init
    assert replies.validateBind(init, bind, rip) is bind
    assert replies.validateConfirm(init, bind, confirm, rip) is confirm
    assert init.route == '/keri-rnd/registry-salt/1/init'
    assert bind.route == '/keri-rnd/registry-salt/1/bind'
    assert confirm.route == '/keri-rnd/registry-salt/1/confirm'
    assert init.pre == parties[starter].pre and bind.pre == parties[1 - starter].pre
    assert confirm.pre == parties[0].pre
    assert confirm.sad['a']['commitment'] == registry_salts.commitment(root, init.raw, bind.raw).qb64
    assert confirm.sad['a']['entitled'] == [parties[0].pre, parties[1].pre]
    assert all(root.qb64.encode() not in body.raw for body in (init, bind, confirm))
    for body in (init, bind, confirm):
        signer = next(hab for hab in parties if hab.pre == body.pre)
        stream = signer.endorse(body, gvrsn=Vrsn_2_0)
        parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(stream), processive=False)[0]
        assert parsed.serder.raw == body.raw
        prefixer, _, _, sigers = parsed.tsgs[0]
        assert prefixer.qb64 == body.pre
        assert signer.kever.verfers[0].verify(sigers[0].raw, body.raw)


@pytest.mark.parametrize('field,value', [
    ('issuer', 'bad-prefix'), ('rep', 'bad-representative'),
    ('key', 'not-a-key'), ('key', Salter(raw=b'0123456789abcdef').qb64),
    ('est', {'s': '00', 'd': Diger(ser=b'event').qb64}),
    ('est', {'s': '-1', 'd': Diger(ser=b'event').qb64}),
    ('est', {'s': 'A', 'd': Diger(ser=b'event').qb64}),
    ('est', {'s': True, 'd': Diger(ser=b'event').qb64}),
    ('est', {'s': '0', 'd': 'bad-digest'}),
    ('est', {'s': '0', 'd': Diger(ser=b'event').qb64, 'i': 'extra'}),
    ('suite', 'unknown-suite'), ('profile', 'unknown-profile'),
    ('purpose', 'other-purpose'), ('extra', 'unfrozen-extension'),
])
def test_reject_malformed_init_fields(parties, field, value):
    """Canonical primitives, exact fields and fixed profile constrain the init body."""
    init, _, _, _, _ = conversation(parties)
    with pytest.raises(ValidationError):
        replies.validateInit(changed(init, **{field: value}))


def test_reject_init_role_and_wire_mismatches(parties):
    """Distinct roles and a party-authored exact v2 JSON reply are mandatory."""
    init, _, _, _, _ = conversation(parties)
    wrongBodies = [changed(init, sender=parties[2].pre),
        changed(init, discloser=parties[0].pre), changed(init, route='/rnd/registry-salt/init'),
        reply(pre=init.pre, route=init.route, data=init.sad['a'], stamp=STAMP,
              version=Vrsn_1_0, kind=Kinds.json),
        reply(pre=init.pre, route=init.route, data=init.sad['a'], stamp=STAMP,
              version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.cbor)]
    for wrong in wrongBodies:
        with pytest.raises(ValidationError):
            replies.validateInit(wrong)
    broken = SerderKERI(raw=init.raw.replace(b'registry-state', b'xxxxxxxxxxxxxx'), verify=False)
    with pytest.raises(ValidationError):
        replies.validateInit(broken)


def test_reject_bind_source_registry_and_cross_references(parties):
    """A bind must reference exact init and an issuer-controlled exact supplied rip."""
    init, bind, _, rip, _ = conversation(parties)
    for wrong in (changed(bind, sender=init.pre), changed(bind, sender=parties[2].pre),
                  changed(bind, init=Diger(ser=b'other-init').qb64),
                  changed(bind, registry=Diger(ser=b'other-registry').qb64),
                  changed(bind, init='truncated'), changed(bind, key=init.sad['a']['key'] + 'AAAA'),
                  changed(bind, profile='other-profile')):
        with pytest.raises(ValidationError):
            replies.validateBind(init, wrong, rip)
    otherRip = regcept(parties[2].pre, stamp=STAMP)
    wrong = changed(bind, registry=otherRip.said)
    with pytest.raises(ValidationError, match='issuer registry inception'):
        replies.validateBind(init, wrong, otherRip)
    with pytest.raises(ValidationError):
        replies.bindReply(init, init, sender=bind.pre, rep=bind.sad['a']['rep'],
            est=bind.sad['a']['est'], key=bind.sad['a']['key'])


def test_reject_confirm_role_entitlement_and_commitment(parties):
    """Only issuer confirmation can bind the exact pair and initial two-party entitlement."""
    init, bind, confirm, rip, _ = conversation(parties)
    for wrong in (changed(confirm, sender=parties[1].pre),
                  changed(confirm, init=Diger(ser=b'other-init').qb64),
                  changed(confirm, bind=Diger(ser=b'other-bind').qb64),
                  changed(confirm, registry=Diger(ser=b'other-registry').qb64),
                  changed(confirm, entitled=[parties[0].pre, parties[1].pre, parties[2].pre]),
                  changed(confirm, entitled=[parties[1].pre, parties[0].pre]),
                  changed(confirm, commitment=Diger(ser=b'wrong-code').qb64),
                  changed(confirm, commitment='truncated'), changed(confirm, extra='forbidden')):
        with pytest.raises(ValidationError):
            replies.validateConfirm(init, bind, wrong, rip)


def test_semantic_validation_does_not_claim_root_agreement(parties):
    """A correctly encoded foreign commitment needs the explicit local-root comparison."""
    init, bind, confirm, rip, root = conversation(parties)
    other = changed(confirm, commitment=Diger(ser=b'unrelated-root', code=MtrDex.SHA2_256).qb64)
    assert replies.validateConfirm(init, bind, other, rip) is other
    assert other.sad['a']['commitment'] != registry_salts.commitment(root, init.raw, bind.raw).qb64


def test_public_key_full_consumption_and_canonical_establishment(parties):
    """Reject trailing CESR data and numeric coordinates rather than coerce them."""
    init, bind, _, rip, _ = conversation(parties)
    for key in (init.sad['a']['key'][:-1], init.sad['a']['key'] + 'AAAA'):
        with pytest.raises(ValidationError):
            replies.validateInit(changed(init, key=key))
    for sn in (0, False, '', '0x0', '01', 'f' * 35):
        with pytest.raises(ValidationError):
            replies.validateBind(init, changed(bind, est={'s': sn, 'd': bind.sad['a']['est']['d']}), rip)
