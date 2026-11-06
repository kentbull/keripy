"""Registry roots replicate to members as ESSR exchanges over real KELs, TELs and Keepers."""

import json
from contextlib import ExitStack, contextmanager
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pysodium
import pytest

from keri import Vrsn_2_0 as V2
from keri.acdc import Regery, Registrar, acdcmap
from keri.acdc.salting import RegistryRoot, RootDeferred, RootRefused, RootUnverified, rootExn
from keri.app import Notifier, openCF, openHby
from keri.core import (Codens, Counter, Dater, Diger, Kevery, Kramer, MtrDex, Parser, Salter,
                       SealSource, SerderKERI, Signer, Texter, exchange, messagize)
from keri.help import helping
from keri.kering import Ilks, Kinds, ValidationError
from keri.peer import Exchanger

Fixture = Path(__file__).parent / "fixtures" / "registry_root_essr.json"


def receive(side, wire):
    ims = bytearray(wire)
    side.psr.parse(ims=ims, framed=False)
    assert not ims


def said(wire):
    return Parser(version=V2).parseOne(ims=bytearray(wire), processive=False).serder.said


def stored(side):
    return [item['said'] for item in side.root.pending()]


@contextmanager
def world(*, enabled=True, newcomer=False, late=()):
    """Individual issuer; Alice/Bob 2-of-2 holder group, optionally Outsider as next-key member.

    Sides named in ``late`` do not receive the registry TEL or its issuer
    anchors; those messages wait in ``w.late`` for later delivery.
    """
    with ExitStack() as stack:
        sides = []
        for n, name in enumerate(('issuer', 'alice', 'bob', 'outsider'), 1):
            signer = Signer(raw=bytes([n]) * 32, transferable=False)
            hby = stack.enter_context(openHby(name=f'root-{name}', base='test', version=V2,
                salt=Salter(raw=bytes([n]) * 16).qb64, seed=signer.qb64, aeid=signer.verfer.qb64))
            hab = hby.makeHab(name=name)
            rgy = Regery(hby=hby, name=f'root-{name}', temp=True)
            stack.callback(rgy.close)
            cf = stack.enter_context(openCF(name=f'root-{name}', base='test'))
            cf.put(dict(kram=dict(enabled=enabled, denials=[],
                caches={'~': [1000, 5000, 60000, 300000, 5000, 60000, 300000]})))
            notifier = Notifier(hby=hby)
            root = RegistryRoot(hby, rgy, notifier=notifier)
            exc = Exchanger(hby=hby, handlers=[root])
            kvy = Kevery(db=hby.db, rvy=hby.rvy, exc=exc, kramer=Kramer(db=hby.db, cf=cf))
            sides.append(SimpleNamespace(hby=hby, hab=hab, rgy=rgy, kvy=kvy, exc=exc, root=root,
                notifier=notifier, psr=Parser(version=V2, kvy=kvy, rvy=hby.rvy, exc=exc, rgy=rgy)))
        issuer, alice, bob, outsider = sides
        for side in sides:
            for other in sides:
                if side is not other:
                    receive(side, other.hab.msgOwnEvent(sn=0, framed=False, gvrsn=V2))
        mids = [alice.hab.pre, bob.hab.pre]
        wires = []
        for side in (alice, bob):
            side.group = side.hby.makeGroupHab(group='group', mhab=side.hab, smids=mids,
                rmids=mids + [outsider.hab.pre] if newcomer else mids,
                isith='2', nsith='1', version=V2)
            wires.append(side.group.msgOwnInception(allowPartiallySigned=True, framed=False, gvrsn=V2))
        for side in sides:
            for wire in wires:
                receive(side, wire)
            side.kvy.processEscrows()
            assert alice.group.pre in side.hby.kevers
        registrar = Registrar(issuer.rgy)
        registry = registrar.makeRegistry('existing', issuer.hab.pre)
        deferred = []

        def transfer(event):
            kel = issuer.hab.interact(data=[dict(i=registry.regk, s=event.sad['n'], d=event.said)],
                                      framed=False, gvrsn=V2)
            assert registry.anchorMsg(event.said)
            anchor = SerderKERI(raw=kel)
            tel = messagize(event, bonds=[SealSource(s=anchor.snh, d=anchor.said)], gvrsn=V2)
            for side in sides[1:]:
                if side.hab.name in late:
                    deferred.append((side, kel, tel))
                    continue
                receive(side, kel)
                receive(side, tel)
                assert side.rgy.store.headEvent(registry.regk).said == event.said

        transfer(issuer.rgy.store.event(registry.regk))
        root = Salter(raw=b'public-test-root')
        issuer.hab.mgr.putRegistryRoot(issuer.hab.pre, registry.regk, root)
        acdc = acdcmap(israid=issuer.hab.pre, iseaid=alice.group.pre,
                       regid=registry.regk, attribute=dict(d='', role='member'))
        opening, event = registrar.issue(registry, acdc, salt=root.qb64, state='issued')
        transfer(event)
        gid = alice.group.pre
        yield SimpleNamespace(sides=sides, issuer=issuer, alice=alice, bob=bob, outsider=outsider,
                              registry=registry.regk, root=root, opening=opening, event=event,
                              acdc=acdc, gid=gid, late=deferred)


def held(w, side, gid=None):
    return side.hby.mgr.getRegistryRoot(gid or w.gid, w.registry)


def copy(w, sender, recipient, *, td=None, gid=None):
    """Send one authorized copy from sender's individual habitat and return its SAID."""
    wire = sender.root.prepare(sender.hab, recipient.hab.pre, gid or w.gid, w.registry,
                               td=w.acdc.said if td is None else td)
    receive(recipient, wire)
    return said(wire)


def seed(w):
    """The issuer's cross-party copy gives Alice's group its first root on arrival."""
    copy(w, w.issuer, w.alice)
    assert held(w, w.alice).qb64 == w.root.qb64 and stored(w.alice) == []


def rotate(w, members, current, *, sith, hold=()):
    """Real member and group rotations; ``current`` becomes the signing roster.

    Sides in ``hold`` sign but do not yet see the others' signatures; the
    rotation wires wait in ``w.held`` for later delivery.
    """
    for member in members:
        kel = member.hab.rotate(framed=False, gvrsn=V2)
        for side in w.sides:
            if side is not member:
                receive(side, kel)
    author = current[0]
    if not hasattr(author, 'group'):
        author.group = author.hby.joinGroupHab(pre=w.gid, group='joined', mhab=author.hab,
            smids=[side.hab.pre for side in current], rmids=[side.hab.pre for side in current])
    wires = [author.group.rotate(smids=[side.hab.pre for side in current],
        rmids=[side.hab.pre for side in current],
        verfers=[side.hab.kever.verfers[0] for side in current],
        digers=[side.hab.kever.ndigers[0] for side in current],
        isith=sith, nsith=sith, framed=False, gvrsn=V2)]
    event = Parser(version=V2).parseOne(ims=bytearray(wires[0]), processive=False).serder
    for other in current[1:]:
        if not hasattr(other, 'group'):
            other.group = other.hby.joinGroupHab(pre=w.gid, group='joined', mhab=other.hab,
                smids=[side.hab.pre for side in current], rmids=[side.hab.pre for side in current])
        wires.append(other.group.rotate(serder=event, smids=[side.hab.pre for side in current],
            rmids=[side.hab.pre for side in current], framed=False, gvrsn=V2))
    w.held = wires
    for side in w.sides:
        if side in hold:
            assert side.hby.kevers[w.gid].serder.said != event.said
            continue
        for wire in wires:
            side.psr.parse(ims=bytearray(wire), framed=False, local=True)
        side.kvy.processEscrows()
        assert side.hby.kevers[w.gid].serder.said == event.said
    return event.said


@pytest.mark.parametrize('enabled', [False, True])
def test_member_copy_is_retained_on_arrival_by_commitment_reproduction(enabled):
    with world(enabled=enabled) as w:
        seed(w)
        bob = w.bob
        assert held(w, bob) is None
        pending = copy(w, w.alice, bob)
        # No approval step: the handler verifies and retains the root at once.
        assert held(w, bob).qb64 == w.root.qb64 and bob.root.pending() == []
        assert bob.hby.db.exns.get(keys=(pending,)) is not None
        (note,) = notes(bob)
        assert note['r'] == RegistryRoot.Note and note['d'] == pending and 'deferred' not in note
        # A second holder's identical copy is retained idempotently with no second note.
        copy(w, w.issuer, bob)
        assert held(w, bob).qb64 == w.root.qb64 and bob.root.pending() == []
        assert len(notes(bob)) == 1


def test_unverifiable_root_stays_escrowed_until_a_held_opening_is_supplied():
    with world() as w:
        seed(w)
        pending = copy(w, w.alice, w.bob, td='')
        assert stored(w.bob) == [pending] and held(w, w.bob) is None and notes(w.bob) == []
        w.bob.exc.processEscrow()
        assert stored(w.bob) == [pending]
        with pytest.raises(RootUnverified):
            w.bob.root.receive(pending)
        assert stored(w.bob) == [pending]
        # Manual retry supplies evidence the copy lacks.
        assert w.bob.root.receive(pending, opening=w.opening) is True
        assert held(w, w.bob).qb64 == w.root.qb64 and stored(w.bob) == []


def test_escrowed_copy_is_retried_by_a_fresh_handler_over_the_same_store():
    with world(late=('bob',)) as w:
        seed(w)
        pending = copy(w, w.alice, w.bob)
        assert stored(w.bob) == [pending]
        for side, kel, tel in w.late:
            receive(side, kel)
            receive(side, tel)
        restarted = RegistryRoot(w.bob.hby, w.bob.rgy)
        exc = Exchanger(hby=w.bob.hby, handlers=[restarted])
        assert [item['said'] for item in restarted.pending()] == [pending]
        exc.processEscrow()
        assert held(w, w.bob).qb64 == w.root.qb64 and restarted.pending() == []


def late(w):
    for side, kel, tel in w.late:
        receive(side, kel)
        receive(side, tel)


def test_deferred_copy_is_retained_long_after_it_was_escrowed():
    with world(late=('bob',)) as w:
        seed(w)
        pending = copy(w, w.alice, w.bob)
        # The copy entered escrow two hours ago, before any former timeout.
        old = helping.toIso8601(helping.nowUTC() - timedelta(hours=2))
        w.bob.hby.db.rrpe.pin(keys=(pending,), val=Dater(dts=old))
        w.bob.exc.processEscrow()
        assert stored(w.bob) == [pending] and held(w, w.bob) is None
        assert w.bob.root.pending()[0]['escrowed'] == old
        late(w)
        w.bob.exc.processEscrow()
        assert held(w, w.bob).qb64 == w.root.qb64 and stored(w.bob) == []
        assert [note['d'] for note in notes(w.bob)] == [pending]


def test_identical_resend_of_an_unretained_stored_copy_is_escrowed_again():
    with world(late=('bob',)) as w:
        seed(w)
        wire = w.alice.root.prepare(w.alice.hab, w.bob.hab.pre, w.gid, w.registry, td=w.acdc.said)
        pending = said(wire)
        receive(w.bob, wire)
        assert stored(w.bob) == [pending]
        # The stored copy left escrow without retention (dropped or expired).
        w.bob.hby.db.rrpe.rem(keys=(pending,))
        assert stored(w.bob) == [] and w.bob.hby.db.exns.get(keys=(pending,)) is not None
        receive(w.bob, wire)
        assert stored(w.bob) == [pending]
        late(w)
        receive(w.bob, wire)  # still escrowed: ignored, not escrowed twice
        assert stored(w.bob) == [pending] and held(w, w.bob) is None
        w.bob.exc.processEscrow()
        assert held(w, w.bob).qb64 == w.root.qb64 and stored(w.bob) == []
        # Once retained, the identical resend is ignored and adds no note.
        receive(w.bob, wire)
        assert stored(w.bob) == [] and [note['d'] for note in notes(w.bob)] == [pending]


@pytest.mark.parametrize('enabled', [False, True])
def test_duplicate_delivery_is_idempotent(enabled):
    with world(enabled=enabled) as w:
        seed(w)
        wire = w.alice.root.prepare(w.alice.hab, w.bob.hab.pre, w.gid, w.registry, td=w.acdc.said)
        receive(w.bob, wire)
        receive(w.bob, wire)
        assert held(w, w.bob).qb64 == w.root.qb64 and stored(w.bob) == []
        assert w.bob.notifier.noter.notes.cntAll() == 1
        # A duplicate of a still-escrowed copy is not escrowed twice.
        wire = w.alice.root.prepare(w.alice.hab, w.bob.hab.pre, w.gid, w.registry, td='')
        receive(w.bob, wire)
        receive(w.bob, wire)
        assert stored(w.bob) == [said(wire)]


def test_kram_exempts_a_copy_delivered_long_after_its_window():
    assert [[2, 0], Ilks.exn, RegistryRoot.Route] in [list(d) for d in Kramer.StoreForwardDenials]
    with world(enabled=True) as w:
        seed(w)
        plain = dict(i=w.alice.hab.pre, ri=w.bob.hab.pre, gid=w.gid, rd=w.registry,
                     s=w.root.qb64, e=w.event.said, td=w.acdc.said)
        # A mailbox copy fetched a day after it was sent, far past the 6 s window.
        stale = helping.toIso8601(helping.nowUTC() - timedelta(days=1))
        wire = forge(w.alice, w.bob.hab.pre, w.gid, w.registry, plain, stamp=stale)
        receive(w.bob, wire)
        assert stored(w.bob) == [] and held(w, w.bob).qb64 == w.root.qb64


def notes(side):
    return [note.attrs for _, note in side.notifier.noter.notes.getTopItemIter()]


@pytest.mark.parametrize('missing', ['tel', 'rotation'])
def test_offline_newcomer_copy_is_retained_by_escrow_once_local_state_arrives(missing):
    with world(newcomer=True, late=('outsider',) if missing == 'tel' else ()) as w:
        seed(w)
        copy(w, w.alice, w.bob)
        assert held(w, w.bob).qb64 == w.root.qb64
        current = [w.alice, w.bob, w.outsider]
        rotate(w, current, current, sith='2', hold=(w.outsider,) if missing == 'rotation' else ())
        # The witnesser sends catch-up while the newcomer still lacks local state.
        pending = copy(w, w.alice, w.outsider)
        assert stored(w.outsider) == [pending] and notes(w.outsider) == []
        w.outsider.exc.processEscrow()
        assert held(w, w.outsider) is None and stored(w.outsider) == [pending]
        with pytest.raises(RootDeferred, match='not yet verifiable'):
            w.outsider.root.receive(pending)
        if missing == 'tel':
            for side, kel, tel in w.late:
                receive(side, kel)
                receive(side, tel)
        else:
            for wire in w.held:
                w.outsider.psr.parse(ims=bytearray(wire), framed=False, local=True)
            w.outsider.kvy.processEscrows()
        assert held(w, w.outsider) is None
        # Ordinary escrow processing retains it; no approval, no resend.
        w.outsider.exc.processEscrow()
        assert held(w, w.outsider).qb64 == w.root.qb64 and stored(w.outsider) == []
        assert [note['d'] for note in notes(w.outsider)] == [pending]


def test_member_removed_before_escrow_retry_is_refused_and_dropped():
    with world(newcomer=True, late=('bob',)) as w:
        seed(w)
        pending = copy(w, w.alice, w.bob)
        assert stored(w.bob) == [pending]
        rotate(w, [w.alice, w.outsider], [w.alice, w.outsider], sith='2')
        for side, kel, tel in w.late:
            receive(side, kel)
            receive(side, tel)
        w.bob.exc.processEscrow()
        assert held(w, w.bob) is None and stored(w.bob) == [] and notes(w.bob) == []
        with pytest.raises(ValidationError, match='current signing member') as refusal:
            w.bob.root.receive(pending)
        assert not isinstance(refusal.value, RootUnverified)


def test_deferred_copy_with_unbound_plaintext_is_dropped_on_retry():
    with world(late=('bob',)) as w:
        seed(w)
        plain = dict(i=w.issuer.hab.pre, ri=w.bob.hab.pre, gid=w.gid, rd=w.registry,
                     s=w.root.qb64, e=w.event.said, td=w.acdc.said)
        wire = forge(w.alice, w.bob.hab.pre, w.gid, w.registry, plain)
        receive(w.bob, wire)
        assert stored(w.bob) == [said(wire)]
        for side, kel, tel in w.late:
            receive(side, kel)
            receive(side, tel)
        w.bob.exc.processEscrow()
        assert stored(w.bob) == [] and held(w, w.bob) is None and notes(w.bob) == []


def forge(sender, recipient, gid, registry, plain, *, digest=None, sealed=None, stamp=None):
    raw = sealed if sealed is not None else pysodium.crypto_box_seal(
        json.dumps(plain).encode(), pysodium.crypto_sign_pk_to_box_pk(
            sender.hby.kevers[recipient].verfers[0].raw))
    texter = Texter(raw=raw)
    serder = exchange(sender=sender.hab.pre, receiver=recipient, route=RegistryRoot.Route,
        attributes=dict(essr=digest or Diger(ser=raw, code=MtrDex.Blake3_256).qb64,
                        gid=gid, rd=registry), stamp=stamp, version=V2, kind=Kinds.json)
    signed = sender.hab.endorse(serder, framed=True, gvrsn=V2)
    atc = bytes(signed[serder.size:]) + Counter(Codens.ESSRPayloadGroup,
        count=len(texter.qb64b) // 4, version=V2).qb64b + texter.qb64b
    return serder.raw + bytes(Counter.enclose(qb64=atc, code=Codens.AttachmentGroup, version=V2))


@pytest.mark.parametrize('fault', ['digest', 'payload', 'wrong-recipient', 'outsider-sender',
                                   'group-recipient'])
def test_unauthorized_or_unbound_copies_are_refused_and_never_persisted(fault):
    with world() as w:
        seed(w)
        alice, bob = w.alice, w.bob
        plain = dict(i=alice.hab.pre, ri=bob.hab.pre, gid=w.gid, rd=w.registry,
                     s=w.root.qb64, e=w.event.said)
        sender, recipient, registry = alice, bob.hab.pre, w.registry
        kwa = {}
        if fault == 'digest':
            kwa['digest'] = Diger(ser=b'other', code=MtrDex.Blake3_256).qb64
        elif fault == 'payload':
            kwa['sealed'] = b'not the digested box'
            kwa['digest'] = Diger(ser=b'not the digested box!', code=MtrDex.Blake3_256).qb64
        elif fault == 'wrong-recipient':
            recipient = w.outsider.hab.pre  # Not a member, and not local to Bob.
        elif fault == 'outsider-sender':
            sender = w.outsider
        elif fault == 'group-recipient':
            recipient = w.gid
        wire = forge(sender, recipient, w.gid, registry, plain, **kwa)
        receive(bob, wire)
        assert bob.hby.db.exns.get(keys=(said(wire),)) is None
        assert bob.root.pending() == [] and held(w, bob) is None
        assert bob.notifier.noter.notes.cntAll() == 0


@pytest.mark.parametrize('fault', ['unknown-registry', 'holder-not-local'])
def test_copies_missing_local_state_are_stored_pending_not_dropped(fault):
    with world() as w:
        seed(w)
        alice, bob = w.alice, w.bob
        gid, registry = w.gid, w.registry
        if fault == 'unknown-registry':
            registry = w.event.said  # Not a registry Bob has accepted.
        else:
            gid = w.issuer.hab.pre  # No local habitat for this holder.
        plain = dict(i=alice.hab.pre, ri=bob.hab.pre, gid=gid, rd=registry,
                     s=w.root.qb64, e=w.event.said)
        wire = forge(alice, bob.hab.pre, gid, registry, plain)
        receive(bob, wire)
        assert stored(bob) == [said(wire)] and notes(bob) == []
        bob.exc.processEscrow()
        with pytest.raises(RootDeferred):
            bob.root.receive(said(wire))
        assert held(w, bob) is None and stored(bob) == [said(wire)]


@pytest.mark.parametrize('fault', ['inner-sender', 'inner-recipient', 'inner-gid', 'inner-registry',
                                   'noncanonical-root', 'wrong-root', 'stale-key'])
def test_copy_with_bad_plaintext_key_or_root_is_never_retained(fault):
    with world() as w:
        seed(w)
        alice, bob = w.alice, w.bob
        plain = dict(i=alice.hab.pre, ri=bob.hab.pre, gid=w.gid, rd=w.registry,
                     s=w.root.qb64, e=w.event.said, td=w.acdc.said)
        if fault == 'inner-sender':
            plain['i'] = w.issuer.hab.pre
        elif fault == 'inner-recipient':
            plain['ri'] = alice.hab.pre
        elif fault == 'inner-gid':
            plain['gid'] = bob.hab.pre
        elif fault == 'inner-registry':
            plain['rd'] = w.event.said
        elif fault == 'noncanonical-root':
            plain['s'] = w.root.qb64 + 'AAAA'
        elif fault == 'wrong-root':
            plain['s'] = Salter(raw=b'wrong-test-root!').qb64
        wire = forge(alice, bob.hab.pre, w.gid, w.registry, plain)
        if fault == 'stale-key':
            kel = bob.hab.rotate(framed=False, gvrsn=V2)
            for side in w.sides:
                if side is not bob:
                    receive(side, kel)
        receive(bob, wire)
        pending = said(wire)
        assert held(w, bob) is None and notes(bob) == []
        assert bob.hby.db.exns.get(keys=(pending,)) is not None
        # Hard refusals leave escrow at once; a wrong root may still be an
        # unknown commitment, so it waits for evidence.
        assert stored(bob) == ([pending] if fault == 'wrong-root' else [])
        error = RootUnverified if fault == 'wrong-root' else RootRefused
        with pytest.raises(error):
            bob.root.receive(pending)
        assert held(w, bob) is None


def test_conflicting_retained_root_is_never_replaced():
    with world() as w:
        seed(w)
        other = Salter(raw=b'wrong-test-root!')
        w.bob.hby.mgr.putRegistryRoot(w.gid, w.registry, other)
        pending = copy(w, w.alice, w.bob)
        # Refused on arrival and dropped from escrow; the retained root stays.
        assert held(w, w.bob).qb64 == other.qb64 and stored(w.bob) == [] and notes(w.bob) == []
        with pytest.raises(RootRefused):
            w.bob.root.receive(pending, opening=w.opening)
        assert held(w, w.bob).qb64 == other.qb64


def test_copy_with_a_root_other_than_the_retained_one_is_refused_and_dropped():
    with world() as w:
        seed(w)
        copy(w, w.alice, w.bob)
        assert held(w, w.bob).qb64 == w.root.qb64 and len(notes(w.bob)) == 1
        # The wrong root never reproduces the commitment; without this refusal
        # it would wait in escrow forever behind the immutable retained root.
        plain = dict(i=w.alice.hab.pre, ri=w.bob.hab.pre, gid=w.gid, rd=w.registry,
                     s=Salter(raw=b'wrong-test-root!').qb64, e=w.event.said, td=w.acdc.said)
        wire = forge(w.alice, w.bob.hab.pre, w.gid, w.registry, plain)
        receive(w.bob, wire)
        assert stored(w.bob) == [] and held(w, w.bob).qb64 == w.root.qb64
        assert len(notes(w.bob)) == 1
        with pytest.raises(RootRefused, match='different root'):
            w.bob.root.receive(said(wire))
        assert held(w, w.bob).qb64 == w.root.qb64


def test_newcomer_catches_up_after_real_rotation_and_removed_member_is_never_recipient():
    with world(newcomer=True) as w:
        seed(w)
        copy(w, w.alice, w.bob)
        assert held(w, w.bob).qb64 == w.root.qb64
        with pytest.raises(ValidationError, match='current signing member'):
            w.alice.root.prepare(w.alice.hab, w.outsider.hab.pre, w.gid, w.registry)
        current = [w.alice, w.bob, w.outsider]
        rotation = rotate(w, current, current, sith='2')
        assert w.alice.root.newcomers(w.alice.group, rotation) == [w.outsider.hab.pre]
        assert w.alice.root.witnesser(w.alice.group, rotation)
        assert not w.bob.root.witnesser(w.bob.group, rotation)
        copy(w, w.alice, w.outsider)
        assert stored(w.outsider) == []
        # Every current member holds every root the group knows.
        assert {held(w, side).qb64 for side in current} == {w.root.qb64}


def test_full_roster_replacement_catch_up_from_removed_historical_member():
    with world(newcomer=True) as w:
        seed(w)
        copy(w, w.alice, w.bob)
        assert held(w, w.bob).qb64 == w.root.qb64
        rotation = rotate(w, [w.outsider], [w.outsider], sith='1')
        assert w.bob.root.newcomers(w.bob.group, rotation) == [w.outsider.hab.pre]
        # Bob left the roster: never a recipient, still an authorized historical sender.
        with pytest.raises(ValidationError, match='current signing member'):
            w.alice.root.prepare(w.alice.hab, w.bob.hab.pre, w.gid, w.registry)
        copy(w, w.bob, w.outsider)
        assert held(w, w.outsider).qb64 == w.root.qb64


def test_essr_round_trip_fixture_decrypts_and_binds():
    vector = json.loads(Fixture.read_text())
    wire = vector['wire'].encode()
    frame = Parser(version=V2).parseOne(ims=bytearray(wire), processive=False)
    serder, (texter,) = frame.serder, frame.essrs
    assert serder.ked['r'] == RegistryRoot.Route and serder.pre == vector['sender']
    assert serder.ked['ri'] == vector['recipient']
    assert set(serder.ked['a']) == {'essr', 'gid', 'rd'}
    assert Diger(qb64=serder.ked['a']['essr']).verify(ser=texter.raw)
    signer = Signer(qb64=vector['recipient_seed'])
    assert signer.verfer.qb64 == vector['recipient_key']
    prikey = pysodium.crypto_sign_sk_to_box_sk(signer.raw + signer.verfer.raw)
    plain = pysodium.crypto_box_seal_open(texter.raw,
        pysodium.crypto_scalarmult_curve25519_base(prikey), prikey)
    assert json.loads(plain) == vector['plaintext']
    assert vector['plaintext']['i'] == serder.pre and vector['plaintext']['ri'] == serder.ked['ri']
    assert {k: vector['plaintext'][k] for k in ('gid', 'rd')} == {
        k: serder.ked['a'][k] for k in ('gid', 'rd')}


def test_essr_negative_fixture_vector_fails_its_digest():
    vector = json.loads(Fixture.read_text())
    good = Parser(version=V2).parseOne(ims=bytearray(vector['wire'].encode()), processive=False)
    (negative,) = vector['negative']
    assert negative['name'] == 'essr-digest-mismatch'
    frame = Parser(version=V2).parseOne(ims=bytearray(negative['wire'].encode()), processive=False)
    # The signed exchange is unchanged; only the attached payload differs.
    assert frame.serder.said == good.serder.said
    assert frame.essrs[0].raw != good.essrs[0].raw
    assert not Diger(qb64=frame.serder.ked['a']['essr']).verify(ser=frame.essrs[0].raw)


def test_root_exn_requires_individual_sender_and_salt128():
    with world() as w:
        with pytest.raises(ValidationError):
            rootExn(w.alice.group, w.bob.hab.pre, w.gid, w.registry, w.root, event=w.event.said)
        with pytest.raises(ValidationError):
            rootExn(w.alice.hab, w.bob.hab.pre, w.gid, w.registry, w.root.qb64, event=w.event.said)


def test_every_member_holds_every_root_after_group_dh():
    from tests.acdc.test_group_dh import exchange as dh, groups, receive as deliver

    with groups(count=2) as h:
        for side in h.members:
            side.root = RegistryRoot(side.hby, side.rgy)
            side.exc.addHandler(side.root)
        dh(h)
        regks = [reg.regk for reg in h.registries]
        hints = {}
        # Replication needs an accepted BUP to verify against; issue in each registry.
        for registry in h.registries:
            node = acdcmap(israid=h.issuers[0].hab.pre, iseaid=h.issuees[0].hab.pre,
                           regid=registry.regk, attribute=dict(d='', role='member'))
            _, event = h.registrar.issue(registry, node,
                salt=h.issuers[0].hab.mgr.getRegistryRoot(h.issuers[0].hab.pre, registry.regk).qb64)
            h.anchor(event)
            hints[registry.regk] = node.said
        for members in (h.issuers, h.issuees):
            custodian = members[h.lead]
            cues = [cue for cue in custodian.dh.cues if cue['kin'] == 'replicate']
            assert cues == [dict(kin='replicate', gid=custodian.hab.pre, registries=regks)]
            others = [side for side in members if side is not custodian]
            assert {side.member.pre for side in others} | {custodian.member.pre} == set(
                custodian.hby.db.signingMembers(pre=custodian.hab.pre))
            # KEL-derived current members, the default send recipients.
            assert set(custodian.root.members(custodian.hab.pre)) == {
                side.member.pre for side in members}
            for side in others:
                for registry in h.registries:
                    deliver(side, custodian.root.prepare(custodian.member, side.member.pre,
                        custodian.hab.pre, registry.regk, td=hints[registry.regk]))
                assert side.root.pending() == []
                assert side.root.held(side.hab.pre) == sorted(regks)
        for registry in h.registries:
            for members in (h.issuers, h.issuees):
                roots = {side.hby.mgr.getRegistryRoot(side.hab.pre, registry.regk).qb64
                         for side in members}
                assert len(roots) == 1
