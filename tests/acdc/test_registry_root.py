"""Registry roots replicate to members as ESSR exchanges over real KELs, TELs and Keepers."""

import json
from contextlib import ExitStack, contextmanager
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pysodium
import pytest

from keri import Vrsn_2_0 as V2
from keri.acdc import Regery, Registrar, acdcmap, ipexing, salting
from keri.acdc.salting import RegistryRoot, RootDeferred, RootRefused, RootUnverified, rootExn
from keri.app import Notifier, openCF, openHby
from keri.core import (Blinder, Codens, Counter, Dater, Diger, Kevery, Kramer, MtrDex, Parser, Salter,
                       Number, SealSource, SerderKERI, Signer, Texter, exchange, messagize)
from keri.help import helping
from keri.kering import Ilks, Kinds, ValidationError
from keri.peer import Exchanger, RouteRefuser
from keri.peer.exchanging import loadParsedNestedSubstreams

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


def resent(monkeypatch, capsys, side, rotation):
    """Run the accepted-rotation re-seal from ``side``; return its (wire, recipient) sends."""
    from keri.cli.common import rootreplicating

    sent = []

    def send(owner, raw, dest, *, topic):
        sent.append((raw, dest))
        yield owner.tock

    monkeypatch.setattr(rootreplicating.sending, 'send', send)
    doer = SimpleNamespace(hby=side.hby, tyme=0.0, tock=0.0, extend=None, remove=None)
    list(rootreplicating.reseal(doer, side.group, side.root, rotation))
    capsys.readouterr()
    return sent


def test_rotation_reseals_to_newcomers_and_rekeyed_members(monkeypatch, capsys):
    with world(newcomer=True) as w:
        seed(w)
        # A held opening is Alice's per-registry hint evidence.
        assert w.alice.rgy.store.putOpening(w.event.said, w.opening)
        current = [w.alice, w.bob, w.outsider]
        rotation = rotate(w, current, current, sith='2')
        # The plain newcomers query is unchanged; the re-seal adds Bob's changed key.
        assert w.alice.root.newcomers(w.alice.group, rotation) == [w.outsider.hab.pre]
        assert w.alice.root.resealed(w.alice.group, rotation) == [w.bob.hab.pre, w.outsider.hab.pre]
        # The newcomer held no prior key, so it owes nothing; Bob holds no root to send.
        assert w.outsider.root.resealed(w.outsider.group, rotation) == []
        assert resent(monkeypatch, capsys, w.outsider, rotation) == []
        assert resent(monkeypatch, capsys, w.bob, rotation) == []
        sent = resent(monkeypatch, capsys, w.alice, rotation)
        assert [dest for _, dest in sent] == [w.bob.hab.pre, w.outsider.hab.pre]
        for wire, dest in sent:
            receive(next(side for side in current if side.hab.pre == dest), wire)
        assert {held(w, side).qb64 for side in current} == {w.root.qb64}
        assert stored(w.bob) == [] and stored(w.outsider) == []


def test_rotation_reseals_a_root_to_a_rotated_member_key(monkeypatch, capsys):
    with world() as w:
        seed(w)
        assert w.alice.rgy.store.putOpening(w.event.said, w.opening)
        rotation = rotate(w, [w.alice, w.bob], [w.alice, w.bob], sith='2')
        assert w.alice.root.newcomers(w.alice.group, rotation) == []
        (wire, dest), = resent(monkeypatch, capsys, w.alice, rotation)
        assert dest == w.bob.hab.pre
        # Sealed to Bob's rotated key, the copy decrypts and is retained on arrival.
        receive(w.bob, wire)
        assert held(w, w.bob).qb64 == w.root.qb64 and stored(w.bob) == []


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
            side.root = salting.loadHandlers(side.hby, side.exc, None, side.rgy)
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


@contextmanager
def issued(count=2):
    """Group DH over ``count`` registries, each Grant ACDC issued and finished by both custodians.

    Each custodian's only verification evidence is its stored Grant: no
    opening is held, so every hint must be derived per registry.
    """
    from tests.acdc.test_group_dh import exchange as dh, groups

    with groups(count=count) as h:
        for side in h.members:
            side.root = salting.loadHandlers(side.hby, side.exc, None, side.rgy)
        dh(h)
        issuer = h.issuers[h.lead]
        h.acdcs = {}
        for nest in loadParsedNestedSubstreams(issuer.hby, h.grant.said):
            registry = next(reg for reg in h.registries if reg.regk == nest.serder.sad['rd'])
            _, event = h.registrar.issue(registry, nest.serder,
                salt=issuer.hab.mgr.getRegistryRoot(issuer.hab.pre, registry.regk).qb64)
            h.anchor(event)
            h.acdcs[registry.regk] = nest.serder.said
        for members in (h.issuers, h.issuees):
            members[h.lead].dh.finish(h.xid)
            assert members[h.lead].hby.db.exns.get((h.grant.said,)) is not None
        yield h


def test_multi_registry_copies_derive_their_own_hint_and_verify_on_arrival():
    from tests.acdc.test_group_dh import receive as deliver

    with issued(count=2) as h:
        regks = sorted(h.acdcs)
        assert len(set(h.acdcs.values())) == 2
        for members in (h.issuers, h.issuees):
            custodian, other = members[h.lead], members[h.lead + 1]
            gid = custodian.hab.pre
            for regk in regks:
                bup = custodian.rgy.store.headEvent(regk)
                root = custodian.hby.mgr.getRegistryRoot(gid, regk)
                uuid = Blinder.makeUUID(salt=root.qb64, sn=Number(numh=bup.sad['n']).num)
                assert custodian.root.hint(gid, regk, uuid, bup) == h.acdcs[regk]
                # One hint for every registry, the old newcomers bug, fails the self-check.
                wrong = next(said for key, said in h.acdcs.items() if key != regk)
                with pytest.raises(ValidationError, match='does not reproduce'):
                    custodian.root.prepare(custodian.member, other.member.pre, gid, regk, td=wrong)
                deliver(other, custodian.root.prepare(custodian.member, other.member.pre, gid, regk,
                                                      hinted=True))
            # Each copy verified by its own derived hint: retained on arrival, nothing pending.
            assert other.root.pending() == [] and other.root.held(other.hab.pre) == regks


def test_automatic_copy_without_local_hint_evidence_is_not_sent():
    with world() as w:
        seed(w)
        # Alice holds the root but no opening and no Grant for this registry.
        with pytest.raises(RootUnverified, match='no held opening or stored Grant'):
            w.alice.root.prepare(w.alice.hab, w.bob.hab.pre, w.gid, w.registry, hinted=True)
        # A manual send without a hint still seals an unverifiable copy, as before.
        pending = said(w.alice.root.prepare(w.alice.hab, w.bob.hab.pre, w.gid, w.registry))
        assert pending
        # An override that does not reproduce the commitment is never sealed.
        with pytest.raises(ValidationError, match='does not reproduce'):
            w.alice.root.prepare(w.alice.hab, w.bob.hab.pre, w.gid, w.registry,
                                 td=w.registry)


def replicated(monkeypatch, capsys, custodian, *, fail=None, **kwa):
    """Run the issuance-completion send; return its (wire, recipient) sends and printed results."""
    from keri.cli.common import rootreplicating

    sent = []

    def send(owner, raw, dest, *, topic):
        assert topic == 'credential' and owner.hab is custodian.hab
        if fail:
            raise fail
        sent.append((raw, dest))
        yield owner.tock

    monkeypatch.setattr(rootreplicating.sending, 'send', send)
    doer = SimpleNamespace(hby=custodian.hby, tyme=0.0, tock=0.0, extend=None, remove=None)
    list(rootreplicating.replicate(doer, custodian.hab, custodian.root,
                                   kwa.pop('registries'), timeout=10.0, **kwa))
    printed = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    return sent, printed


def test_issuance_completion_sends_every_root_to_every_other_member(monkeypatch, capsys):
    from tests.acdc.test_group_dh import receive as deliver

    with issued(count=2) as h:
        regks = sorted(h.acdcs)
        for members in (h.issuers, h.issuees):
            custodian, other = members[h.lead], members[h.lead + 1]
            sent, printed = replicated(monkeypatch, capsys, custodian, registries=regks)
            assert [dest for _, dest in sent] == [other.member.pre] * 2
            assert [(item['registry'], item['recipient'], item['transmitted']) for item in printed] == [
                (regk, other.member.pre, True) for regk in regks]
            # Duplicate copies, as several senders may produce, are harmless.
            for wire, _ in sent + sent:
                deliver(other, wire)
            assert other.root.pending() == [] and other.root.held(other.hab.pre) == regks


def test_failed_issuance_copy_is_reported_and_never_raises(monkeypatch, capsys):
    from keri.kering import ConfigurationError

    with issued(count=1) as h:
        custodian = h.issuers[h.lead]
        other = h.issuers[h.lead + 1]
        sent, printed = replicated(monkeypatch, capsys, custodian, registries=sorted(h.acdcs),
                                   fail=ConfigurationError('no finite recipient transport was available'))
        assert sent == []
        assert [(item['recipient'], item['transmitted'], item['recovery']) for item in printed] == [
            (other.member.pre, False, 'kli vc registry root send')]
        assert 'transport' in printed[0]['error']
        # A registry with no accepted BUP is reported, not sent, and does not stop the others.
        sent, printed = replicated(monkeypatch, capsys, custodian,
                                   registries=[h.registries[0].regk, h.grant.said])
        assert [(item['registry'], item['transmitted']) for item in printed] == [
            (h.registries[0].regk, True), (h.grant.said, False)]
        assert len(sent) == 1


def test_ipex_loader_registers_the_root_handler_once():
    with world() as w:
        hby, rgy = w.bob.hby, w.bob.rgy
        exc = Exchanger(hby=hby, handlers=[])
        ipexing.loadHandlers(hby, exc, w.bob.notifier, rgy=rgy)
        root = exc.routes[RegistryRoot.Route]
        assert isinstance(root, RegistryRoot)
        assert salting.loadHandlers(hby, exc, w.bob.notifier, rgy) is root
        # A caller's own instance is kept, not replaced or duplicated.
        mine = Exchanger(hby=hby, handlers=[w.bob.root])
        assert salting.loadHandlers(hby, mine, w.bob.notifier, rgy) is w.bob.root
        ipexing.loadHandlers(hby, mine, w.bob.notifier, rgy=rgy)
        assert mine.routes[RegistryRoot.Route] is w.bob.root
        # Verifiers opt out; without a Regery there is nothing to register.
        for kwa in (dict(rgy=rgy, roots=False), dict()):
            other = Exchanger(hby=hby, handlers=[])
            ipexing.loadHandlers(hby, other, w.bob.notifier, **kwa)
            assert RegistryRoot.Route not in other.routes and '/ipex/grant' in other.routes


def bare(side):
    """Deliver through an Exchanger that has IPEX handlers but no registry-root handler."""
    exc = Exchanger(hby=side.hby, handlers=[])
    ipexing.loadHandlers(side.hby, exc, side.notifier)
    return Parser(version=V2, kvy=side.kvy, rvy=side.hby.rvy, exc=exc, rgy=side.rgy)


@pytest.mark.parametrize('deferred', [False, True])
def test_copy_stored_without_the_handler_is_adopted_by_reconcile(deferred):
    with world(late=('bob',) if deferred else ()) as w:
        seed(w)
        wire = w.alice.root.prepare(w.alice.hab, w.bob.hab.pre, w.gid, w.registry,
                                    td=w.acdc.said)
        pending = said(wire)
        ims = bytearray(wire)
        bare(w.bob).parse(ims=ims, framed=False)
        db = w.bob.hby.db
        assert db.exns.get(keys=(pending,)) is not None and db.essrs.get(keys=(pending,))
        assert db.rrpe.get(keys=(pending,)) is None and held(w, w.bob) is None
        # A handler constructed over the same store adopts the copy.
        root = RegistryRoot(w.bob.hby, w.bob.rgy)
        if not deferred:
            assert held(w, w.bob).qb64 == w.root.qb64 and stored(w.bob) == []
            assert root.reconcile() == []
            return
        assert stored(w.bob) == [pending] and held(w, w.bob) is None
        assert root.reconcile() == []  # already escrowed: not adopted twice
        late(w)
        root.processEscrows()
        assert held(w, w.bob).qb64 == w.root.qb64 and stored(w.bob) == []


def test_reconcile_with_a_locked_keeper_leaves_the_copy_pending():
    with world() as w:
        seed(w)
        wire = w.alice.root.prepare(w.alice.hab, w.bob.hab.pre, w.gid, w.registry,
                                    td=w.acdc.said)
        bare(w.bob).parse(ims=bytearray(wire), framed=False)
        mgr = w.bob.hby.mgr
        decrypter, mgr.decrypter = mgr.decrypter, None
        try:
            assert w.bob.root.reconcile() == [said(wire)]
        finally:
            mgr.decrypter = decrypter
        assert stored(w.bob) == [said(wire)] and held(w, w.bob) is None
        w.bob.exc.processEscrow()
        assert held(w, w.bob).qb64 == w.root.qb64 and stored(w.bob) == []


def test_route_refuser_persists_nothing():
    with world() as w:
        seed(w)
        wire = w.alice.root.prepare(w.alice.hab, w.bob.hab.pre, w.gid, w.registry,
                                    td=w.acdc.said)
        pending = said(wire)
        exc = Exchanger(hby=w.bob.hby, handlers=[RouteRefuser(RegistryRoot.Route)])
        serder = Parser(version=V2).parseOne(ims=bytearray(wire), processive=False).serder
        Parser(version=V2, kvy=w.bob.kvy, rvy=w.bob.hby.rvy, exc=exc).parse(
            ims=bytearray(wire), framed=False)
        db = w.bob.hby.db
        assert serder.said == pending
        assert db.exns.get(keys=(pending,)) is None and not db.essrs.get(keys=(pending,))
        assert db.rrpe.get(keys=(pending,)) is None and held(w, w.bob) is None
