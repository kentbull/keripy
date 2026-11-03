"""Root copies cross real serialized replies, current KELs and encrypted Keepers."""

from contextlib import ExitStack, contextmanager
from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0 as V2
from keri.acdc import Regery, Registrar, acdcmap
from keri.acdc.salting import RegistrySalt
from keri.app import openCF, openHby
from keri.app.habbing import GroupHab, SignifyGroupHab, SignifyHab
from keri.core import (Blinder, Cipher, Codens, Counter, Encrypter, Kevery, Kramer, MtrDex, Parser,
                       Salter, SealSource, SerderKERI, Signer, messagize, reply)
from keri.kering import AuthError, Kinds, ValidationError


def receive(side, wire):
    ims = bytearray(wire)
    side.psr.parse(ims=ims, framed=False)
    assert not ims


def parsed(wire):
    return Parser(version=V2).parseOne(ims=bytearray(wire), processive=False)


@contextmanager
def world(*, group=False, enabled=False, bound=False, newcomer=False):
    with ExitStack() as stack:
        sides = []
        for n, name in enumerate(('issuer', 'alice', 'bob', 'outsider'), 1):
            signer = Signer(raw=bytes([n]) * 32, transferable=False)
            hby = stack.enter_context(openHby(name=f'salt-{name}', base='test', version=V2,
                salt=Salter(raw=bytes([n]) * 16).qb64,
                seed=signer.qb64, aeid=signer.verfer.qb64))
            hab = hby.makeHab(name=name)
            rgy = Regery(hby=hby, name=f'salt-{name}', temp=True)
            stack.callback(rgy.close)
            cf = stack.enter_context(openCF(name=f'salt-{name}', base='test'))
            cf.put(dict(kram=dict(enabled=enabled, denials=[],
                caches={'~': [1000, 5000, 60000, 300000, 5000, 60000, 300000]})))
            kvy = Kevery(db=hby.db, rvy=hby.rvy, kramer=Kramer(db=hby.db, cf=cf))
            sides.append(SimpleNamespace(hby=hby, hab=hab, rgy=rgy, kvy=kvy,
                psr=Parser(version=V2, kvy=kvy, rvy=hby.rvy, rgy=rgy)))
        issuer, alice, bob, outsider = sides
        for side in sides:
            for other in sides:
                if side is not other:
                    receive(side, other.hab.msgOwnEvent(sn=0, framed=False, gvrsn=V2))
        if group:
            mids = [alice.hab.pre, bob.hab.pre]
            wires = []
            for side in (alice, bob):
                side.group = side.hby.makeGroupHab(group='group', mhab=side.hab,
                    smids=mids, rmids=mids + [outsider.hab.pre] if newcomer else mids,
                    isith='2', nsith='1', version=V2)
                wires.append(side.group.msgOwnInception(allowPartiallySigned=True,
                                                       framed=False, gvrsn=V2))
            for side in sides:
                for wire in wires:
                    receive(side, wire)
                side.kvy.processEscrows()
                assert alice.group.pre in side.hby.kevers
        for side in sides:
            side.logical = getattr(side, 'group', side.hab)
            side.salt = RegistrySalt(side.logical, side.rgy)
            side.hby.rtr.addRoute(RegistrySalt.Route, side.salt, attachments=True)
        registrar = Registrar(issuer.rgy)
        registry = registrar.makeRegistry('existing', issuer.hab.pre)

        def transfer(event):
            kel = issuer.hab.interact(data=[dict(i=registry.regk, s=event.sad['n'], d=event.said)],
                                       framed=False, gvrsn=V2)
            assert registry.anchorMsg(event.said)
            anchor = SerderKERI(raw=kel)
            tel = messagize(event, bonds=[SealSource(s=anchor.snh, d=anchor.said)], gvrsn=V2)
            for side in sides[1:]:
                receive(side, kel)
                receive(side, tel)
                assert side.rgy.store.headEvent(registry.regk).said == event.said

        transfer(issuer.rgy.store.event(registry.regk))
        root = Salter(raw=b'public-test-root')
        issuer.hab.mgr.putRegistryRoot(issuer.hab.pre, registry.regk, root)
        acdc = acdcmap(israid=issuer.hab.pre, iseaid=alice.logical.pre,
                       regid=registry.regk, attribute=dict(d='', role='member'))
        kwa = dict(bound=True, bsn=alice.logical.kever.sn,
                   bd=alice.logical.kever.serder.said) if bound else {}
        opening, event = registrar.issue(registry, acdc, salt=root.qb64, state='issued', **kwa)
        transfer(event)
        yield SimpleNamespace(sides=sides, issuer=issuer, alice=alice, bob=bob, outsider=outsider,
                              registry=registry.regk, root=root, opening=opening, event=event)


def approve(w, side, sender=None):
    side.salt.approve(w.registry, sender or w.issuer.hab.pre,
                      event=w.event.said, opening=w.opening)


def retained(w, side):
    return side.logical.mgr.getRegistryRoot(side.logical.pre, w.registry)


@pytest.mark.parametrize('enabled', [False, True])
@pytest.mark.parametrize('bound', [False, True])
def test_individual_copy_rechecks_exact_accepted_opening(enabled, bound):
    with world(enabled=enabled, bound=bound) as w:
        approve(w, w.alice)
        wire = w.issuer.salt.prepare(w.registry, w.alice.hab.pre, w.alice.hab.pre)
        data = parsed(wire).serder.sad['a']
        assert set(data) == {'registry', 'recipient', 'target', 'cipher'}
        assert Cipher(qb64=data['cipher']).code == MtrDex.X25519_Cipher_Salt
        assert w.root.qb64b not in wire
        receive(w.alice, wire)
        assert retained(w, w.alice).qb64 == w.root.qb64
        receive(w.alice, wire)
        assert retained(w, w.alice).qb64 == w.root.qb64
        cipher = w.alice.hab.mgr.ks.rroots.get((w.alice.hab.pre, w.registry))
        assert cipher.qb64 != w.root.qb64
        assert w.alice.rgy.store.opening(w.event.said) is None
        assert w.root.qb64b not in w.alice.rgy.store.cloneTel(w.registry)


@pytest.mark.parametrize('fault', ['unapproved', 'abandoned', 'restart', 'wrong-root',
    'wrong-recipient', 'wrong-target', 'wrong-sender', 'missing-signature',
    'forged-signature', 'extra-proof', 'cipher-suffix', 'plaintext'])
def test_refused_transfer_never_populates_keeper(fault):
    with world() as w:
        if fault != 'unapproved':
            approve(w, w.alice)
        if fault == 'abandoned':
            w.alice.salt.abandon(w.registry, w.issuer.hab.pre)
        if fault == 'restart':
            replacement = RegistrySalt(w.alice.hab, w.alice.rgy)
            for route in w.alice.hby.rtr.routes:
                if route.resource is w.alice.salt:
                    route.resource = replacement
        wire = w.issuer.salt.prepare(w.registry, w.alice.hab.pre, w.alice.hab.pre)
        message = parsed(wire).serder
        data = dict(message.sad['a'])
        signer = w.issuer.hab
        if fault == 'wrong-root':
            data['cipher'] = Encrypter(verkey=w.alice.hab.kever.verfers[0].qb64).encrypt(
                prim=Salter(raw=b'wrong-test-root!')).qb64
        elif fault in ('wrong-recipient', 'wrong-target'):
            data[fault.removeprefix('wrong-')] = w.bob.hab.pre
        elif fault == 'wrong-sender':
            signer = w.outsider.hab
        elif fault == 'cipher-suffix':
            data['cipher'] += 'AAAA'
        elif fault == 'plaintext':
            data['cipher'] = w.root.qb64
        message = reply(pre=signer.pre, route=RegistrySalt.Route, data=data,
                        pvrsn=V2, kind=Kinds.json)
        wire = signer.endorse(message, gvrsn=V2)
        if fault == 'missing-signature':
            wire = message.raw + Counter.enclose(qb64=b'', code=Codens.AttachmentGroup, version=V2)
        elif fault == 'forged-signature':
            group = parsed(wire).tsgs[0]
            wire = messagize(message, tsgs=[(*group[:3], w.outsider.hab.sign(message.raw))], gvrsn=V2)
        elif fault == 'extra-proof':
            dom = parsed(wire)
            wire = messagize(message, tsgs=dom.tsgs, bonds=[w.opening.data], gvrsn=V2)
        receive(w.alice, wire)
        assert retained(w, w.alice) is None


def test_rootless_sender_and_wrong_local_evidence_refuse():
    with world() as w:
        with pytest.raises(ValidationError, match='only the issuer'):
            w.bob.salt.prepare(w.registry, w.alice.hab.pre, w.alice.hab.pre)
        with pytest.raises(ValidationError):
            w.alice.salt.approve(w.registry, w.issuer.hab.pre,
                                 event=w.registry, opening=w.opening)
        with pytest.raises(ValidationError):
            w.alice.salt.approve(w.registry, w.issuer.hab.pre,
                event=w.event.said, opening=Blinder.blind(acdc=w.opening.acdc, state='issued'))
        w.issuer.hab.mgr.ks.rroots.rem((w.issuer.hab.pre, w.registry))
        with pytest.raises(ValidationError, match='unavailable'):
            w.issuer.salt.prepare(w.registry, w.alice.hab.pre, w.alice.hab.pre)


@pytest.mark.parametrize('who', ['author', 'target'])
def test_rotation_refuses_old_author_or_old_encryption_key(who):
    with world() as w:
        approve(w, w.alice)
        old = w.issuer.salt.prepare(w.registry, w.alice.hab.pre, w.alice.hab.pre)
        side = w.issuer if who == 'author' else w.alice
        kel = side.hab.rotate(framed=False, gvrsn=V2)
        for other in w.sides:
            if other is not side:
                receive(other, kel)
        receive(w.alice, old)
        assert retained(w, w.alice) is None
        fresh = w.issuer.salt.prepare(w.registry, w.alice.hab.pre, w.alice.hab.pre)
        receive(w.alice, fresh)
        assert retained(w, w.alice).qb64 == w.root.qb64


@pytest.mark.parametrize('enabled', [False, True])
def test_group_copy_uses_real_threshold_and_current_contributed_membership(enabled):
    with world(group=True, enabled=enabled) as w:
        approve(w, w.alice)
        receive(w.alice, w.issuer.salt.prepare(w.registry, w.alice.group.pre, w.alice.hab.pre))
        assert retained(w, w.alice).qb64 == w.root.qb64
        coordinator = (0, w.alice.group.pre)
        with pytest.raises(ValidationError, match='coordinator'):
            w.bob.salt.prepare(w.registry, w.bob.group.pre, w.bob.hab.pre, coordinator=coordinator)
        with pytest.raises(ValidationError, match='signing member'):
            w.alice.salt.prepare(w.registry, w.alice.group.pre, w.outsider.hab.pre,
                                 coordinator=coordinator)
        approve(w, w.bob, w.alice.group.pre)
        first = w.alice.salt.prepare(w.registry, w.alice.group.pre, w.bob.hab.pre,
                                     coordinator=coordinator)
        receive(w.bob, first)
        assert retained(w, w.bob) is None
        receive(w.bob, first)  # Duplicate index cannot satisfy the second member.
        assert retained(w, w.bob) is None
        message = parsed(first).serder
        second = w.bob.group.endorse(message, gvrsn=V2)
        receive(w.bob, second)
        assert retained(w, w.bob).qb64 == w.root.qb64


def test_rotated_member_is_provisionable_but_removed_member_is_not():
    with world(group=True) as w:
        kel = w.bob.hab.rotate(framed=False, gvrsn=V2)
        for side in (w.issuer, w.alice, w.outsider):
            receive(side, kel)
        approve(w, w.bob)
        wire = w.issuer.salt.prepare(w.registry, w.bob.group.pre, w.bob.hab.pre)
        receive(w.bob, wire)
        assert retained(w, w.bob).qb64 == w.root.qb64
        # Group rotation drops Bob; his historical contribution no longer
        # matches any key in the current group's accepted establishment.
        kel = w.alice.hab.rotate(framed=False, gvrsn=V2)
        for side in (w.issuer, w.bob, w.outsider):
            receive(side, kel)
        kel = w.alice.group.rotate(smids=[w.alice.hab.pre], rmids=[w.alice.hab.pre],
            verfers=w.alice.hab.kever.verfers, digers=w.alice.hab.kever.ndigers,
            isith='1', nsith='1', framed=False, gvrsn=V2)
        for side in (w.issuer, w.bob, w.outsider):
            # Existing group KEL policy requires local approval when an update
            # lacks this process's own contribution, including its removal.
            side.psr.parse(ims=bytearray(kel), framed=False, local=True)
            assert side.hby.kevers[w.alice.group.pre].serder.said == parsed(kel).serder.said
        with pytest.raises(ValidationError, match='signing member'):
            w.issuer.salt.prepare(w.registry, w.bob.group.pre, w.bob.hab.pre)
        dom = parsed(wire)
        with pytest.raises(ValidationError, match='signing member'):
            w.bob.hby.rvy.processReply(dom.serder, tsgs=dom.tsgs)


def test_existing_root_is_never_replaced_by_an_authorized_copy():
    with world() as w:
        other = Salter(raw=b'wrong-test-root!')
        w.alice.hab.mgr.putRegistryRoot(w.alice.hab.pre, w.registry, other)
        approve(w, w.alice)
        receive(w.alice, w.issuer.salt.prepare(w.registry, w.alice.hab.pre, w.alice.hab.pre))
        assert retained(w, w.alice).qb64 == other.qb64


def test_remote_signer_habitats_are_explicitly_unsupported():
    with world() as w:
        hby = w.alice.hby
        kwa = dict(ks=hby.ks, db=hby.db, cf=hby.cf, mgr=hby.mgr, rtr=hby.rtr,
                   rvy=hby.rvy, kvy=hby.kvy, psr=hby.psr, name='remote', temp=True)
        remote = SignifyHab(**kwa)
        actors = (remote, SignifyGroupHab(mhab=remote, smids=[w.alice.hab.pre], **kwa),
                  GroupHab(mhab=remote, smids=[w.alice.hab.pre], **kwa))
        for actor in actors:
            with pytest.raises(AuthError, match='local signing and decryption'):
                RegistrySalt(actor, w.alice.rgy)


def test_new_signing_member_receives_group_copy_after_real_rotation():
    with world(group=True, newcomer=True) as w:
        approve(w, w.alice)
        receive(w.alice, w.issuer.salt.prepare(w.registry, w.alice.group.pre, w.alice.hab.pre))
        with pytest.raises(ValidationError, match='signing member'):
            w.issuer.salt.prepare(w.registry, w.alice.group.pre, w.outsider.hab.pre)
        # Being a next-key/rotation participant is not current signing membership.
        for member in (w.alice, w.bob, w.outsider):
            kel = member.hab.rotate(framed=False, gvrsn=V2)
            for side in w.sides:
                if side is not member:
                    receive(side, kel)
        current = [w.alice, w.bob, w.outsider]
        rotation = w.alice.group.rotate(
            verfers=[side.hab.kever.verfers[0] for side in current],
            digers=[side.hab.kever.ndigers[0] for side in current],
            isith='2', nsith='2', framed=False, gvrsn=V2)
        event = parsed(rotation).serder
        partial = w.bob.group.rotate(serder=event,
            smids=[side.hab.pre for side in current], rmids=[side.hab.pre for side in current],
            framed=False, gvrsn=V2)
        for side in w.sides:
            receive(side, rotation)
            receive(side, partial)
            side.kvy.processEscrows()
            assert side.hby.kevers[w.alice.group.pre].serder.said == event.said
        new = w.outsider
        new.group = new.hby.joinGroupHab(pre=w.alice.group.pre, group='joined', mhab=new.hab,
            smids=[side.hab.pre for side in current], rmids=[side.hab.pre for side in current])
        oldroute = new.salt
        new.logical = new.group
        new.salt = RegistrySalt(new.group, new.rgy)
        for route in new.hby.rtr.routes:
            if route.resource is oldroute:
                route.resource = new.salt
        approve(w, new, w.alice.group.pre)
        # Keep the original coordinating event; later signing indices do not elect anew.
        wire = w.alice.salt.prepare(w.registry, new.group.pre, new.hab.pre,
                                    coordinator=(0, w.alice.group.pre))
        receive(new, wire)
        assert retained(w, new) is None
        receive(new, w.bob.group.endorse(parsed(wire).serder, gvrsn=V2))
        assert retained(w, new).qb64 == w.root.qb64
