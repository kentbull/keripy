"""Native registry notification approval through the normal multisig join UI."""
from contextlib import contextmanager
from functools import partial
from importlib import import_module

import pytest
from hio.base import doing, tyming

from keri import Vrsn_1_0, Vrsn_2_0
from keri.acdc.messaging import blindate, regcept
from keri.app import Notifier
from keri.app.grouping import multisigBupExn
from keri.app.acdc_v2_grouping import RegistryApproval
from keri.core import Blinder, Codens, Counter, Diger, Parser, SerderKERI, exchange
from keri.kering import Kinds, MissingRegistryError, ValidationError
from tests.app.test_acdc_v2_groups import members, groupMembers, groupNetwork

from keri.peer.exchanging import serializeParsedSubstream

join = import_module("keri.cli.commands.multisig.join")


@contextmanager
def joining(members, *, auto=True):
    """Borrow one real peer's processors to exercise join without another runtime."""
    hbys, _, rgys, owners = members
    peer = owners[1]
    command = join.JoinDoer.__new__(join.JoinDoer)
    doing.DoDoer.__init__(command, doers=[])
    command.hby, command.rgyV2 = hbys[1], rgys[1]
    command.exc, command.mux = peer.exc, peer.mux
    command.psr, command.counselor = peer.parser, peer.counselor
    command.auto, command.timeout, command.toRemove = auto, 2.0, []
    command.notifier = Notifier(hby=hbys[1])
    peer.mux.notifier = command.notifier
    clock = tyming.Tymist(tock=0.01)
    command.wind(clock.tymen())
    try:
        yield command, clock
    finally:
        # Borrowed stores remain caller-owned. Removing temporary I/O children
        # must not close the native registry store as a side effect.
        command.remove(list(command.doers))
        command.notifier.noter.close(clear=True)


def drive(command, clock, operation, until):
    """Drive finite join work alongside the existing real HTTP group network."""
    finished, result = False, None

    def step():
        nonlocal finished, result
        if not finished:
            try:
                next(operation)
            except StopIteration as stop:
                finished, result = True, stop.value
            clock.tick()
            command.recur(clock.tyme)
        return finished

    until(step)
    return result


@pytest.mark.parametrize('public', [False, True])
def test_join_native_notifications_approve_exact_tel_and_fanout(members, unused_tcp_port_factory, public):
    """Approve notified rip/bup bodies with real quorum, HTTP fanout, and no custody."""
    hbys, groups, rgys, owners = members
    with joining(members) as (command, clock), groupNetwork(members, unused_tcp_port_factory) as (until, _):
        rip = regcept(groups[0].pre)
        proposed, atc = owners[0].approveRegistry(rip)
        owners[1].receive(proposed.raw + atc)
        assert command.notifier.noter.notes.cnt() == 1
        drive(command, clock, command.joinDo(clock.tymen()), until)
        assert command.notifier.noter.notes.cnt() == 0
        assert rgys[0].store.headEvent(rip.said).said == rip.said
        assert rgys[1].store.headEvent(rip.said).said == rip.said
        assert rgys[2].store.headEvent(rip.said) is None

        opening = Blinder.blind(sn=1, acdc=Diger(ser=b'credential').qb64, state='issued')
        bup = blindate(rip.said, rip.said, opening.said)
        proposed, atc = owners[0].approveRegistry(bup, opening=opening if public else None)
        owners[1].receive(proposed.raw + atc)
        drive(command, clock, command.joinDo(clock.tymen()), until)
        assert command.notifier.noter.notes.cnt() == 0
        assert all(rgy.store.headEvent(rip.said).said == bup.said for rgy in rgys[:2])
        assert rgys[2].store.headEvent(rip.said) is None
        local = [said.qb64 for said in hbys[1].db.meids.get((groups[1].kever.serder.said,))
                 if hbys[1].db.exns.get((said.qb64,)).pre == groups[1].mhab.pre]
        assert len(local) == 1
        retained = Parser(version=Vrsn_2_0).parse(
            ims=bytearray(join.serializeMessage(hbys[1], local[0])), processive=False)[0]
        assert retained.nests[0].serder.raw == bup.raw
        assert bool(retained.nests[0].bsqs + retained.nests[0].bsss) is public
        assert not command.doers and rgys[1].store.opened


def test_join_decline_adds_no_group_signature(members, monkeypatch):
    """Inspection and human decline leave the exact proposal unapproved locally."""
    hbys, groups, rgys, owners = members
    with joining(members, auto=False) as (command, _):
        rip = regcept(groups[0].pre)
        proposed, atc = owners[0].approveRegistry(rip)
        owners[1].receive(proposed.raw + atc)
        event, anchor, _ = owners[1].registryProposal(proposed.raw + atc)
        monkeypatch.setattr('builtins.input', lambda _: 'n')
        operation = command.registry(dict(r=proposed.route, d=proposed.said))
        with pytest.raises(StopIteration) as stop:
            next(operation)
        assert stop.value.value is False
        assert [member.qb64 for member in hbys[1].db.maids.get((anchor.said,))] == [groups[0].mhab.pre]
        assert rgys[1].store.headEvent(event.said) is None
        assert not command.doers


def test_registry_approval_requires_accepted_matching_inception(members):
    """Unknown or foreign registry control cannot obtain a local group signature."""
    hbys, groups, rgys, owners = members
    unknown = regcept(groups[0].pre)
    event = blindate(unknown.said, unknown.said, Diger(ser=b'blinded').qb64)
    with pytest.raises(MissingRegistryError):
        owners[1].approveRegistry(event)
    assert hbys[1].db.pses.getLast(keys=groups[1].pre, on=1) is None

    # Supply real accepted foreign-controller KEL/TEL evidence, then ask this
    # group to anchor an update to it. Possessing that evidence grants no control.
    with groupMembers('join-foreign') as (_, foreignGroups, _, foreignOwners):
        rip = regcept(foreignGroups[0].pre)
        first, atc = foreignOwners[0].approveRegistry(rip)
        tel, anchor, _ = foreignOwners[1].registryProposal(first.raw + atc)
        foreignOwners[1].approveRegistry(tel, anchor)
        owners[1].receive(foreignGroups[1].replay(gvrsn=Vrsn_2_0))
        owners[1].rever.processEvent(rip)
        assert rgys[1].store.seqEvent(rip.said, 0).said == rip.said
        event = blindate(rip.said, rip.said, Diger(ser=b'blinded').qb64)
        with pytest.raises(ValidationError, match='different group'):
            owners[1].approveRegistry(event)
        assert hbys[1].db.pses.getLast(keys=groups[1].pre, on=1) is None


def test_join_missing_inception_retains_notification_without_prompt(members, monkeypatch):
    """A valid signed bup proposal stays pending until its accepted rip is known."""
    hbys, groups, _, owners = members
    with joining(members) as (command, clock):
        rip = regcept(groups[0].pre)
        bup = blindate(rip.said, rip.said, Diger(ser=b'private commitment').qb64)
        anchor = groups[0].interact(data=[dict(s='1', d=bup.said)],
            version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        footer = Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b
        proposed, atc = multisigBupExn(groups[0], bup.raw + footer, anchor)
        owners[1].receive(proposed.raw + atc)
        monkeypatch.setattr('builtins.input', lambda _: pytest.fail('pending evidence must not prompt'))
        list(command.joinDo(clock.tymen()))
        assert command.notifier.noter.notes.cnt() == 1
        assert hbys[1].db.pses.getLast(keys=groups[1].pre, on=1) is None
        assert [member.qb64 for member in hbys[1].db.maids.get(
            (SerderKERI(raw=anchor).said,))] == [groups[0].mhab.pre]


def test_join_cancellation_closes_temporary_delivery_children(members, monkeypatch):
    """Cancellation releases finite transport work without closing borrowed TEL state."""
    _, groups, rgys, owners = members
    deliveries = []

    class PendingDelivery(doing.Doer):
        closed = False

        def exit(self):
            self.closed = True

    class PendingPoster:
        def __init__(self, **kwa):
            self.delivery = PendingDelivery()
            deliveries.append(self.delivery)

        def send(self, *args, **kwa):
            pass

        def deliver(self):
            return [self.delivery]

    monkeypatch.setattr(join, 'StreamPoster', PendingPoster)
    with joining(members) as (command, _):
        rip = regcept(groups[0].pre)
        proposed, atc = owners[0].approveRegistry(rip)
        owners[1].receive(proposed.raw + atc)
        operation = command.registry(dict(r=proposed.route, d=proposed.said))
        next(operation)
        assert len(command.doers) == len(deliveries) == 2
        operation.close()
        assert all(delivery.closed for delivery in deliveries)
        assert not command.doers and rgys[1].store.opened


@pytest.mark.parametrize('version', [Vrsn_1_0, Vrsn_2_0])
def test_join_owns_native_store_only_for_v2_and_closes_it(members, monkeypatch, version):
    """Keep legacy join composition and close native storage only on owner exit."""
    hbys, groups, _, owners = members
    monkeypatch.setattr(join, 'setupHby', lambda **_: hbys[1])
    monkeypatch.setattr(join, 'Regery', partial(join.Regery, temp=True))
    monkeypatch.setattr(join, 'NativeRegery', partial(join.NativeRegery, temp=True))
    command = join.JoinDoer(name=hbys[1].name, base='', bran=None, group='group', version=version)
    try:
        assert (command.rgyV2 is not None) is (version == Vrsn_2_0)
        assert command.psr.tvy is command.rgy.tvy
        command.remove([])
        if command.rgyV2 is not None:
            assert command.mux.exc is command.exc
            assert command.rgyV2.store.opened
            assert command.psr.rgy is command.mbx.parser.rgy is command.mux.rgy
            assert command.psr.kvy is command.mbx.kvy is command.mux.kvy
            assert command.psr.rvy is command.mbx.rvy is command.mux.rvy
            assert command.psr.kvy.kramer is command.hby.kvy.kramer is command.pruner.kramer
            assert command.pruner in command.doers and command.pruner in command.toRemove
            clock = tyming.Tymist()
            command.wind(clock.tymen())
            command.deeds.extend(command.enter(doers=[command.pruner]))
            assert any(deed[2] is command.pruner for deed in command.deeds)
            command.remove([command.pruner])
            assert not any(deed[2] is command.pruner for deed in command.deeds)
            assert command.rgyV2.store.opened

            proposed, atc = owners[0].approveRegistry(regcept(groups[0].pre))
            parsed = Parser(version=Vrsn_2_0).parse(
                ims=bytearray(proposed.raw + atc), processive=False)[0]
            stale = exchange(sender=proposed.pre, route=proposed.route,
                attributes=proposed.sad['a'], stamp='2021-01-01T00:00:00.000000+00:00',
                version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)
            message = groups[0].mhab.endorse(stale, last=False, framed=False,
                gvrsn=Vrsn_2_0, nests=[serializeParsedSubstream(child) for child in parsed.nests])
            command.psr.parse(ims=bytearray(message), local=True)
            assert hbys[1].db.exns.get((stale.said,)) is None
            assert command.notifier.noter.notes.cnt() == 0
            approval = RegistryApproval(command.hby, command.rgyV2, groups[1],
                command.exc, command.mux, command.psr, command.counselor)
            event, anchor, _ = approval.proposal(proposed.raw + atc)
            approval.approve(event, anchor)
            assert command.rgyV2.store.headEvent(event.said).said == event.said
        else:
            assert command.pruner is None
            assert command.psr.kvy is command.hby.kvy
            assert command.mux.exc is not command.exc
        command.exit()
        if command.rgyV2 is not None:
            assert not command.rgyV2.store.opened
    finally:
        command.rgy.close()
        command.notifier.noter.close(clear=True)
