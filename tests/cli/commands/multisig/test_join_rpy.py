"""Native endpoint reply approval reuses retained children and group consent."""

from importlib import import_module
from types import SimpleNamespace

import pytest
from hio.base import doing

from keri import Vrsn_1_0, Vrsn_2_0
from keri.app import Notifier, Organizer
from keri.app.grouping import Multiplexor, loadHandlers, multisigRpyExn
from keri.core import Parser, Revery, reply, messagize
from keri.kering import Kinds, ValidationError
from keri.peer import Exchanger
from keri.peer.exchanging import loadParsedNestedSubstreams
from tests.app.test_acdc_v2_groups import members, groupNetwork
from tests.app.test_grouping import openMultiSig
from tests.cli.commands.multisig.test_join_v2 import joining, drive


join = import_module('keri.cli.commands.multisig.join')


def proposal(members, *, route='/end/role/add', data=None):
    """Retain one real member's exact group reply proposal on two peers."""
    _, groups, _, owners = members
    if data is None:
        data = dict(cid=groups[0].pre, role='agent', eid=groups[0].mhab.pre)
    body = reply(pre=groups[0].pre, route=route, data=data,
                 version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)
    wrapper, atc = multisigRpyExn(groups[0], groups[0].endorse(body, gvrsn=Vrsn_2_0))
    for owner in owners[:2]:
        owner.receive(wrapper.raw + atc)
    return body, wrapper


def configure(command):
    """Borrow the peer's installed reply processor and real organizer."""
    command.rvy = command.mux.rvy
    command.org = Organizer(hby=command.hby)


def test_join_v2_endpoint_reply_exact_quorum_and_http_fanout(members, unused_tcp_port_factory):
    """Approve exact native endpoint bytes, reach quorum, and fan out over real HTTP."""
    hbys, groups, _, _ = members
    with joining(members) as (command, clock), groupNetwork(members, unused_tcp_port_factory) as (until, _):
        configure(command)
        body, wrapper = proposal(members)
        assert not groups[1].loadEndRole(cid=groups[1].pre, role='agent', eid=groups[0].mhab.pre)
        result = drive(command, clock, command.rpy(dict(r=wrapper.route, d=wrapper.said)), until)
        assert result is True
        assert hbys[1].db.eans.get((groups[1].pre, 'agent', groups[0].mhab.pre)).qb64 == body.said
        assert groups[0].loadEndRole(cid=groups[0].pre, role='agent', eid=groups[0].mhab.pre)
        assert not groups[2].loadEndRole(cid=groups[2].pre, role='agent', eid=groups[0].mhab.pre)
        approved = [hbys[1].db.exns.get((said.qb64,)) for said in hbys[1].db.meids.get((body.said,))
                    if hbys[1].db.exns.get((said.qb64,)).pre == groups[1].mhab.pre]
        assert len(approved) == 1 and approved[0].pvrsn == Vrsn_2_0
        assert loadParsedNestedSubstreams(hbys[1], approved[0].said)[0].serder.raw == body.raw
        assert not command.doers


def test_join_v2_decline_adds_no_approval_or_group_signature(members, monkeypatch):
    """Human refusal preserves the retained proposal without adding local consent."""
    hbys, groups, _, _ = members
    with joining(members, auto=False) as (command, _):
        configure(command)
        body, wrapper = proposal(members)
        monkeypatch.setattr('builtins.input', lambda _: 'n')
        operation = command.rpy(dict(r=wrapper.route, d=wrapper.said))
        with pytest.raises(StopIteration) as stopped:
            next(operation)
        assert stopped.value.value is False
        assert [member.qb64 for member in hbys[1].db.maids.get((body.said,))] == [groups[0].mhab.pre]
        assert hbys[1].db.eans.get((groups[1].pre, 'agent', groups[0].mhab.pre)) is None


def test_join_group_rotation_during_prompt_prevents_stale_approval(members, monkeypatch):
    """Accepting a new real group establishment during review cannot select new signers silently."""
    from tests.app.test_acdc_v2_groups import memberAids, rotateMembers, groupRotation

    hbys, groups, _, _ = members
    with joining(members, auto=False) as (command, _):
        configure(command)
        body, wrapper = proposal(members)

        def rotateDuringPrompt(_):
            """Accept a real two-member group rotation before returning human approval."""
            smids = memberAids(groups)
            rotateMembers(hbys, groups)
            rotation = groupRotation(hbys[1], groups[1], smids)
            messages = [group.rotate(smids=smids, rmids=smids,
                serder=rotation, gvrsn=Vrsn_2_0) for group in groups[:2]]
            for message in messages:
                command.psr.parse(ims=bytearray(message), local=True)
            command.mux.kvy.processEscrows()
            assert groups[1].kever.lastEst.s == 1
            return 'y'

        monkeypatch.setattr('builtins.input', rotateDuringPrompt)
        with pytest.raises(ValidationError, match='establishment changed during reply approval'):
            next(command.rpy(dict(r=wrapper.route, d=wrapper.said)))
        assert [member.qb64 for member in hbys[1].db.maids.get((body.said,))] == [groups[0].mhab.pre]


def test_join_uninstalled_domain_retains_notice_without_prompt(members, monkeypatch):
    """A salt domain with no installed approval policy cannot obtain CLI consent."""
    hbys, groups, _, _ = members
    with joining(members, auto=False) as (command, clock):
        configure(command)
        body, _ = proposal(members, route='/keri-rnd/registry-salt/1/init', data={})
        monkeypatch.setattr('builtins.input', lambda _: pytest.fail('unsupported domain must not prompt'))
        list(command.joinDo(clock.tymen()))
        assert command.notifier.noter.notes.cnt() == 1
        assert [member.qb64 for member in hbys[1].db.maids.get((body.said,))] == [groups[0].mhab.pre]


@pytest.mark.parametrize('field,value', [('cid', 'bad-controller'), ('eid', 'bad-endpoint'), ('role', 'invented-role')])
def test_join_endpoint_policy_precedes_prompt(members, monkeypatch, field, value):
    """Wrapper authentication cannot make invalid endpoint semantics approvable."""
    hbys, groups, _, _ = members
    data = dict(cid=groups[0].pre, role='agent', eid=groups[0].mhab.pre)
    data[field] = value
    with joining(members, auto=False) as (command, _):
        configure(command)
        body, wrapper = proposal(members, data=data)
        monkeypatch.setattr('builtins.input', lambda _: pytest.fail('invalid domain must not prompt'))
        with pytest.raises(ValidationError):
            next(command.rpy(dict(r=wrapper.route, d=wrapper.said)))
        assert [member.qb64 for member in hbys[1].db.maids.get((body.said,))] == [groups[0].mhab.pre]


def test_join_v2_endpoint_cancellation_releases_delivery_children(members, monkeypatch):
    """Cancelling finite fanout closes owned children and preserves borrowed stores."""
    pending = []

    class Delivery(doing.Doer):
        """Retain a pending transport child until the owner cancels it."""
        closed = False

        def exit(self):
            """Record that the join owner released this child."""
            self.closed = True

    class Poster:
        """Expose one pending finite delivery without real network I/O."""

        def __init__(self, **kwa):
            """Create one caller-observable transport child."""
            self.child = Delivery()
            pending.append(self.child)

        def send(self, *args, **kwa):
            """Accept the already constructed wrapper for this cleanup test."""

        def deliver(self):
            """Return the finite child whose lifecycle belongs to join."""
            return [self.child]

    monkeypatch.setattr(join, 'StreamPoster', Poster)
    with joining(members) as (command, _):
        configure(command)
        _, wrapper = proposal(members)
        operation = command.rpy(dict(r=wrapper.route, d=wrapper.said))
        next(operation)
        assert len(pending) == len(command.doers) == 2
        operation.close()
        assert all(child.closed for child in pending) and not command.doers


def test_join_legacy_endpoint_reply_keeps_v1_wrapper():
    """The existing legacy endpoint branch still accepts quorum and emits v1 wrappers."""
    with openMultiSig(prefix='legacy-endpoint-join') as ((hby, group), (_, other), (_, third)):
        notifier = Notifier(hby=hby)
        try:
            exc = Exchanger(hby=hby, handlers=[])
            mux = Multiplexor(hby=hby, notifier=notifier, exc=exc)
            loadHandlers(exc, mux)
            rvy = Revery(db=hby.db, lax=True)
            hby.kvy.registerReplyRoutes(rvy.rtr)
            parser = Parser(kvy=mux.kvy, rvy=rvy, exc=exc, version=Vrsn_1_0)
            body = reply(route='/end/role/add',
                data=dict(cid=group.pre, role='agent', eid=other.mhab.pre),
                version=Vrsn_1_0, kind=Kinds.json)
            signed = Parser(version=Vrsn_1_0).parse(ims=bytearray(
                other.endorse(body, gvrsn=Vrsn_1_0, framed=True)), processive=False)[0]
            signed.tsgs[0][3].extend(third.sign(body.raw))
            wrapper, atc = multisigRpyExn(other, messagize(body, tsgs=signed.tsgs,
                gvrsn=Vrsn_1_0, framed=True), version=Vrsn_1_0)
            parser.parse(ims=bytearray(wrapper.raw + atc), local=True)
            command = join.JoinDoer.__new__(join.JoinDoer)
            doing.DoDoer.__init__(command, doers=[])
            command.hby, command.auto, command.psr, command.rvy = hby, True, parser, rvy
            command.org = Organizer(hby=hby)
            command.org.update(other.mhab.pre, dict(alias='other-member'))
            command.rgy = SimpleNamespace(processEscrows=lambda: None)
            sent = []
            command.postman = SimpleNamespace(send=lambda **kwa: sent.append(kwa))
            operation = command.rpy(dict(r=wrapper.route, d=wrapper.said))
            with pytest.raises(StopIteration) as stopped:
                next(operation)
            assert stopped.value.value is True
            assert sent and all(item['serder'].pvrsn == Vrsn_1_0 for item in sent)
            assert group.loadEndRole(cid=group.pre, role='agent', eid=other.mhab.pre)
        finally:
            notifier.noter.close(clear=True)
