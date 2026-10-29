"""Existing group join approves encrypted replies without acquiring recipient custody."""
import pytest

from keri import Vrsn_2_0
from keri.app.grouping import multisigRpyExn
from keri.kering import ValidationError
from tests.app.test_acdc_v2_groups import groupNetwork
from tests.app.test_registry_salt_direct import groupServiceNetwork
from tests.cli.commands.multisig.test_join_v2 import joining, drive


def proposal(case):
    """Retain one member's real encrypted reply proposal on the first two peers."""
    leader = case.services[0]
    leader.custody.createCustody(case.rip.said, case.discloser.pre)
    body = leader.makeReply(case.groups[0], case.rip.said, case.discloser.pre)
    signed = case.groups[0].endorse(body, gvrsn=Vrsn_2_0)
    case.owners[0].parser.parse(ims=bytearray(signed), local=True)
    wrapper, atc = multisigRpyExn(case.groups[0], signed)
    for owner in case.owners[:2]:
        owner.receive(wrapper.raw + atc)
    return body, wrapper


def test_join_salt_reply_uses_existing_quorum(groupServiceNetwork, unused_tcp_port_factory):
    """A second member approves exact reply bytes and returns its signature over HTTP."""
    case = groupServiceNetwork
    leader, cosigner = case.services[:2]
    with joining(case.members) as (command, clock), \
         groupNetwork(case.members, unused_tcp_port_factory) as (until, _):
        command.rvy, command.saltService = cosigner.rvy, cosigner
        command.group = case.groups[1].name
        body, wrapper = proposal(case)
        assert cosigner.hby.db.rpys.get((body.said,)) is None
        result = drive(command, clock, command.rpy(dict(r=wrapper.route, d=wrapper.said)), until)
        assert result is True
        leader.rvy.processEscrowReply()
        cosigner.rvy.processEscrowReply()
        assert leader.hby.db.rpys.get((body.said,)).raw == body.raw
        assert cosigner.hby.db.rpys.get((body.said,)).raw == body.raw
        assert cosigner.custody.db.custody.get((case.rip.said,)) is None
        assert case.services[3].custody.db.custody.get((case.rip.said,)) is None
        assert not command.doers


def test_join_salt_decline_never_adds_signature_or_custody(groupServiceNetwork, monkeypatch):
    """Inspection and refusal retain the proposal without recording member consent."""
    case = groupServiceNetwork
    cosigner = case.services[1]
    with joining(case.members, auto=False) as (command, _):
        command.rvy, command.saltService = cosigner.rvy, cosigner
        command.group = case.groups[1].name
        body, wrapper = proposal(case)
        monkeypatch.setattr('builtins.input', lambda _: 'n')
        with pytest.raises(StopIteration) as stopped:
            next(command.rpy(dict(r=wrapper.route, d=wrapper.said)))
        assert stopped.value.value is False
        assert [member.qb64 for member in cosigner.hby.db.maids.get((body.said,))] == [case.groups[0].mhab.pre]
        assert cosigner.hby.db.rpys.get((body.said,)) is None
        assert cosigner.custody.db.custody.get((case.rip.said,)) is None


def test_join_salt_missing_registry_rejects_before_prompt(groupServiceNetwork, monkeypatch):
    """Missing accepted TEL evidence is an explicit failure, not a new replay escrow."""
    case = groupServiceNetwork
    cosigner = case.services[1]
    body, wrapper = proposal(case)
    original = cosigner.rgy.store.seqEvent
    monkeypatch.setattr(cosigner.rgy.store, 'seqEvent',
        lambda registry, sn: None if registry == case.rip.said else original(registry, sn))
    with joining(case.members, auto=False) as (command, _):
        command.rvy, command.saltService = cosigner.rvy, cosigner
        command.group = case.groups[1].name
        monkeypatch.setattr('builtins.input', lambda _: pytest.fail('missing evidence must not prompt'))
        with pytest.raises(ValidationError, match='accepted registry inception'):
            next(command.rpy(dict(r=wrapper.route, d=wrapper.said)))
        assert cosigner.hby.db.rpys.get((body.said,)) is None
        assert [member.qb64 for member in cosigner.hby.db.maids.get((body.said,))] == [case.groups[0].mhab.pre]
