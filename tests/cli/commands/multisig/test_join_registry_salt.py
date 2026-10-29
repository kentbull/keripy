"""The existing group join dialog approves salt replies without owning DH state."""
import pytest

from tests.app.test_acdc_v2_groups import groupNetwork
from tests.app.test_registry_salt_service import groupServiceNetwork, groupBound
from tests.cli.commands.multisig.test_join_v2 import joining, drive


def test_join_salt_statement_uses_exact_existing_quorum(tmp_path, unused_tcp_port_factory):
    """A nonrepresentative approves a public init and fans out over real HTTP."""
    with groupServiceNetwork(tmp_path) as case:
        leader, cosigner = case.services[:2]
        with joining(case.members) as (command, clock), \
             groupNetwork(case.members, unused_tcp_port_factory) as (until, _):
            command.rvy = cosigner.rvy
            command.saltService = cosigner
            body = leader.prepareInit(issuer=case.groups[0].pre, discloser=case.discloser.pre,
                party=case.groups[0].pre, representative=case.groups[0].mhab.pre)
            outbound = leader.approveReply(body)
            case.owners[1].receive(outbound.proposal.raw + outbound.attachments)
            assert cosigner.state.proof(body.said) is None
            assert not cosigner.state.hasPending(body.said, case.groups[1].mhab.pre)
            result = drive(command, clock, command.rpy(dict(r='/multisig/rpy',
                          d=outbound.proposal.said)), until)
            assert result is True
            assert leader.state.proof(body.said) and cosigner.state.proof(body.said)
            assert not case.services[2].state.proof(body.said)  # no unsolicited local approval
            assert not cosigner.state.hasPending(body.said, case.groups[1].mhab.pre)
            assert not cosigner.custody.db.custody.get((case.rip.said,))
            assert not command.doers


def test_join_salt_decline_never_signs_or_starts_dh(tmp_path, monkeypatch):
    """Inspection and refusal do not become a local approval or private attempt."""
    with groupServiceNetwork(tmp_path) as case:
        leader, cosigner = case.services[:2]
        with joining(case.members, auto=False) as (command, _):
            command.rvy = cosigner.rvy
            command.saltService = cosigner
            body = leader.prepareInit(issuer=case.groups[0].pre, discloser=case.discloser.pre,
                party=case.groups[0].pre, representative=case.groups[0].mhab.pre)
            outbound = leader.approveReply(body)
            case.owners[1].receive(outbound.proposal.raw + outbound.attachments)
            monkeypatch.setattr('builtins.input', lambda _: 'n')
            with pytest.raises(StopIteration) as stopped:
                next(command.rpy(dict(r='/multisig/rpy', d=outbound.proposal.said)))
            assert stopped.value.value is False
            assert [member.qb64 for member in cosigner.hby.db.maids.get((body.said,))] == [case.groups[0].mhab.pre]
            assert cosigner.state.proof(body.said) is None
            assert not cosigner.state.hasPending(body.said, case.groups[1].mhab.pre)


def test_join_salt_missing_transcript_stays_pending_before_prompt(tmp_path, monkeypatch):
    """Unavailable public evidence retains the proposal without asking for blind approval."""
    with groupServiceNetwork(tmp_path) as case:
        init, bind = groupBound(case)
        leader, cosigner = case.services[:2]
        body = leader.prepareConfirm(init.said, bind.said)
        outbound = leader.approveReply(body)
        # The member has a proposal but its independent proof archive is missing
        # a dependency. Incoming notification cannot replace that evidence.
        cosigner.state.db.saltProofs.rem((init.said,))
        case.owners[1].receive(outbound.proposal.raw + outbound.attachments)
        with joining(case.members, auto=False) as (command, _):
            command.rvy, command.saltService = cosigner.rvy, cosigner
            monkeypatch.setattr('builtins.input', lambda _: pytest.fail('missing evidence must not prompt'))
            with pytest.raises(StopIteration) as stopped:
                next(command.rpy(dict(r='/multisig/rpy', d=outbound.proposal.said)))
            assert stopped.value.value is None
            assert cosigner.state.proof(body.said) is None
            assert [member.qb64 for member in cosigner.hby.db.maids.get((body.said,))] == [case.groups[0].mhab.pre]
