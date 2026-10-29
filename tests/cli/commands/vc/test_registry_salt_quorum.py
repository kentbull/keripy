"""Authenticated group replies survive an unavailable nonapproving third member."""
from contextlib import contextmanager
import json
import socket
from types import SimpleNamespace

import pytest
from hio.base import doing

from keri import Vrsn_2_0
from keri.cli.common import registry_salts
from keri.kering import Kinds, Roles
from tests.app.test_acdc_v2_groups import groupNetwork
from tests.app.test_registry_salt_service import groupServiceNetwork
from tests.cli.commands.multisig.test_join_v2 import joining, drive


@contextmanager
def thirdMember(case, mode):
    """Leave the real third member without a route or behind a silent TCP listener."""
    with socket.socket() as listener:
        if mode != 'missing':
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            member = case.groups[2].mhab
            role = member.makeEndRole(eid=member.pre, role=Roles.controller,
                version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)
            location = member.makeLocScheme(url=f'http://127.0.0.1:{listener.getsockname()[1]}',
                version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)
            for hby in case.members[0]:
                hby.psr.parse(ims=bytearray(role + location))
        yield listener
        if mode != 'missing':
            listener.settimeout(0.5)
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(0.5)
                received = bytearray()
                while chunk := connection.recv(65536):
                    received.extend(chunk)
                assert received.startswith(b'PUT ')
                # EOF, rather than timeout, proves cancellation closed the child.


def initialProposal(case):
    """Retain one real representative contribution on the independent cosigner."""
    leader = case.services[0]
    body = leader.prepareInit(issuer=case.groups[0].pre, discloser=case.discloser.pre,
        party=case.groups[0].pre, representative=case.groups[0].mhab.pre)
    outbound = leader.approveReply(body)
    case.owners[1].receive(outbound.proposal.raw + outbound.attachments)
    return body, outbound.proposal.said


@pytest.mark.parametrize('mode', ['missing', 'stalled', 'all-stalled'])
def test_join_salt_quorum_cancels_unavailable_third(tmp_path, unused_tcp_port_factory, capsys, mode):
    """Deliver to the healthy representative, then close an optional stalled child."""
    with groupServiceNetwork(tmp_path) as case:
        count = 0 if mode == 'all-stalled' else 1
        first = (case.members[0], *(items[:count] for items in case.members[1:]))
        with groupNetwork(first, unused_tcp_port_factory) as (until, endpoints), \
             thirdMember(case, mode), joining(case.members) as (command, clock):
            command.rvy = case.services[1].rvy
            command.saltService = case.services[1]
            if mode == 'all-stalled':
                command.timeout = 0.2
            body, proposal = initialProposal(case)
            assert not command.saltService.state.proof(body.said)
            result = drive(command, clock, command.rpy(dict(r='/multisig/rpy', d=proposal)), until)
            assert result is True
            if endpoints:
                assert endpoints[0].requests == 1
            assert 'Dissemination to some members remains pending' in capsys.readouterr().out
            assert bool(case.services[0].state.proof(body.said)) is (mode != 'all-stalled')
            assert case.services[1].state.proof(body.said)
            assert case.services[2].state.proof(body.said) is None
            assert not command.deeds


@pytest.mark.parametrize('mode', ['missing', 'stalled', 'all-stalled'])
def test_salt_command_quorum_cancels_unavailable_third(tmp_path, unused_tcp_port_factory, monkeypatch, capsys, mode):
    """The actual command composes its processors and exports the threshold proof."""
    with groupServiceNetwork(tmp_path) as case:
        count = 0 if mode == 'all-stalled' else 1
        first = (case.members[0], *(items[:count] for items in case.members[1:]))
        with groupNetwork(first, unused_tcp_port_factory) as (until, endpoints), thirdMember(case, mode):
            body, proposal = initialProposal(case)
            service = case.services[1]

            @contextmanager
            def borrowed(args, custody):
                """Borrow real encrypted fixture stores; their existing owner closes them."""
                yield service.hby, service.rgy, service.wallet

            monkeypatch.setattr(registry_salts.acdc_v2, 'opened', borrowed)
            output = tmp_path / 'authenticated.cesr'
            args = SimpleNamespace(operation='approve', alias='group', timeout=0.2 if mode == 'all-stalled' else 1.0,
                evidence=[], rosters=None, input=None, output=str(output),
                proposal=proposal, proposal_output=None, endpoint=None)
            command = registry_salts.SaltDoer(args)
            runner = doing.Doist(tock=0.01, real=False, doers=[command])
            runner.enter()
            try:
                def complete():
                    runner.recur()
                    return command.done
                until(complete)
            finally:
                runner.exit()
            if endpoints:
                assert endpoints[0].requests == 1
            result = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
            assert result['authenticated'] and result['dissemination_pending']
            assert output.read_bytes() == service.state.proof(body.said)
            assert bool(case.services[0].state.proof(body.said)) is (mode != 'all-stalled')
            assert case.services[2].state.proof(body.said) is None
            assert not command.deeds


def test_salt_command_submission_without_quorum_remains_pending(tmp_path, unused_tcp_port_factory, monkeypatch):
    """A healthy HTTP submission cannot replace the missing second approval."""
    with groupServiceNetwork(tmp_path) as case:
        first = (case.members[0], *(items[:1] for items in case.members[1:]))
        with groupNetwork(first, unused_tcp_port_factory) as (until, endpoints):
            service = case.services[1]

            @contextmanager
            def borrowed(args, custody):
                """Borrow the independent member's actual encrypted stores."""
                yield service.hby, service.rgy, service.wallet

            monkeypatch.setattr(registry_salts.acdc_v2, 'opened', borrowed)
            output = tmp_path / 'unapproved.cesr'
            args = SimpleNamespace(operation='init', alias='group', timeout=0.2,
                issuer=case.groups[0].pre, discloser=case.discloser.pre,
                evidence=[], rosters=None, input=None, output=str(output),
                proposal=None, proposal_output=None, endpoint=None)
            command = registry_salts.SaltDoer(args)
            runner = doing.Doist(tock=0.01, real=False, doers=[command])
            runner.enter()
            try:
                with pytest.raises(TimeoutError, match='pending exact group approval'):
                    until(lambda: (runner.recur(), command.done)[1])
            finally:
                runner.exit()
            assert endpoints[0].requests == 1
            assert not output.exists()
            assert service.state.db.saltProofs.cnt() == 0
            assert not command.deeds
