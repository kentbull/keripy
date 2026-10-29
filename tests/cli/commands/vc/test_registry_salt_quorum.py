"""Finite group reply submission does not impose an all-members-online barrier."""
from contextlib import contextmanager
import socket
import pytest
from keri import Vrsn_2_0
from keri.kering import ConfigurationError, Kinds, Roles
from tests.app.test_acdc_v2_groups import groupNetwork
from tests.app.test_registry_salt_direct import groupServiceNetwork
from tests.cli.commands.multisig.test_join_registry_salt import proposal
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



@pytest.mark.parametrize('mode', ['missing', 'stalled'])
def test_join_returns_signature_without_waiting_for_third(groupServiceNetwork, unused_tcp_port_factory, mode):
    """The actual proposer receives quorum; optional stalled HTTP is closed on return."""
    case = groupServiceNetwork
    first = (case.members[0], *(items[:1] for items in case.members[1:]))
    with groupNetwork(first, unused_tcp_port_factory) as (until, endpoints), \
         thirdMember(case, mode), joining(case.members) as (command, clock):
        command.rvy, command.saltService = case.services[1].rvy, case.services[1]
        command.group = case.groups[1].name
        body, wrapper = proposal(case)
        result = drive(command, clock, command.rpy(dict(r=wrapper.route, d=wrapper.said)), until)
        assert result is True and endpoints[0].requests == 1
        case.services[0].rvy.processEscrowReply()
        assert case.hbys[0].db.rpys.get((body.said,)).raw == body.raw
        assert case.hbys[1].db.rpys.get((body.said,)).raw == body.raw
        assert case.hbys[2].db.rpys.get((body.said,)) is None
        assert not command.doers


def test_missing_proposer_route_is_explicit_submission_failure(groupServiceNetwork):
    """Local approval is retained, but no route must not be reported as delivery."""
    case = groupServiceNetwork
    with joining(case.members) as (command, clock):
        command.rvy, command.saltService = case.services[1].rvy, case.services[1]
        command.group = case.groups[1].name
        body, wrapper = proposal(case)
        with pytest.raises(ConfigurationError, match='proposer has no delivery route'):
            next(command.rpy(dict(r=wrapper.route, d=wrapper.said)))
        assert case.hbys[1].db.rpys.get((body.said,)).raw == body.raw
        assert case.hbys[0].db.rpys.get((body.said,)) is None
        assert not command.doers
