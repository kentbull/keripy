"""Real independent group members, ACDC v2 registry TELs and IPEX approval thresholds."""
from contextlib import ExitStack, contextmanager

import pytest

from keri import Vrsn_2_0
from keri.acdc import Regery, acdcmap, grant, loadHandlers
from keri.acdc.messaging import blindate, regcept
from keri.app import openHby
from keri.app.acdc_v2_grouping import AcdcV2GroupCoordinator
from keri.core import Blinder, Diger, Number, Parser, messagize, eventing
from keri.kering import Kinds, ValidationError, MissingSchemaError
from keri.peer import Exchanger


class Notices:
    def add(self, attrs):
        """Ignore accepted-notification attributes for this verifier-only test.

        Args:
            attrs (dict): Notification payload deliberately unused by the test.

        Returns:
            None. No notification side effects are needed to observe acceptance."""
        pass


@pytest.fixture
def members():
    """Yield three independent members of an accepted real 2-of-3 group.

    Yields:
        tuple: Haberies, GroupHabs, Regery owners, and AcdcV2GroupCoordinator coordinators.
        groupMembers owns cleanup; membership/quorum are real signed KEL state."""
    with groupMembers('members') as result:
        yield result


@contextmanager
def groupMembers(label, *, sectioned=False):
    """Yield independent 2-of-3 group peers with optional real section stores.

    Args:
        label (str): Isolated test identity namespace.
        sectioned (bool): Share one caller-owned Sectioner per peer between
            ACDC v2 IPEX verification, direct proposal intake, and mailbox parsing.

    Yields:
        tuple: Haberies, group identities, registry owners, and coordinators.
        ExitStack closes all evidence stores after the caller's assertions.
    """
    from keri.acdc.sectioning import SectionBaser, Sectioner
    from keri.db import openLMDB

    with ExitStack() as stack:
        hbys = [stack.enter_context(openHby(name=f'acdc-v2-group-{label}-{n}', version=Vrsn_2_0))
                for n in range(3)]
        people = [hby.makeHab(name='member') for hby in hbys]
        for hby in hbys:
            for person in people:
                Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(
                    ims=bytearray(person.replay(gvrsn=Vrsn_2_0)), local=True)
        groups = [hby.makeGroupHab(group='group', mhab=person,
                    smids=[member.pre for member in people], isith='2', nsith='2',
                    version=Vrsn_2_0) for hby, person in zip(hbys, people)]
        messages = [group.msgOwnInception(allowPartiallySigned=True, gvrsn=Vrsn_2_0)
                    for group in groups]
        for hby in hbys:
            for message in messages:
                Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(message), local=True)
            hby.kvy.processEscrows()
        assert len({group.pre for group in groups}) == 1
        assert all(group.accepted for group in groups)
        rgys, coordinators = [], []
        for hby, group in zip(hbys, groups):
            rgy = Regery(hby=hby, temp=True)
            stack.callback(rgy.close)
            exc = Exchanger(hby, handlers=[])
            sections = (stack.enter_context(openLMDB(cls=SectionBaser, name=hby.name))
                        if sectioned else None)
            scy = Sectioner(db=hby.db, sections=sections) if sectioned else None
            loadHandlers(hby, exc, Notices(), rgy=rgy, sections=sections)
            rgys.append(rgy)
            coordinators.append(AcdcV2GroupCoordinator(hby, rgy, group, exc, Notices(), scy=scy))
        yield hbys, groups, rgys, coordinators


def test_registry_quorum_and_explicit_member_approval(members):
    """Require real group quorum and each member local approval before accepting ACDC v2 registry TEL state; old proposal replay cannot lower the head.

    Parameters:
        members: Three independent accepted 2-of-3 group environments and coordinators.

    Returns:
        None. Assertions check the stated evidence boundary."""
    hbys, groups, rgys, owners = members
    rip = regcept(groups[0].pre)
    first, atc = owners[0].approveRegistry(rip)
    assert first.route == '/multisig/rip'
    assert '/multisig/registry' not in owners[0].exc.routes
    assert rgys[0].store.headEvent(rip.said) is None
    proposal = first.raw + atc
    event, anchor, opening = owners[1].registryProposal(proposal)
    assert opening is None
    owners[2].receive(proposal)
    assert event.said == rip.said
    assert rgys[1].store.headEvent(rip.said) is None
    assert rgys[2].store.headEvent(rip.said) is None
    second, batc = owners[1].approveRegistry(event, anchor)
    assert rgys[1].store.headEvent(rip.said).said == rip.said
    owners[0].receive(second.raw + batc)
    assert rgys[0].store.headEvent(rip.said).said == rip.said
    owners[2].receive(second.raw + batc)
    assert rgys[2].store.headEvent(rip.said) is None
    owners[2].approveRegistry(event, anchor)
    assert rgys[2].store.headEvent(rip.said).said == rip.said

    credential = acdcmap(israid=groups[0].pre, regid=rip.said,
                         attribute=dict(d='', role='group-issued'))
    opening = Blinder.blind(sn=1, acdc=credential.said, state='issued')
    issued = blindate(rip.said, rip.said, opening.said)
    first, atc = owners[0].approveRegistry(issued, opening=opening)
    assert first.route == '/multisig/bup'
    event, anchor, disclosed = owners[1].registryProposal(first.raw + atc)
    assert disclosed.qb64 == opening.qb64
    assert rgys[1].store.headEvent(rip.said).said == rip.said
    second, batc = owners[1].approveRegistry(event, anchor, opening=disclosed)
    owners[0].receive(second.raw + batc)
    assert rgys[0].store.headEvent(rip.said).said == issued.said
    assert rgys[1].store.headEvent(rip.said).said == issued.said
    # Exact old proposal replay cannot lower the accepted ACDC v2 registry TEL head.
    owners[0].receive(proposal)
    assert rgys[0].store.headEvent(rip.said).said == issued.said


def test_blinded_registry_approval_needs_no_opening(members):
    """Approve an exact bup commitment without disclosing or deriving its opening."""
    _, groups, rgys, owners = members
    rip = regcept(groups[0].pre)
    first, atc = owners[0].approveRegistry(rip)
    event, anchor, _ = owners[1].registryProposal(first.raw + atc)
    second, atc = owners[1].approveRegistry(event, anchor)
    owners[0].receive(second.raw + atc)

    opening = Blinder.blind(sn=1, acdc=Diger(ser=b'private credential').qb64, state='issued')
    bup = blindate(rip.said, rip.said, opening.said)
    first, atc = owners[0].approveRegistry(bup)
    proposal = Parser(version=Vrsn_2_0).parse(
        ims=bytearray(first.raw + atc), processive=False)[0]
    assert first.route == '/multisig/bup'
    assert not proposal.nests[0].bsqs and not proposal.nests[0].bsss
    assert opening.qb64b not in first.raw + atc
    event, anchor, disclosed = owners[1].registryProposal(first.raw + atc)
    assert disclosed is None
    second, atc = owners[1].approveRegistry(event, anchor)
    owners[0].receive(second.raw + atc)
    assert all(rgy.store.headEvent(rip.said).said == bup.said for rgy in rgys[:2])


def test_group_ipex_uses_real_threshold_and_shared_semantic_handler(members):
    """Combine independent member signatures through the shared IPEX verifier without accepting unapproved member state.

    Parameters:
        members: Three independent accepted 2-of-3 group environments and coordinators.

    Returns:
        None. Assertions check the stated evidence boundary."""
    hbys, groups, _, owners = members
    holder = hbys[0].makeHab(name='holder')
    credential = acdcmap(israid=groups[0].pre, iseaid=holder.pre,
                         attribute=dict(d='', role='group-grant'))
    # The ACDC origin has the same 2-of-3 issuer threshold as the EXN. Each
    # member's explicit approval contributes its own independent origin proof.
    signatures = [group.sign(credential.raw)[0] for group in groups[:2]]
    origin = messagize(credential, tsgs=[(groups[0].kever.prefixer,
        Number(num=groups[0].kever.lastEst.s), Diger(qb64=groups[0].kever.lastEst.d),
        signatures)], gvrsn=Vrsn_2_0)
    exn, atc = grant(groups[0], holder.pre, 'group approved grant', origin=origin)
    first, fatc = owners[0].approveExchange(exn.raw + atc)
    assert not owners[0].completeExchange(exn.said)
    owners[1].receive(first.raw + fatc)
    owners[2].receive(first.raw + fatc)
    assert not owners[1].completeExchange(exn.said)
    second, satc = owners[1].approveExchange(exn.raw + atc)
    assert owners[1].completeExchange(exn.said)
    owners[0].receive(second.raw + satc)
    assert owners[0].completeExchange(exn.said)
    owners[2].receive(second.raw + satc)
    assert not owners[2].completeExchange(exn.said)
    owners[2].approveExchange(exn.raw + atc)
    assert owners[2].completeExchange(exn.said)


def test_acdc_v2_registry_approval_refuses_different_tel(members):
    """Refuse a substituted TEL body under an anchor approved for a different exact inception.

    Parameters:
        members: Three independent accepted 2-of-3 group environments and coordinators.

    Returns:
        None. Assertions check the stated evidence boundary."""
    _, groups, _, owners = members
    rip = regcept(groups[0].pre)
    proposal, atc = owners[0].approveRegistry(rip)
    _, anchor, _ = owners[1].registryProposal(proposal.raw + atc)
    substitute = regcept(groups[0].pre)
    with pytest.raises(ValidationError, match='exclusively anchor'):
        owners[1].approveRegistry(substitute, anchor)


@pytest.mark.parametrize('route,ilk', [
    ('/multisig/rip', 'bup'),
    ('/multisig/bup', 'rip'),
    ('/multisig/rip', 'icp'),
    ('/multisig/bup', 'icp'),
])
def test_registry_handlers_reject_wrong_tel_ilk_before_save(members, route, ilk):
    """Reject signed proposals whose TEL child does not match the route.

    Real independent members authenticate the wrapper, while the handler must
    reject its shape before retaining proposal children or recording approval.
    """
    from keri.core import Codens, Counter, SerderKERI, exchange
    from keri.peer.exchanging import serializeParsedSubstream

    hbys, groups, rgys, owners = members
    rip = regcept(groups[0].pre)
    if ilk == 'bup':
        event = blindate(rip.said, rip.said, Diger(ser=b'private event').qb64)
    elif ilk == 'icp':
        event = SerderKERI(raw=groups[0].msgOwnInception(gvrsn=Vrsn_2_0))
    else:
        event = rip
    anchorStream = groups[0].interact(data=[dict(s=event.sad.get('n', '0'), d=event.said)],
        version=Vrsn_2_0, gvrsn=Vrsn_2_0)
    anchor = SerderKERI(raw=anchorStream)
    wrapper = exchange(sender=groups[0].mhab.pre, route=route,
        attributes=dict(gid=groups[0].pre, tel=event.said, anc=anchor.said),
        version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)
    footer = Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b
    children = [Parser(version=Vrsn_2_0).parse(ims=bytearray(stream),
        processive=False)[0] for stream in (event.raw + footer, anchorStream)]
    message = groups[0].mhab.endorse(wrapper, last=False, framed=False,
        gvrsn=Vrsn_2_0, nests=[serializeParsedSubstream(child) for child in children])

    parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(message), processive=False)
    assert len(parsed) == 1 and parsed[0].serder.said == wrapper.said
    assert parsed[0].serder.route == route and len(parsed[0].nests) == 2
    with pytest.raises(ValidationError, match='invalid ACDC v2 registry proposal bodies'):
        owners[1].mux.validate(parsed[0].serder, nests=parsed[0].nests)
    with pytest.raises(ValidationError, match='registry proposal is not authenticated'):
        owners[1].registryProposal(message)
    assert hbys[1].db.exns.get((wrapper.said,)) is None
    assert not hbys[1].db.enst.get((wrapper.said,))
    assert not hbys[1].db.meids.get((anchor.said,))
    assert not hbys[1].db.maids.get((anchor.said,))
    assert rgys[1].store.headEvent(rip.said) is None
    assert groups[1].kever.sn == 0


@pytest.mark.parametrize('ilk', ['rip', 'bup'])
@pytest.mark.parametrize('form', ['couple', 'digest', 'triple', 'extra'])
def test_registry_proposal_seal_policy_is_identical_before_consent(members, monkeypatch, ilk, form):
    """Builder, remote intake and approval share one exact anchor contract.

    Digest/triple seals remain valid core evidence forms, but this narrowly
    scoped group signing proposal supports only one sequence/digest couple.
    A signed unsupported proposal must not become a notice awaiting consent.
    """
    from keri.app.grouping import multisigRipExn, multisigBupExn
    from keri.core import Codens, Counter, SerderKERI, exchange
    from keri.peer.exchanging import serializeParsedSubstream

    hbys, groups, rgys, owners = members
    rip = regcept(groups[0].pre)
    if ilk == 'bup':
        initial, atc = owners[0].approveRegistry(rip)
        event, anchor, _ = owners[1].registryProposal(initial.raw + atc)
        approved, atc = owners[1].approveRegistry(event, anchor)
        owners[0].receive(approved.raw + atc)
        assert rgys[0].store.headEvent(rip.said).said == rip.said
    event = rip if ilk == 'rip' else blindate(rip.said, rip.said, Diger(ser=b'private').qb64)
    couple = dict(s=event.sad['n'], d=event.said)
    seals = dict(couple=[couple], digest=[dict(d=event.said)],
                 triple=[dict(i=rip.said, **couple)],
                 extra=[couple, dict(d=Diger(ser=b'unrelated').qb64)])[form]
    stream = groups[0].interact(data=seals, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
    anchor = SerderKERI(raw=stream)
    footer = Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b
    builder = multisigRipExn if ilk == 'rip' else multisigBupExn
    if form == 'couple':
        wrapper, atc = builder(groups[0], event.raw + footer, stream)
        proposed, exact, _ = owners[1].registryProposal(wrapper.raw + atc)
        assert proposed.raw == event.raw and exact.raw == anchor.raw
        owners[1].approveRegistry(proposed, exact)
        return

    with pytest.raises(ValidationError, match='one s,d seal'):
        builder(groups[0], event.raw + footer, stream)
    with pytest.raises(ValidationError, match='one s,d seal'):
        owners[1].approveRegistry(event, anchor)
    # Bypass the local builder to represent an authenticated foreign sender.
    wrapper = exchange(sender=groups[0].mhab.pre, route=f'/multisig/{ilk}',
        attributes=dict(gid=groups[0].pre, tel=event.said, anc=anchor.said),
        version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)
    children = [Parser(version=Vrsn_2_0).parse(ims=bytearray(raw),
        processive=False)[0] for raw in (event.raw + footer, stream)]
    message = groups[0].mhab.endorse(wrapper, gvrsn=Vrsn_2_0,
        nests=[serializeParsedSubstream(child) for child in children])
    notices = []
    monkeypatch.setattr(owners[1].mux.notifier, 'add', notices.append)
    with pytest.raises(ValidationError, match='registry proposal is not authenticated'):
        owners[1].registryProposal(message)
    assert hbys[1].db.exns.get((wrapper.said,)) is None
    assert not hbys[1].db.maids.get((anchor.said,))
    assert notices == []


def test_registry_builders_reject_wrong_route_and_removed_route(members):
    """Make route contracts explicit at authoring and reject the removed wrapper.

    Neither route selection nor proposal inspection may sign an unrelated TEL.
    """
    from keri import Vrsn_1_0
    from keri.app.grouping import multisigRipExn, multisigBupExn
    from keri.peer import specialExchange
    from keri.core import Codens, Counter, exchange

    _, groups, _, owners = members
    rip = regcept(groups[0].pre)
    bup = blindate(rip.said, rip.said, Diger(ser=b'private event').qb64)
    anchor = groups[0].interact(data=[dict(s='0', d=rip.said)],
        version=Vrsn_2_0, gvrsn=Vrsn_2_0)
    footer = Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b
    with pytest.raises(ValueError, match='requires a rip event'):
        multisigRipExn(groups[0], bup.raw + footer, anchor)
    with pytest.raises(ValueError, match='requires a bup event'):
        multisigBupExn(groups[0], rip.raw + footer, anchor)

    wrapper = exchange(sender=groups[0].mhab.pre, route='/multisig/registry',
        attributes=dict(gid=groups[0].pre), version=Vrsn_2_0, gvrsn=Vrsn_2_0)
    message = groups[0].mhab.endorse(wrapper, last=False, framed=False, gvrsn=Vrsn_2_0)
    assert '/multisig/registry' not in owners[1].exc.routes
    with pytest.raises(ValidationError, match='expected one ACDC v2 registry proposal'):
        owners[1].registryProposal(message)

    for route in ('/multisig/rip', '/multisig/bup'):
        legacy, _ = specialExchange(sender=groups[0].mhab.pre, route=route,
            attributes=dict(gid=groups[0].pre), version=Vrsn_1_0)
        with pytest.raises(ValidationError, match='requires a v2 wrapper'):
            owners[1].mux.validate(legacy)
        assert not owners[1].exc.routes[route].verify(legacy)


def test_cli_group_proposal_reopens_pending_state_and_issues_without_secret_fanout(tmp_path):
    """Resume exact public group proposals across actual CLI process exits and issue without distributing custody secrets.

    Parameters:
        tmp_path: Pytest-owned exact proposal files surviving installed CLI process exits.

    Returns:
        None. Assertions check the stated evidence boundary."""
    import uuid
    from tests.app.test_acdc_v2_cli import PASSCODE, command, invoke

    names = ['group-cli-' + uuid.uuid4().hex for _ in range(2)]
    with ExitStack() as stack:
        hbys = [stack.enter_context(openHby(name=name, base='acdc-v2-cli-test', temp=False,
                    bran=PASSCODE, version=Vrsn_2_0)) for name in names]
        people = [hby.makeHab(name='member') for hby in hbys]
        for hby, remote in zip(hbys, reversed(people)):
            Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(
                ims=bytearray(remote.replay(gvrsn=Vrsn_2_0)), local=True)
        groups = [hby.makeGroupHab(group='group', mhab=person,
                    smids=[member.pre for member in people], isith='2', nsith='2', version=Vrsn_2_0)
                  for hby, person in zip(hbys, people)]
        messages = [group.msgOwnInception(allowPartiallySigned=True, gvrsn=Vrsn_2_0)
                    for group in groups]
        for hby, message in zip(hbys, reversed(messages)):
            Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(message), local=True)
            hby.kvy.processEscrows()
        prefix = groups[0].pre

    first, second = tmp_path / 'first.cesr', tmp_path / 'second.cesr'
    result = command(names[0], 'vc', 'registry', 'incept', '--acdc-v2', '-a', 'group',
        '-r', 'registry', '--proposal-output', str(first), '--timeout', '0.2')
    assert first.exists()
    assert 'pending member approval' in result.stdout
    pending = invoke(names[0], 'vc', 'registry', 'status', '--acdc-v2', '-r', 'registry')[0]
    assert pending['accepted'] is False and pending['pending']
    accepted = invoke(names[1], 'vc', 'registry', 'incept', '--acdc-v2', '-a', 'group',
        '-r', 'registry', '--proposal', str(first), '--proposal-output', str(second), '--timeout', '2')[0]
    assert accepted['accepted'] and accepted['controller'] == prefix
    assert accepted['custody'] == 'not requested'
    accepted = invoke(names[0], 'vc', 'registry', 'incept', '--acdc-v2', '-a', 'group',
        '-r', 'registry', '--proposal', str(second), '--timeout', '2')[0]
    assert accepted['accepted']

    # A public bup needs no independently regenerated custody secret. Its exact
    # opening, TEL and KEL bodies are reused after each CLI process exits.
    issue1, issue2 = tmp_path / 'issue1.cesr', tmp_path / 'issue2.cesr'
    args = ('vc', 'create', '--acdc-v2', '-a', 'group', '-r', 'registry',
            '--public', '--data', '{"role":"member-approved"}')
    result = command(names[0], *args, '--proposal-output', str(issue1), '--timeout', '0.2')
    assert 'pending member approval' in result.stdout
    issued = invoke(names[1], *args, '--proposal', str(issue1), '--proposal-output', str(issue2), '--timeout', '2')[0]
    assert issued['state'] == 'issued'
    issuedAgain = invoke(names[0], *args, '--proposal', str(issue2), '--timeout', '2')[0]
    assert issuedAgain['credential'] == issued['credential']
    assert invoke(names[0], 'vc', 'registry', 'status', '--acdc-v2', '-r', 'registry')[0]['sn'] == 1
    # Public group authoring must not provision a secret in either member store.
    from keri.app import Keeper
    from keri.db import openLMDB
    for name in names:
        with openLMDB(cls=Keeper, name=name, base='acdc-v2-cli-test', temp=False) as keeper:
            assert keeper.custody.get((accepted['registry'],)) is None
    for path in (first, second, issue1, issue2):
        parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(path.read_bytes()), processive=False)
        wrapper = parsed[-1]
        assert wrapper.serder.route == ('/multisig/rip' if path in (first, second)
                                        else '/multisig/bup')
        assert not wrapper.bsqs and not wrapper.bsss
    for path in (issue1, issue2):
        tel = Parser(version=Vrsn_2_0).parse(
            ims=bytearray(path.read_bytes()), processive=False)[-1].nests[0]
        assert tel.serder.ilk == 'bup'
        assert len(tel.bsqs) + len(tel.bsss) == 1


@contextmanager
def groupNetwork(members, unused_tcp_port_factory):
    """Run real HTTP group delivery over authenticated endpoint-role/location replies.

    Args:
        members (tuple): Independent accepted group members and concrete coordinators.
        unused_tcp_port_factory: Pytest allocator for independent loopback listeners.

    Yields:
        tuple: A bounded cooperative until(predicate) driver and observable intake
        endpoints. Finally removes doers and closes all sockets on exit."""
    import time
    import falcon
    from hio.base import doing
    from hio.core import http
    from keri.app import HttpEnd
    from keri.kering import Kinds, Roles

    hbys, groups, rgys, owners = members

    class Intake(HttpEnd):
        def __init__(self, owner):
            """Bind one loopback HTTP intake endpoint to its real group coordinator.

            Args:
                owner (AcdcV2GroupCoordinator): Destination coordinator receiving each request stream.

            Returns:
                None. Initializes a fresh byte buffer and request counter."""
            self.owner, self.requests = owner, 0
            super().__init__(rxbs=bytearray())

        def on_post(self, req, rep):
            """Parse a real HTTP POST body then hand its bytes to group intake.

            Args:
                req (falcon.Request): Incoming CESR request.
                rep (falcon.Response): Response populated by the ordinary HttpEnd parser.

            Returns:
                None. Counts delivery and clears the buffer after owner.receive; acceptance
                and explicit local approval are asserted separately."""
            super().on_post(req, rep)
            self.requests += 1
            self.owner.receive(self.rxbs)
            self.rxbs.clear()

        def on_put(self, req, rep):
            """Parse a real HTTP PUT body then hand its bytes to group intake.

            Args:
                req (falcon.Request): Incoming CESR request.
                rep (falcon.Response): Response populated by the ordinary HttpEnd parser.

            Returns:
                None. Counts delivery and clears the buffer; it grants no member approval."""
            super().on_put(req, rep)
            self.requests += 1
            self.owner.receive(self.rxbs)
            self.rxbs.clear()

    servers, endpoints = [], []
    for group, owner in zip(groups, owners):
        port = unused_tcp_port_factory()
        app = falcon.App()
        endpoint = Intake(owner)
        app.add_route('/', endpoint)
        endpoints.append(endpoint)
        servers.append(http.Server(port=port, app=app))
        # Endpoint discovery itself uses authenticated KERI replies.
        role = group.mhab.makeEndRole(eid=group.mhab.pre, role=Roles.controller,
            version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)
        location = group.mhab.makeLocScheme(url=f'http://127.0.0.1:{port}',
            version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)
        for hby in hbys:
            hby.psr.parse(ims=bytearray(role + location))

    doist = doing.Doist(tock=0.01, real=False,
        doers=owners + [http.ServerDoer(server=server) for server in servers])
    doist.enter()
    try:
        def until(predicate):
            """Drive cooperative group/socket work until the predicate holds or five seconds pass.

            Args:
                predicate (Callable[[], bool]): Observable accepted/delivered state to await.

            Returns:
                None. AssertionError reports a deadline without falsely claiming completion."""
            deadline = time.monotonic() + 5
            while not predicate() and time.monotonic() < deadline:
                doist.recur()
                time.sleep(0.01)
            assert predicate()

        yield until, endpoints
    finally:
        doist.exit()
        for server in servers:
            server.close()


def test_group_fanout_uses_real_http_and_keeps_unapproved_member_pending(members, unused_tcp_port_factory):
    """Deliver proposals over real discovered HTTP endpoints while leaving an unapproved third member pending.

    Parameters:
        members: Three independent accepted 2-of-3 group environments and coordinators.
        unused_tcp_port_factory: Pytest allocator for real independent loopback listeners.

    Returns:
        None. Assertions check the stated evidence boundary."""
    hbys, groups, rgys, owners = members
    with groupNetwork(members, unused_tcp_port_factory) as (until, endpoints):
        rip = regcept(groups[0].pre)
        first, atc = owners[0].approveRegistry(rip)
        owners[0].send(first, atc)
        until(lambda: endpoints[1].requests > 0 and endpoints[2].requests > 0)
        assert rgys[1].store.headEvent(rip.said) is None
        assert rgys[2].store.headEvent(rip.said) is None

        event, anchor, opening = owners[1].registryProposal(first.raw + atc)
        assert opening is None
        second, batc = owners[1].approveRegistry(event, anchor)
        owners[1].send(second, batc)
        until(lambda: rgys[0].store.headEvent(rip.said) is not None and endpoints[2].requests > 1)
        assert rgys[0].store.headEvent(rip.said).said == rip.said
        assert rgys[1].store.headEvent(rip.said).said == rip.said
        assert rgys[2].store.headEvent(rip.said) is None


def test_group_issuer_holder_admission_presentation_and_revocation_converge(members, unused_tcp_port_factory):
    """Converge real group issuer/holder approvals, explicit admission, onward presentation, and later revocation over loopback transport.

    Parameters:
        members: Three independent accepted 2-of-3 group environments and coordinators.
        unused_tcp_port_factory: Pytest allocator for real independent loopback listeners.

    Returns:
        None. Assertions check the stated evidence boundary."""
    from keri.acdc import admit
    from keri.acdc.regeventing import vet
    from keri.app.credentialing import Wallet
    from keri.core import Codens, Counter, Prefixer
    from keri.peer import serializeMessage
    from keri.peer.exchanging import serializeParsedSubstream

    issuerTeam = members
    with groupMembers('holders') as holderTeam, ExitStack() as stack:
        allTeams = [issuerTeam, holderTeam]
        combined = tuple([item for team in allTeams for item in team[index]] for index in range(4))
        hbys, groups, rgys, owners = combined
        # Establish actual remote member and group KELs at each independent peer.
        for owner in owners:
            for group in groups:
                owner.receive(group.mhab.replay(gvrsn=Vrsn_2_0))
                owner.receive(group.replay(gvrsn=Vrsn_2_0))
        wallets = [Wallet(hby, rgy, exc=owner.exc) for hby, rgy, owner in zip(hbys, rgys, owners)]
        for wallet in wallets:
            stack.callback(wallet.close)
        foot = Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b

        with groupNetwork(combined, unused_tcp_port_factory) as (until, endpoints):
            def approveRegistry(team, event, opening=None):
                """Collect independent local approvals and deliver the same TEL proposal to a team.

                Args:
                    team (tuple): Real group environments, registries, and coordinators.
                    event (SerderACDC): Exact ACDC v2 registry TEL event requiring group approval.

                Returns:
                    None. Assertions require each member's accepted registry frontier to converge."""
                _, _, stores, peers = team
                first, atc = peers[0].approveRegistry(event, opening=opening)
                peers[0].send(first, atc)
                until(lambda: peers[1].exc.complete(first.said) and peers[2].exc.complete(first.said))
                proposed, anchor, disclosed = peers[1].registryProposal(first.raw + atc)
                second, batc = peers[1].approveRegistry(proposed, anchor, opening=disclosed)
                peers[1].send(second, batc)
                until(lambda: peers[0].exc.complete(second.said) and peers[2].exc.complete(second.said))
                peers[2].approveRegistry(proposed, anchor, opening=disclosed)
                regid = event.said if event.ilk == 'rip' else event.sad['rd']
                assert all(store.store.headEvent(regid).said == event.said for store in stores)

            def synchronize():
                # Public proof dissemination goes through the production Parser
                # and Rever; no accepted-table shortcuts or synthetic KRAM rows.
                """Replay actual group KEL/TEL bytes between issuer, holder, and verifier teams.

                Returns:
                    None. Each destination uses ordinary group intake rather than copying accepted
                    database rows; pending dependencies remain subject to its normal processors."""
                for team in allTeams:
                    _, teamGroups, stores, _ = team
                    stream = bytearray(teamGroups[0].replay(gvrsn=Vrsn_2_0))
                    for _, event in stores[0].store.baser.evts.getTopItemIter():
                        stream.extend(event.raw + foot)
                    for owner in owners:
                        owner.receive(stream)

            def approveExchange(team, stream):
                """Collect explicit group approvals for one exact ACDC v2 IPEX child exchange stream.

                Args:
                    team (tuple): Real group environments and coordinators.
                    stream (bytes): Exact signed ACDC v2 IPEX exchange bytes to approve and deliver.

                Returns:
                    bytearray: Serialized accepted child exchange/proof after every group peer
                    reports completion."""
                _, _, _, peers = team
                child = Parser(version=Vrsn_2_0).parse(ims=bytearray(stream), processive=False)[0].serder
                first, atc = peers[0].approveExchange(stream)
                peers[0].send(first, atc)
                until(lambda: peers[1].exc.complete(first.said) and peers[2].exc.complete(first.said))
                exact = peers[1].exchangeProposal(first.raw + atc)
                second, batc = peers[1].approveExchange(exact)
                peers[1].send(second, batc)
                until(lambda: peers[0].completeExchange(child.said) and peers[2].exc.complete(second.said))
                peers[2].approveExchange(exact)
                assert all(peer.completeExchange(child.said) for peer in peers)
                return serializeMessage(peers[0].hby, child.said, framed=False)

            issuer, holder = issuerTeam[1][0], holderTeam[1][0]
            issuerRip, holderRip = regcept(issuer.pre), regcept(holder.pre)
            approveRegistry(issuerTeam, issuerRip)
            approveRegistry(holderTeam, holderRip)
            credential = acdcmap(israid=issuer.pre, regid=issuerRip.said, iseaid=holder.pre,
                attribute=dict(d='', role='group authority', rd=holderRip.said))
            issuedOpening = Blinder.blind(sn=1, acdc=credential.said, state='issued')
            issued = blindate(issuerRip.said, issuerRip.said, issuedOpening.said)
            approveRegistry(issuerTeam, issued, issuedOpening)
            synchronize()
            for wallet in wallets[:3]:
                wallet.recordIssued(credential, issued.said, blinder=issuedOpening)

            # First create the immutable grant, then have the holder group
            # authorize that exact grant through its declared presentation TEL.
            original, atc = grant(issuer, holder.pre, 'group issuance',
                                  origin=messagize(credential, bonds=[issuedOpening.data],
                                                   gvrsn=Vrsn_2_0))

            def presentation(stream, exn, prior, sn):
                """Anchor a holder-group presentation binding and attach its actual historical source.

                Args:
                    stream (bytes): ACDC v2 IPEX Grant stream whose first node receives the source.
                    exn (Serder): Grant whose immutable SAID the public presentation update binds.
                    prior (str): Accepted holder TEL predecessor.
                    sn (int): Next holder registry ordinal.

                Returns:
                    tuple: Accepted presentation update and serialized exact Grant with source proof."""
                opening = Blinder.blind(sn=sn, acdc=exn.said, state='presented')
                binding = blindate(holderRip.said, prior, opening.said, sn=sn)
                approveRegistry(holderTeam, binding, opening)
                synchronize()
                number, diger = holderTeam[2][0].store.anchor(binding.said)
                parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(stream), processive=False)[0]
                node = parsed.nests[0]
                node.ssts.append((Prefixer(qb64=holder.pre), number, diger))
                node.bsqs.append(opening.data)
                return binding, serializeParsedSubstream(parsed)

            firstBinding, stream = presentation(original.raw + atc, original, holderRip.said, 1)
            delivered = approveExchange(issuerTeam, stream)
            for peer in holderTeam[3]:
                peer.receive(delivered)
                assert peer.completeExchange(original.said)
            response, ratc = admit(holder, 'explicit group holder consent', original)
            admitted = approveExchange(holderTeam, response.raw + ratc)
            for peer in issuerTeam[3]:
                peer.receive(admitted)
            for wallet in wallets[3:]:
                wallet.verification.validateAdmission(original.said, response.said, consent=True)
                assert wallet.verification.heldCredential(original.said)['credential'].said == credential.said

            # The group holder presents the retained disclosure with a distinct
            # grant and a newly approved binding. The first grant stays historical.
            held = wallets[3].verification.heldCredential(original.said)
            presented, patc = grant(holder, issuer.mhab.pre, 'group presentation', origin=held['proof'])
            secondBinding, stream = presentation(presented.raw + patc, presented, firstBinding.said, 2)
            delivered = approveExchange(holderTeam, stream)
            for peer in issuerTeam[3]:
                peer.receive(delivered)
                assert peer.completeExchange(presented.said)

            revokedOpening = Blinder.blind(sn=2, acdc=credential.said, state='revoked')
            revoked = blindate(issuerRip.said, issued.said, revokedOpening.said, sn=2)
            approveRegistry(issuerTeam, revoked, revokedOpening)
            synchronize()
            for hby, rgy in zip(hbys, rgys):
                assert rgy.store.headEvent(issuerRip.said).said == revoked.said
                assert vet(issuerRip, [issued, revoked], db=hby.db, acdc=credential,
                           blinder=revokedOpening).state == 'revoked'
                assert rgy.store.headEvent(holderRip.said).said == secondBinding.said
            assert all(wallet.verification.heldCredential(original.said)['grant'].said == original.said
                       for wallet in wallets[3:])
            assert all(endpoint.requests > 0 for endpoint in endpoints)


@pytest.mark.parametrize('arrival', ['before', 'after'])
@pytest.mark.parametrize('intake', ['direct', 'mailbox'])
def test_group_ipex_independent_schema_preserves_approved_disclosure(arrival, intake):
    """Real group approvals resolve standalone schema evidence through either intake.

    Args:
        arrival (str): Deliver the matching section before approval or after
            local approval is deferred for its missing own schema.
        intake (str): Exercise the coordinator or its actual mailbox parser.

    Returns:
        None. Assertions cover independent section lookup, deferred approval,
        real 2-of-3 approval, and exact retained disclosure after fuller caching.
    """
    from copy import deepcopy
    from keri import Kinds
    from keri.acdc.messaging import sectattr, sectschema
    from keri.core import Codens, Compactor, Counter, Noncer
    from keri.peer.exchanging import loadParsedNestedSubstreams, serializeMessage

    with groupMembers(f'schema-{arrival}-{intake}', sectioned=True) as members:
        hbys, groups, _, owners = members
        holder = hbys[0].makeHab(name='holder')
        section = sectschema({'$id': '', 'version': '1.0.0', 'type': 'object',
                              'title': 'group standalone schema'})
        schema = section.sad['s']['$id']
        full = acdcmap(israid=groups[0].pre, iseaid=holder.pre,
            uuid=Noncer().qb64, schema=schema,
            attribute={'d': '', 'u': Noncer().qb64,
                'shown': {'d': '', 'value': 'approved'},
                'private': {'d': '', 'value': 'never disclosed by this grant'}})
        compact = Compactor(mad=deepcopy(full.sad['a']), makify=True, kind=Kinds.json)
        compact.compact(paths=['a/shown/'], root='a')
        partial = acdcmap(israid=full.israid, iseaid=holder.pre, uuid=full.sad['u'],
                           schema=schema, attribute=compact.partials[('a/shown/',)].mad)
        assert partial.said == full.said
        signatures = [group.sign(partial.raw)[0] for group in groups[:2]]
        origin = messagize(partial, tsgs=[(groups[0].kever.prefixer,
            Number(num=groups[0].kever.lastEst.s), Diger(qb64=groups[0].kever.lastEst.d),
            signatures)], gvrsn=Vrsn_2_0)
        exn, atc = grant(groups[0], holder.pre, 'group partial disclosure', origin=origin)

        def receiveSection(owner, message):
            """Feed an independent schema through the selected real direct/mailbox parser.

            Args:
                owner (AcdcV2GroupCoordinator): Peer sharing one concrete Sectioner with both parsers.
                message (SerderACDC): Independently received schema section message.

            Returns:
                None. Dispatches the framed message and retries group work without changing
                the approved/retained credential view."""
            wire = message.raw + Counter(Codens.AttachmentGroup, count=0,
                                         version=Vrsn_2_0).qb64b
            assert owner.parser.scy is owner.scy
            assert owner.mailbox.parser.scy is owner.scy
            if intake == 'direct':
                owner.receive(wire)
            else:
                owner.mailbox.parser.parse(ims=bytearray(wire))
                owner.process()

        assert all(hby.db.schema.get(schema) is None for hby in hbys)
        if arrival == 'after':
            for owner in owners[:2]:
                with pytest.raises(MissingSchemaError):
                    owner.approveExchange(exn.raw + atc)
                assert not owner.completeExchange(exn.said)
        for owner in owners:
            receiveSection(owner, section)
        first, fatc = owners[0].approveExchange(exn.raw + atc)
        assert not owners[0].completeExchange(exn.said)
        owners[1].receive(first.raw + fatc)
        owners[2].receive(first.raw + fatc)
        exact = owners[1].exchangeProposal(first.raw + fatc)
        second, satc = owners[1].approveExchange(exact)
        owners[0].receive(second.raw + satc)
        owners[2].receive(second.raw + satc)
        # Receiving two approvals does not substitute for this member's consent.
        assert not owners[2].completeExchange(exn.said)
        assert all(owner.completeExchange(exn.said) for owner in owners[:2])
        owners[2].approveExchange(exact)
        for owner in owners:
            assert owner.completeExchange(exn.said)
            assert owner.hby.db.emse.get((exn.said, schema)) is None
            assert owner.scy.sections.messages.get(section.said).raw == section.raw
            context = owner.exc.routes['/ipex/grant'].verification
            assert context.verifyAccepted(exn.said, '/ipex/grant')
            assert context.evaluateGrant(exn.said) is True
            before = serializeMessage(owner.hby, exn.said)
            receiveSection(owner, sectattr(full.sad['a']))
            assert serializeMessage(owner.hby, exn.said) == before
            retained = loadParsedNestedSubstreams(owner.hby, exn.said)[0].serder
            assert retained.raw == partial.raw
            assert isinstance(retained.sad['a']['private'], str)
            assert owner.hby.db.schema.get(schema) is None

@pytest.mark.parametrize('operator', ['NOR', 'AVG'])
@pytest.mark.parametrize('boundary', ['proposer', 'approval', 'completion'])
def test_cli_proposer_and_imported_approval_gate_before_member_signature(members, tmp_path, monkeypatch, operator, boundary):
    """Run the actual CLI owner with real held evidence before its Grant builder.

    Boot reuses the three real member owners through an owned capability context.
    Completion supplies an explicit policy and drives ordinary remote approval
    during the wait. Parser, proof checks, wallet consent and CLI control flow
    remain real; signature observation wraps the GroupHab signer.
    """
    from hio.base import doing
    from keri.acdc import admit, apply
    from keri.app.credentialing import Wallet
    from keri.cli.common import acdc_v2_ipex
    from keri.cli.commands.ipex.grant import parser as arguments
    from keri.kering import ConfigurationError
    hbys, groups, rgys, owners = members
    hby, group, rgy = hbys[0], groups[0], rgys[0]
    issuer = group.mhab

    class Policy:
        permitted = True
        def validity(self, node):
            return node.sad['a'].get('eligible', True) if self.permitted else True
        def value(self, **kwa):
            return 1
        def accept(self, **kwa):
            return self.permitted

    far = acdcmap(israid=issuer.pre, attribute=dict(d='', eligible=operator == 'AVG'))
    near = acdcmap(israid=issuer.pre, iseaid=group.pre, attribute=dict(d='', held=True),
        edge=dict(d='', o=operator, proof=dict(n=far.said)))
    def proof(node):
        return messagize(node, tsgs=[(issuer.kever.prefixer,
            Number(num=issuer.kever.lastEst.s), Diger(qb64=issuer.kever.lastEst.d),
            issuer.sign(node.raw))], gvrsn=Vrsn_2_0)
    exc = Exchanger(hby, handlers=[])
    policy = Policy()
    verification = loadHandlers(hby, exc, Notices(), rgy=rgy, graphPolicy=policy)
    incoming, atc = grant(issuer, group.pre, 'held with explicit policy', origin=proof(near),
        artifacts=[proof(far)], modifiers=dict(dp=[[near.schema['$id'], '/', []],
                                                   [far.schema['$id'], '/e/proof/_/', []]]))
    parser = Parser(kvy=hby.kvy, exc=exc, version=Vrsn_2_0)
    parser.parse(ims=bytearray(incoming.raw + atc))
    assert exc.complete(incoming.said)
    reply, _ = admit(group, 'explicit prior consent', incoming)
    parser.parse(ims=messagize(reply, tsgs=[(group.kever.prefixer,
        Number(num=group.kever.lastEst.s), Diger(qb64=group.kever.lastEst.d),
        [member.sign(reply.raw)[0] for member in groups[:2]])], gvrsn=Vrsn_2_0))
    assert exc.complete(reply.said)
    wallet = Wallet(hby, rgy, exc=exc, verification=verification)
    try:
        wallet.verification.validateAdmission(incoming.said, reply.said, consent=True)
        plan = [[near.schema['$id'], '/', []], [far.schema['$id'], '/e/proof/_/', []]]
        request, ratc = apply(groups[1].mhab, group.pre, 'exact graph request', modifiers=dict(dp=plan))
        parser.parse(ims=bytearray(request.raw + ratc))
        assert exc.complete(request.said)
        candidate, catc = grant(group, groups[1].mhab.pre, 'imported candidate',
            origin=proof(near), artifacts=[proof(far)], apply=request)
        calls = []
        target = groups[1] if boundary == 'approval' else group
        sign = target.sign
        def observed(*args, **kwa):
            calls.append(True)
            return sign(*args, **kwa)
        monkeypatch.setattr(target, 'sign', observed)
        if boundary == 'approval':
            error = None
            try:
                owners[1].approveExchange(candidate.raw + catc)
            except ValidationError as ex:
                error = ex
            assert calls == []
            assert error is not None and 'graph' in str(error)
            return
        @contextmanager
        def opened(args, **kwa):
            yield hby, rgy, wallet
        monkeypatch.setattr(acdc_v2_ipex.acdc_v2, 'opened', opened)
        completed = []
        if boundary == 'completion':
            # Keep the real Peer, but explicitly select this application's policy.
            peerType = acdc_v2_ipex.Peer
            monkeypatch.setattr(acdc_v2_ipex, 'Peer',
                lambda *args, **kwa: peerType(*args, graphPolicy=policy, **kwa))
            builder = acdc_v2_ipex.ipexing.grant
            selected = []
            def built(*args, **kwa):
                result = builder(*args, **kwa)
                selected.append(result)
                return result
            monkeypatch.setattr(acdc_v2_ipex.ipexing, 'grant', built)
            process = AcdcV2GroupCoordinator.process
            def finish(owner):
                process(owner)
                if selected and proposal.exists() and not completed:
                    exn, atc = selected[0]
                    completed.append(exn.said)  # guard cooperative receive/process recursion
                    from keri.acdc.ipexing import AcdcV2IpexVerification
                    handler = owners[1].exc.routes['/ipex/grant']
                    handler.graphPolicy = policy
                    handler.verification = AcdcV2IpexVerification(hbys[1], rgys[1], graphPolicy=policy)
                    owners[1].receive(request.raw + ratc)
                    owners[1].receive(proposal.read_bytes())
                    second, attachments = owners[1].approveExchange(exn.raw + atc)
                    owner.receive(second.raw + attachments)
                    from keri.peer.exchanging import serializeMessage
                    owner.receive(serializeMessage(hbys[1], exn.said))
                    assert owner.completeExchange(exn.said)
                    policy.permitted = False
            monkeypatch.setattr(AcdcV2GroupCoordinator, 'process', finish)
        proposal, output = tmp_path / 'proposal.cesr', tmp_path / 'usable.cesr'
        priorInput = tmp_path / 'apply.cesr'
        priorInput.write_bytes(request.raw + ratc)
        args = arguments.parse_args(['--acdc-v2', '--name', hby.name, '--base', hby.base,
            '-a', 'group', '-r', groups[1].mhab.pre, '-s', near.said, '--prior', request.said,
            '--from-grant', incoming.said, '--input', str(priorInput), '--proposal-output', str(proposal),
            '--output', str(output), '--timeout', '0.05'])
        error = None
        try:
            doing.Doist(tock=0.01, real=False, limit=0.1).do(
                doers=[acdc_v2_ipex.ExchangeDoer(args, 'grant')])
        except (ConfigurationError, ValidationError, TimeoutError) as ex:
            error = ex
        if boundary == 'completion':
            assert completed and calls  # real threshold acceptance precedes changed policy
        else:
            assert calls == []
            assert not proposal.exists()
        assert error is not None and 'graph' in str(error)
        assert not output.exists()
    finally:
        wallet.close()


def memberAids(groups):
    """Return the fixture's explicit trusted local member order."""
    return [group.mhab.pre for group in groups]


def rotateMembers(hbys, groups):
    """Accept each member's independent rotation in every peer's local KEL."""
    messages = [group.mhab.rotate(version=Vrsn_2_0, gvrsn=Vrsn_2_0) for group in groups]
    for hby in hbys:
        for message in messages:
            Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(message), local=True)


def groupRotation(hby, group, smids):
    """Build a group rotation using supplied trusted member order and new keys."""
    return eventing.rotate(pre=group.pre, sn=group.kever.sn + 1,
        dig=group.kever.serder.said, isith='2', nsith='2',
        keys=[hby.kevers[aid].verfers[0].qb64 for aid in smids],
        ndigs=[hby.kevers[aid].ndigers[0].qb64 for aid in smids], version=Vrsn_2_0)
