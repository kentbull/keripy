"""Three independent groups retain one registry root across real member replacement."""

from contextlib import ExitStack, contextmanager
from time import time
from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0
from keri.acdc.messaging import blindate, regcept
from keri.acdc.regeventing import Rever, vetBlind
from keri.app import registry_salts
from keri.app.credentialing import Wallet, WalletBaser
from keri.app.essring import EssrReplyHandler
from keri.app.evidencing import ServiceConfig
from keri.app.grouping import Multiplexor, loadHandlers
from keri.app.registry_custody import RegistryCustody
from keri.app.registry_salt_replies import PROVISION_ROUTE, RECEIPT_ROUTE
from keri.app.registry_salt_service import RegistrySaltService
from keri.app.registry_salt_state import RegistrySaltState
from keri.core import Diger, Kramer, Parser, Signer, eventing, messagize
from keri.kering import ConfigurationError, ValidationError
from keri.peer import Exchanger
from tests.app.test_acdc_v2_groups import Notices
from tests.app.test_acdc_v2_wallet import encrypted, regery


def shareAcceptedKels(case):
    """Copy public accepted personal/group replays; pending candidates are never replayed."""
    active = [node for node in case.nodes if node.active]
    streams = [node.person.replay(gvrsn=Vrsn_2_0) for node in active]
    streams.extend(role.groups[1].replay(gvrsn=Vrsn_2_0) for role in case.roles.values())
    for node in active:
        for stream in streams:
            Parser(kvy=node.hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(stream), local=True)


def closeRegistry(rgy):
    """Close a borrowed fixture registry once, including departed representatives."""
    if rgy.store.opened:
        rgy.close()


def attachService(case, node):
    """Compose one caller-owned wallet and normal live pipeline for this actual member."""
    rgy = regery(node.hby, case.path)
    case.stack.callback(closeRegistry, rgy)
    db = WalletBaser(name=node.hby.name, headDirPath=str(case.path))
    case.stack.callback(db.close)
    custody = RegistryCustody(node.hby, rgy, db=db)
    wallet = Wallet(node.hby, rgy, db=db, custody=custody)
    exc = Exchanger(node.hby, handlers=[])
    mux = Multiplexor(node.hby, Notices(), exc=exc, rgy=Rever(db=node.hby.db, reger=rgy.baser))
    mux.kvy.kramer = Kramer(db=node.hby.db, cf=ServiceConfig())
    parser = Parser(kvy=mux.kvy, rvy=mux.rvy, exc=exc, rgy=mux.rgy, version=Vrsn_2_0)
    loadHandlers(exc, mux)
    service = RegistrySaltService(node.hby, rgy, wallet, custody,
        RegistrySaltState(custody), parser, mux.rvy, exc=exc, mux=mux)
    service.register()
    exc.addHandler(EssrReplyHandler(node.hby, node.person, parser, (PROVISION_ROUTE, RECEIPT_ROUTE)))
    node.rgy, node.service, node.parser = rgy, service, parser
    for role in case.roles.values():
        service.trustRoster(role.gid, role.members)
    for event in case.events:
        mux.rgy.processEvent(event)
        assert rgy.store.seqEvent(case.registry, int(event.sad['n'], 16)).said == event.said


def acceptedRegistryEvent(case, event):
    """Accept an exact registry event under a real current two-signature issuer KEL anchor."""
    issuer = case.roles['issuer']
    signers = issuer.groups[1:3]
    head = signers[0].kever
    anchor = eventing.interact(pre=issuer.gid, dig=head.serder.said, sn=head.sn + 1,
        data=[dict(i=case.registry, s=event.sad['n'], d=event.said)], version=Vrsn_2_0)
    signatures = [group.sign(anchor.raw)[0] for group in signers]
    stream = messagize(anchor, sigers=signatures, gvrsn=Vrsn_2_0)
    for node in case.nodes:
        if node.active:
            node.parser.parse(ims=bytearray(stream), local=True)
            node.service.mux.rgy.processEvent(event)
            assert node.rgy.store.seqEvent(case.registry, int(event.sad['n'], 16)).said == event.said
    case.events.append(event)


@contextmanager
def threeGroups(path):
    """Yield nine encrypted independent KERI members of three accepted 2-of-3 groups."""
    with ExitStack() as stack:
        case = SimpleNamespace(stack=stack, path=path, nodes=[], roles={}, events=[])
        for label in ('issuer', 'discloser', 'holder'):
            nodes = []
            for index in range(3):
                hby = stack.enter_context(encrypted(f'salt-groups-{label}-{index}', path,
                                                   Signer(transferable=False)))
                node = SimpleNamespace(hby=hby, person=hby.makeHab(name='member'), active=True)
                nodes.append(node)
                case.nodes.append(node)
            case.roles[label] = SimpleNamespace(nodes=nodes,
                members=[node.person.pre for node in nodes], groups=[])
        for node in case.nodes:
            for person in (peer.person for peer in case.nodes):
                Parser(kvy=node.hby.kvy, version=Vrsn_2_0).parse(
                    ims=bytearray(person.replay(gvrsn=Vrsn_2_0)), local=True)
        for role in case.roles.values():
            role.groups = [node.hby.makeGroupHab(group='group', mhab=node.person,
                smids=role.members, isith='2', nsith='2', version=Vrsn_2_0) for node in role.nodes]
            for node in case.nodes:
                for group in role.groups:
                    Parser(kvy=node.hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(
                        group.msgOwnInception(allowPartiallySigned=True, gvrsn=Vrsn_2_0)), local=True)
                node.hby.kvy.processEscrows()
            assert all(group.accepted for group in role.groups)
            role.gid = role.groups[0].pre
        case.rip = regcept(case.roles['issuer'].gid)
        case.registry = case.rip.said
        for node in case.nodes:
            attachService(case, node)
        acceptedRegistryEvent(case, case.rip)
        yield case


def quorum(case, role, body):
    """Approve one exact logical reply through existing member wrappers with only two signers."""
    first, second = role.nodes[:2]
    proposed = first.service.approveReply(body)
    second.parser.parse(ims=bytearray(proposed.proposal.raw + proposed.attachments), local=True)
    approved = second.service.approveReply(second.service.inspectProposal(proposed.proposal.said),
                                           proposal=proposed.proposal.said)
    first.parser.parse(ims=bytearray(approved.proposal.raw + approved.attachments), local=True)
    frame = first.service.state.proof(body.said)
    assert frame and second.service.state.proof(body.said)
    assert role.nodes[2].service.state.hasPending(body.said, role.nodes[2].person.pre) is False
    for node in case.nodes:
        if node.active:
            node.service.receive(frame)
    return frame


def provision(case, source, sourceRole, target, party):
    """Send durable exact ESSR provision/receipt frames between distinct actual members."""
    jobs = source.service.reconcile(case.registry, party.gid)
    job = next(job for job in jobs if job.member == target.person.pre)
    body, signed, outer = source.service.prepareProvision(job, sourceRole.gid)
    now = time()
    saved = source.service.state.recordAttempt(job, body, signed, outer,
        body.sad['a']['recipientEst'], now, now + source.service.maxAge)
    assert saved is not None
    target.parser.parse(ims=bytearray(outer), local=False)
    assert target.service.state.receipt(body.said) is not None
    receipt, acknowledgement, sealed = target.service.prepareReceipt(body.said)
    intent = target.service.state.receipt(body.said)
    parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(sealed), processive=False)[0]
    recipientEst = dict(s=parsed.serder.sad['q']['sn'], d=parsed.serder.sad['q']['dig'])
    now = time()
    retained = target.service.state.recordReceiptAttempt(intent, receipt, acknowledgement,
        sealed, recipientEst, now, now + target.service.maxAge)
    assert retained is not None
    source.parser.parse(ims=bytearray(sealed), local=False)
    assert source.service.state.delivery(*job.key).state == 'confirmed'
    target.service.state.markReceiptSent(retained)
    return body


def newcomer(case, label):
    """Create one encrypted individual with public evidence but no admission or root."""
    hby = case.stack.enter_context(encrypted(f'salt-groups-{label}-new', case.path,
                                            Signer(transferable=False)))
    node = SimpleNamespace(hby=hby, person=hby.makeHab(name='member'), active=True)
    case.nodes.append(node)
    shareAcceptedKels(case)
    attachService(case, node)
    return node


def replaceRepresentative(case, label):
    """Reject failed/pending admission, then admit a newcomer using two real dual-index signatures."""
    role = case.roles[label]
    first, second = role.nodes[1:3]
    joining = newcomer(case, label)
    for node in (first, second):
        message = node.person.rotate(version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        for peer in case.nodes:
            if peer.active:
                peer.parser.parse(ims=bytearray(message), local=True)
    proposed = [first.person.pre, second.person.pre, joining.person.pre]
    head = role.groups[1].kever
    oldCoordinate = (head.lastEst.s, head.lastEst.d)
    rotation = eventing.rotate(pre=role.gid, dig=head.serder.said, sn=head.sn + 1,
        isith='2', nsith='2', keys=[first.person.kever.verfers[0].qb64,
            second.person.kever.verfers[0].qb64, joining.person.kever.verfers[0].qb64],
        ndigs=[first.person.kever.ndigers[0].qb64, second.person.kever.ndigers[0].qb64,
               joining.person.kever.ndigers[0].qb64], version=Vrsn_2_0)
    partial = role.groups[1].rotate(smids=proposed, rmids=proposed,
                                    serder=rotation, gvrsn=Vrsn_2_0)
    assert first.hby.db.signingMembers(role.gid) == proposed
    assert (first.hby.kevers[role.gid].lastEst.s, first.hby.kevers[role.gid].lastEst.d) == oldCoordinate
    pending = first.service.reconcileKnown(role.gid)
    assert joining.person.pre not in [job.member for job in pending]
    assert first.service.roster(role.gid).digest == oldCoordinate[1]
    assert joining.service.custody.db.custody.get((case.registry,)) is None

    bad = eventing.rotate(pre=role.gid, dig=Diger(ser=b'wrong prior').qb64, sn=rotation.sn,
        isith='2', nsith='2', keys=rotation.sad['k'], ndigs=rotation.sad['n'], version=Vrsn_2_0)
    signatures = [group.sign(bad.raw, verfers=bad.verfers, rotated=True)[0]
                  for group in role.groups[1:3]]
    first.parser.parse(ims=messagize(bad, sigers=signatures, gvrsn=Vrsn_2_0), local=True)
    assert (first.hby.kevers[role.gid].lastEst.s, first.hby.kevers[role.gid].lastEst.d) == oldCoordinate
    assert joining.person.pre not in [job.member for job in first.service.reconcileKnown(role.gid)]
    assert joining.service.custody.db.custody.get((case.registry,)) is None

    remaining = role.groups[2].rotate(smids=proposed, rmids=proposed,
                                      serder=rotation, gvrsn=Vrsn_2_0)
    for node in case.nodes:
        if node.active:
            node.parser.parse(ims=bytearray(partial + remaining), local=True)
            node.service.parser.kvy.processEscrows()
            assert node.hby.kevers[role.gid].lastEst.d == rotation.said
    role.members = proposed
    for node in case.nodes:
        if node.active:
            node.service.trustRoster(role.gid, proposed)  # explicit trusted operator mapping
    joined = joining.hby.joinGroupHab(role.gid, 'group', joining.person, proposed, proposed)
    assert joined.accepted
    old = role.nodes[0]
    stale = next((job for job in first.service.state.deliveryCandidates(time(), limit=32)
                  if job.party == role.gid and job.member == old.person.pre), None)
    if stale is not None:
        with pytest.raises(ValidationError):
            first.service.prepareProvision(stale, role.gid)
    with pytest.raises(ConfigurationError, match='no local current source member'):
        old.service.prepareProvision(next(job for job in old.service.reconcile(case.registry, role.gid)
            if job.member == joining.person.pre), role.gid)
    old.active = False
    old.service.wallet.db.close()
    old.rgy.close()
    old.hby.close()
    return first, joining


@pytest.mark.parametrize('initiator', ['issuer', 'discloser'])
def test_three_group_root_lifecycle_after_each_original_representative_leaves(tmp_path, monkeypatch, initiator):
    """Keep one root through group/group DH, third-group assignment and three independent admissions."""
    with threeGroups(tmp_path) as case:
        issuer, discloser, holder = (case.roles[name] for name in ('issuer', 'discloser', 'holder'))
        left = case.roles[initiator]
        right = discloser if left is issuer else issuer
        init = left.nodes[0].service.prepareInit(issuer=issuer.gid, discloser=discloser.gid,
            party=left.gid, representative=left.nodes[0].person.pre)
        quorum(case, left, init)
        bind = right.nodes[0].service.prepareBind(init.said, case.registry, right.nodes[0].person.pre)
        quorum(case, right, bind)
        confirm = issuer.nodes[0].service.prepareConfirm(init.said, bind.said)
        quorum(case, issuer, confirm)
        assert issuer.nodes[1].service.custody.db.custody.get((case.registry,)) is None
        assert holder.nodes[0].service.state.origin(case.registry) is None
        with pytest.raises(ValidationError, match='entitlement'):
            issuer.nodes[0].service.reconcile(case.registry, holder.gid)
        assignment = issuer.nodes[0].service.prepareAssign(confirm.said, holder.gid)
        quorum(case, issuer, assignment)
        for role in (issuer, discloser, holder):
            for node in role.nodes:
                if node is not issuer.nodes[0]:
                    provision(case, issuer.nodes[0], issuer, node, role)
                origin = node.service.state.origin(case.registry)
                assert (origin.init, origin.bind, origin.confirm, origin.discloser) == (
                    init.said, bind.said, confirm.said, discloser.gid)
            # The third member never co-signed the DH/confirmation or grant.
            assert role.nodes[2].service.state.origin(case.registry) is not None
            assert not role.nodes[2].service.state.hasPending(init.said, role.nodes[2].person.pre)

        credential = Diger(ser=b'group lifecycle private credential').qb64
        original = issuer.nodes[0].service.custody.derive(case.registry, 1, credential, 'issued')
        historical = blindate(case.registry, case.rip.said, original.said, sn=1)
        acceptedRegistryEvent(case, historical)
        for node in case.nodes:
            opening = node.service.custody.derive(case.registry, 1, credential, 'issued')
            assert opening.qb64 == original.qb64
            assert vetBlind(opening, blid=historical.sad['b']) == (credential, 'issued')
        monkeypatch.setattr(registry_salts, 'generateKeypair',
                            lambda: pytest.fail('existing roots must not restart DH'))
        for label in ('issuer', 'discloser', 'holder'):
            source, joining = replaceRepresentative(case, label)
            role = case.roles[label]
            assert role.nodes[0].person.pre not in [member.aid for member in source.service.roster(role.gid).members]
            delivered = provision(case, source, role, joining, role)
            assert delivered.sad['a']['origin'] == confirm.said
            assert joining.service.state.origin(case.registry).discloser == discloser.gid
            opening = joining.service.custody.derive(case.registry, 1, credential, 'issued')
            assert opening.qb64 == original.qb64
            assert vetBlind(opening, blid=historical.sad['b']) == (credential, 'issued')
            ordinal = len(case.events)
            future = issuer.nodes[1].service.custody.derive(case.registry, ordinal, credential, 'revoked')
            event = blindate(case.registry, case.events[-1].said, future.said, sn=ordinal)
            acceptedRegistryEvent(case, event)
            derived = joining.service.custody.derive(case.registry, ordinal, credential, 'revoked')
            assert derived.qb64 == future.qb64
            assert vetBlind(derived, blid=event.sad['b']) == (credential, 'revoked')
            assert joining.service.state.origin(case.registry).confirm == confirm.said
