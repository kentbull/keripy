"""Three independent groups retain one registry root across real member replacement."""

from contextlib import ExitStack, contextmanager
from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0
from keri.acdc.messaging import blindate, regcept
from keri.acdc.regeventing import Rever, vetBlind
from keri.app.credentialing import WalletBaser
from keri.app.essring import EssrReplyHandler, envelope
from keri.app.evidencing import ServiceConfig
from keri.app.grouping import Multiplexor, loadHandlers, multisigRpyExn, replyProposal, endorseReply
from keri.app.registry_custody import RegistryCustody
from keri.app.registry_salt_service import RegistrySaltService, ROUTES
from keri.core import Diger, Kramer, Parser, Signer, eventing, messagize
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
    exc = Exchanger(node.hby, handlers=[])
    mux = Multiplexor(node.hby, Notices(), exc=exc, rgy=Rever(db=node.hby.db, reger=rgy.baser))
    mux.kvy.kramer = Kramer(db=node.hby.db, cf=ServiceConfig())
    parser = Parser(kvy=mux.kvy, rvy=mux.rvy, exc=exc, rgy=mux.rgy, version=Vrsn_2_0)
    loadHandlers(exc, mux)
    service = RegistrySaltService(node.hby, rgy, custody, mux.rvy)
    service.register()
    exc.addHandler(EssrReplyHandler(node.hby, node.person, parser, ROUTES))
    node.rgy, node.service, node.parser, node.mux, node.exc = rgy, service, parser, mux, exc
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
            node.mux.rgy.processEvent(event)
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
    """Use two current members' ordinary EXN proposals to sign the exact reply."""
    first, second = [node for node in role.nodes if node.active][:2]
    lead = first.hby.habByPre(role.gid)
    cohab = second.hby.habByPre(role.gid)
    signed = lead.endorse(body, gvrsn=Vrsn_2_0)
    wrapper, atc = multisigRpyExn(lead, signed)
    first.parser.parse(ims=bytearray(signed), local=True)
    for node in (first, second):
        node.parser.parse(ims=bytearray(wrapper.raw + atc), local=True)
    child = replyProposal(second.hby, second.exc, second.mux, wrapper.said,
        ghab=cohab, validate=second.service.validate)
    complete, approved, atc = endorseReply(second.hby, cohab, child,
        validate=second.service.validate)
    second.parser.parse(ims=bytearray(complete), local=True)
    for node in (second, first):
        node.parser.parse(ims=bytearray(approved.raw + atc), local=True)
        node.service.rvy.processEscrowReply()
    assert first.hby.db.rpys.get((body.said,)).raw == body.raw
    assert second.hby.db.rpys.get((body.said,)).raw == body.raw
    return complete


def provision(case, source, sourceRole, target, party):
    """Send one threshold-signed reply inside ordinary ESSR to the selected member."""
    hab = source.hby.habByPre(sourceRole.gid)
    body = source.service.makeReply(hab, case.registry, party.gid, target=target.person.pre)
    signed = quorum(case, sourceRole, body)
    outer = envelope(source.person, signed, target.person.pre,
        target.person.kever.verfers[0], version=Vrsn_2_0,
        establishment=(target.person.kever.lastEst.s, target.person.kever.lastEst.d))
    target.parser.parse(ims=bytearray(outer), local=False)
    assert target.hby.db.rpys.get((body.said,)).raw == body.raw
    assert target.service.custody._load(case.registry).salt == source.service.custody._load(case.registry).salt
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
    assert joining.service.custody.db.custody.get((case.registry,)) is None

    bad = eventing.rotate(pre=role.gid, dig=Diger(ser=b'wrong prior').qb64, sn=rotation.sn,
        isith='2', nsith='2', keys=rotation.sad['k'], ndigs=rotation.sad['n'], version=Vrsn_2_0)
    signatures = [group.sign(bad.raw, verfers=bad.verfers, rotated=True)[0]
                  for group in role.groups[1:3]]
    first.parser.parse(ims=messagize(bad, sigers=signatures, gvrsn=Vrsn_2_0), local=True)
    assert (first.hby.kevers[role.gid].lastEst.s, first.hby.kevers[role.gid].lastEst.d) == oldCoordinate
    assert joining.service.custody.db.custody.get((case.registry,)) is None

    remaining = role.groups[2].rotate(smids=proposed, rmids=proposed,
                                      serder=rotation, gvrsn=Vrsn_2_0)
    for node in case.nodes:
        if node.active:
            node.parser.parse(ims=bytearray(partial + remaining), local=True)
            node.parser.kvy.processEscrows()
            assert node.hby.kevers[role.gid].lastEst.d == rotation.said
    role.members = proposed
    joined = joining.hby.joinGroupHab(role.gid, 'group', joining.person, proposed, proposed)
    assert joined.accepted
    # Membership changes use ordinary GroupHab configuration. Former members may
    # retain their known salts; there is no revocation-of-knowledge claim.
    role.nodes[0].active = False
    role.nodes.append(joining)
    return first, joining


@pytest.mark.parametrize('firstRecipient', ['holder', 'discloser'])
def test_three_groups_keep_same_salt_after_each_original_lead_leaves(tmp_path, firstRecipient):
    """Nine independent members and three newcomers share roots through signed encrypted replies."""
    with threeGroups(tmp_path) as case:
        issuer = case.roles['issuer']
        source = issuer.nodes[0].service
        source.custody.createCustody(case.registry, issuer.gid)
        root = source.custody._load(case.registry).salt
        other = 'discloser' if firstRecipient == 'holder' else 'holder'
        for label in ('issuer', firstRecipient, other):
            role = case.roles[label]
            for node in role.nodes:
                if node is not issuer.nodes[0]:
                    provision(case, issuer.nodes[0], issuer, node, role)
                assert node.service.custody._load(case.registry).salt == root

        credential = Diger(ser=b'group lifecycle private credential').qb64
        original = source.custody.derive(case.registry, 1, credential, 'issued')
        historical = blindate(case.registry, case.rip.said, original.said, sn=1)
        acceptedRegistryEvent(case, historical)
        for node in case.nodes:
            opening = node.service.custody.derive(case.registry, 1, credential, 'issued')
            assert opening.qb64 == original.qb64
            assert vetBlind(opening, blid=historical.sad['b']) == (credential, 'issued')
        for label in ('issuer', 'discloser', 'holder'):
            source_node, joining = replaceRepresentative(case, label)
            role = case.roles[label]
            assert role.nodes[0].person.pre not in source_node.hby.habByPre(role.gid).smids
            assert joining.service.custody.db.custody.get((case.registry,)) is None
            provision(case, source_node, role, joining, role)
            assert joining.service.custody._load(case.registry).salt == root
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
