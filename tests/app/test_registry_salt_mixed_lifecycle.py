"""Independent individual/group peers share one salt through ordinary encrypted replies."""
import pytest
from keri import Vrsn_2_0
from keri.acdc import Registrar
from keri.acdc.messaging import blindate
from keri.acdc.regeventing import Rever, vetBlind
from keri.app import GroupHab
from keri.app.essring import EssrReplyHandler, envelope
from keri.app.evidencing import ServiceConfig
from keri.app.registry_salt_service import ROUTES
from keri.core import Diger, Kevery, Kramer, Parser, eventing, messagize
from keri.peer import Exchanger
from tests.app.test_acdc_v2_wallet import anchored
from tests.app.test_registry_salt_direct import groupServiceNetwork


def signedReply(case, issuer, body):
    """Combine real individual or group endorsements; normal intake verifies threshold."""
    signers = case.groups[:2] if isinstance(issuer, GroupHab) else [issuer]
    signatures = []
    for signer in signers:
        parsed = Parser(version=Vrsn_2_0).parseOne(
            ims=bytearray(signer.endorse(body, gvrsn=Vrsn_2_0)), processive=False)
        signatures.extend(parsed.tsgs)
    return messagize(body, tsgs=signatures, gvrsn=Vrsn_2_0)


def acceptUpdate(case, issuer, event):
    """Accept the exact blinded commitment under the actual issuer's KEL threshold."""
    head = issuer.kever
    anchor = eventing.interact(pre=issuer.pre, dig=head.serder.said, sn=head.sn + 1,
        data=[dict(i=case.registry, s=event.sad['n'], d=event.said)], version=Vrsn_2_0)
    signatures = ([group.sign(anchor.raw)[0] for group in case.groups[:2]]
                  if isinstance(issuer, GroupHab) else issuer.sign(anchor.raw))
    stream = messagize(anchor, sigers=signatures, gvrsn=Vrsn_2_0)
    for service, parser in zip(case.services, case.parsers):
        parser.parse(ims=bytearray(stream), local=True)
        Rever(db=service.hby.db, reger=service.rgy.baser).processEvent(event)
        assert service.rgy.store.seqEvent(case.registry, event.sn).said == event.said


@pytest.mark.parametrize('groupedParty', ['issuer', 'discloser'])
def test_mixed_parties_share_encrypted_salt_and_open_same_history(groupServiceNetwork, groupedParty):
    """Both asymmetric directions preserve ciphertext, quorum and exact accepted openings."""
    case = groupServiceNetwork
    case.parsers = [owner.parser for owner in case.owners]
    single_service = case.services[3]
    exc = Exchanger(single_service.hby, handlers=[])
    kvy = Kevery(db=single_service.hby.db, rvy=single_service.rvy,
                 kramer=Kramer(db=single_service.hby.db, cf=ServiceConfig()))
    case.parsers.append(Parser(kvy=kvy, rvy=single_service.rvy, exc=exc, version=Vrsn_2_0))
    for service, person, parser in zip(case.services, case.habs, case.parsers):
        parser.exc.addHandler(EssrReplyHandler(service.hby, person, parser, ROUTES))
    issuer = case.groups[0] if groupedParty == 'issuer' else case.discloser
    source_index = 0 if groupedParty == 'issuer' else 3
    source = case.services[source_index]
    if groupedParty == 'discloser':
        registry = Registrar(rgy=source.rgy).makeRegistry('single-issuer', issuer.pre)
        case.rip = source.rgy.store.event(registry.regk)
        anchored(issuer, registry, case.rip)
        for service, parser in zip(case.services[:3], case.parsers[:3]):
            parser.parse(ims=issuer.replay(gvrsn=Vrsn_2_0), local=False)
            Rever(db=service.hby.db, reger=service.rgy.baser).processEvent(case.rip)
    case.registry = case.rip.said
    source.custody.createCustody(case.registry, issuer.pre)
    root = source.custody._load(case.registry).salt
    for index, (service, person, parser) in enumerate(zip(case.services, case.habs, case.parsers)):
        if index == source_index:
            continue
        recipient = case.groups[0].pre if index < 3 else case.discloser.pre
        body = source.makeReply(issuer, case.registry, recipient, target=person.pre)
        stream = signedReply(case, issuer, body)
        sender = issuer.mhab if isinstance(issuer, GroupHab) else issuer
        outer = envelope(sender, stream, person.pre, person.kever.verfers[0],
            version=Vrsn_2_0, establishment=(person.kever.lastEst.s, person.kever.lastEst.d))
        assert root.encode() not in body.raw + outer
        parser.parse(ims=bytearray(outer), local=False)
        assert service.hby.db.rpys.get((body.said,)).raw == body.raw
        assert service.custody._load(case.registry).salt == root
    credential = Diger(ser=b'mixed private credential').qb64
    prior = case.rip
    for ordinal, state in ((1, 'issued'), (2, 'revoked')):
        opening = source.custody.derive(case.registry, ordinal, credential, state)
        event = blindate(case.registry, prior.said, opening.said, sn=ordinal)
        acceptUpdate(case, issuer, event)
        for service in case.services:
            derived = service.custody.derive(case.registry, ordinal, credential, state)
            assert derived.qb64 == opening.qb64
            assert vetBlind(derived, blid=event.sad['b']) == (credential, state)
        prior = event
