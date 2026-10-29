"""Ordinary signed replies carry encrypted salts without assignment messages."""
from contextlib import ExitStack
from types import SimpleNamespace
import pytest
from keri import Vrsn_2_0
from keri.acdc import Registrar
from keri.acdc.regeventing import Rever
from keri.app.credentialing import Wallet, WalletBaser
from keri.app.evidencing import ServiceConfig
from keri.app.registry_custody import RegistryCustody
from keri.app.registry_salt_service import RegistrySaltService
from keri.core import Kevery, Kramer, Parser, Revery, Signer
from keri.kering import ValidationError, UnverifiedReplyError
from tests.app.test_acdc_v2_wallet import encrypted, regery, anchored

@pytest.fixture
def network(tmp_path, request):
    """Yield three independent encrypted identities with real accepted KEL/TEL evidence."""
    with ExitStack() as stack:
        hbys = [stack.enter_context(encrypted(f'salt-service-{n}', tmp_path, Signer(transferable=False)))
                for n in range(3)]
        habs = [hby.makeHab(name='party', transferable=(index != 1 or getattr(request, 'param', True)))
                for index, hby in enumerate(hbys)]
        rgys = [regery(hby, tmp_path) for hby in hbys]
        for rgy in rgys:
            stack.callback(rgy.close)
        registry = Registrar(rgy=rgys[0]).makeRegistry(name='salt', prefix=habs[0].pre)
        rip = rgys[0].store.event(registry.regk)
        anchored(habs[0], registry, rip)
        for hby in hbys:
            for hab in habs:
                Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(hab.replay()), local=True)
        for hby, rgy in zip(hbys[1:], rgys[1:]):
            Rever(db=hby.db, reger=rgy.baser).processEvent(rip)
            assert rgy.store.seqEvent(rip.said, 0).said == rip.said
        services, parsers = [], []
        for hby, rgy in zip(hbys, rgys):
            db = WalletBaser(name=hby.name, headDirPath=str(tmp_path))
            stack.callback(db.close)
            custody = RegistryCustody(hby, rgy)
            wallet = Wallet(hby, rgy, db=db, custody=custody)
            rvy = Revery(db=hby.db)
            kvy = Kevery(db=hby.db, rvy=rvy,
                kramer=Kramer(db=hby.db, cf=ServiceConfig()), lax=False, local=False)
            kvy.registerReplyRoutes(rvy.rtr)
            parser = Parser(kvy=kvy, rvy=rvy, version=Vrsn_2_0)
            service = RegistrySaltService(hby, rgy, custody, rvy)
            service.register()
            services.append(service)
            parsers.append(parser)
        yield SimpleNamespace(hbys=hbys, habs=habs, services=services, parsers=parsers, rip=rip)


def receive(service, wire):
    """Send an exact signed reply through the receiver's ordinary Revery."""
    parsed = Parser(version=Vrsn_2_0).parseOne(ims=bytearray(wire), processive=False)
    service.rvy.processReply(serder=parsed.serder, cigars=parsed.cigars, tsgs=parsed.tsgs)


def test_issuer_shares_salt_with_holder_through_signed_reply(network):
    """Authenticated encrypted delivery preserves derivation without further protocol messages."""
    c = network
    issuer, holder = c.services[:2]
    issuer.custody.createCustody(c.rip.said, c.habs[1].pre)
    body = issuer.makeReply(c.habs[0], c.rip.said, c.habs[1].pre)
    wire = c.habs[0].endorse(body, gvrsn=Vrsn_2_0)
    receive(holder, wire)
    assert holder.custody._load(c.rip.said).salt == issuer.custody._load(c.rip.said).salt
    receive(holder, wire)
    assert holder.custody._load(c.rip.said).salt == issuer.custody._load(c.rip.said).salt


def test_wrong_sender_or_recipient_cannot_install_salt(network):
    """Neither an unrelated signature nor delivery to another identity grants custody."""
    c = network
    issuer, holder, outsider = c.services
    issuer.custody.createCustody(c.rip.said, c.habs[1].pre)
    body = issuer.makeReply(c.habs[0], c.rip.said, c.habs[1].pre)
    with pytest.raises(UnverifiedReplyError):
        receive(holder, c.habs[2].endorse(body, gvrsn=Vrsn_2_0))
    with pytest.raises(ValidationError, match='another local recipient'):
        receive(outsider, c.habs[0].endorse(body, gvrsn=Vrsn_2_0))
    assert holder.custody.db.custody.get((c.rip.said,)) is None
    assert outsider.custody.db.custody.get((c.rip.said,)) is None


def test_cli_signed_reply_can_be_retained_by_author_and_received_by_holder(network):
    """CLI signs one encrypted reply; normal Revery retains signatures at either end."""
    from keri.cli.common.registry_salts import SaltDoer
    from keri.cli.commands.vc.registry.salt import parser
    from keri.db import fetchTsgs
    from keri.core import Diger

    c = network
    issuer, holder = c.services[:2]
    issuer.custody.createCustody(c.rip.said, c.habs[1].pre)
    args = parser.parse_args(['send', '--name', 'issuer', '--alias', 'party',
                              '--registry', c.rip.said, '--party', c.habs[1].pre,
                              '--output', 'encrypted-reply.cesr'])
    doer = SaltDoer(args)
    peer = SimpleNamespace(service=issuer, hab=c.habs[0])
    wire, proposal, attachments = doer._reply(peer)
    assert proposal is None and attachments is None
    receive(issuer, wire)
    body = Parser(version=Vrsn_2_0).parseOne(ims=bytearray(wire), processive=False).serder
    signatures = list(fetchTsgs(db=issuer.hby.db.tsgs, diger=Diger(qb64=body.said)))
    assert signatures
    assert issuer.rvy.acceptReply(serder=body, saider=Diger(qb64=body.said),
                                  route=body.route, aid=body.pre, tsgs=signatures)
    receive(holder, wire)
    assert holder.custody._load(c.rip.said).salt == issuer.custody._load(c.rip.said).salt


from tests.app.test_acdc_v2_groups import Notices

@pytest.fixture
def groupServiceNetwork(tmp_path):
    """Yield a real encrypted 2-of-3 group and independent single discloser.

    Existing coordinators own each group's shared Parser/Revery/Multiplexor.
    The service borrows them; the caller-owned wallets close before identities.
    """
    with ExitStack() as stack:
        from keri.app.acdc_v2_grouping import AcdcV2GroupCoordinator
        from keri.peer import Exchanger

        hbys = [stack.enter_context(encrypted(f'salt-service-group-{n}', tmp_path,
            Signer(transferable=False))) for n in range(3)]
        people = [hby.makeHab(name='member') for hby in hbys]
        for hby in hbys:
            for person in people:
                Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(person.replay()), local=True)
        groups = [hby.makeGroupHab(group='group', mhab=person,
            smids=[member.pre for member in people], isith='2', nsith='2', version=Vrsn_2_0)
            for hby, person in zip(hbys, people)]
        for hby in hbys:
            for group in groups:
                Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(
                    group.msgOwnInception(allowPartiallySigned=True, gvrsn=Vrsn_2_0)), local=True)
            hby.kvy.processEscrows()
        assert all(group.accepted for group in groups)
        rgys = [regery(hby, tmp_path) for hby in hbys]
        for rgy in rgys:
            stack.callback(rgy.close)
        owners = [AcdcV2GroupCoordinator(hby, rgy, group, Exchanger(hby, handlers=[]), Notices())
                  for hby, rgy, group in zip(hbys, rgys, groups)]
        # This registry fixture also hosts replies. Borrow its existing Revery
        # explicitly, as the real SaltPeer and join command do.
        for owner in owners:
            owner.parser.rvy = owner.mux.rvy
            owner.mailbox.rvy = owner.mux.rvy
            owner.mailbox.parser.rvy = owner.mux.rvy
        members = list(hbys), groups, list(rgys), owners
        hby = stack.enter_context(encrypted('salt-service-discloser', tmp_path, Signer(transferable=False)))
        discloser = hby.makeHab(name='discloser')
        rgy = regery(hby, tmp_path)
        stack.callback(rgy.close)
        hbys.append(hby)
        rgys.append(rgy)
        people = [group.mhab for group in groups] + [discloser]
        for hby in hbys:
            for person in people:
                Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(person.replay()), local=True)
            Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(groups[0].replay()), local=True)
        from keri.acdc.messaging import regcept
        rip = regcept(groups[0].pre)
        first, atc = owners[0].approveRegistry(rip)
        event, anchor, _ = owners[1].registryProposal(first.raw + atc)
        second, atc = owners[1].approveRegistry(event, anchor)
        owners[0].receive(second.raw + atc)
        for hby, rgy in zip(hbys, rgys):
            Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(groups[0].replay()), local=True)
            Rever(db=hby.db, reger=rgy.baser).processEvent(rip)
            assert rgy.store.seqEvent(rip.said, 0).said == rip.said
        services = []
        for index, (hby, rgy) in enumerate(zip(hbys, rgys)):
            db = WalletBaser(name=hby.name, headDirPath=str(tmp_path))
            stack.callback(db.close)
            custody = RegistryCustody(hby, rgy)
            rvy = owners[index].mux.rvy if index < 3 else Revery(db=hby.db)
            service = RegistrySaltService(hby, rgy, custody, rvy)
            service.register()
            services.append(service)
        yield SimpleNamespace(members=members, hbys=hbys, groups=groups, rgys=rgys,
            owners=owners, services=services, discloser=discloser, rip=rip, habs=people)



def test_group_reply_uses_normal_partial_signature_escrow(groupServiceNetwork):
    """Two signatures satisfy 2-of-3 without requiring third-member approval."""
    c = groupServiceNetwork
    issuer, receiver = c.services[0], c.services[3]
    issuer.custody.createCustody(c.rip.said, c.discloser.pre)
    body = issuer.makeReply(c.groups[0], c.rip.said, c.discloser.pre)
    with pytest.raises(UnverifiedReplyError):
        receive(receiver, c.groups[0].endorse(body, gvrsn=Vrsn_2_0))
    assert receiver.custody.db.custody.get((c.rip.said,)) is None
    receive(receiver, c.groups[1].endorse(body, gvrsn=Vrsn_2_0))
    assert receiver.custody._load(c.rip.said).salt == issuer.custody._load(c.rip.said).salt


@pytest.mark.parametrize('kind', ['rip', 'bup'])
def test_registry_proposal_carries_encrypted_salt_separately_from_opening(groupServiceNetwork, kind):
    """Signed proposal ciphertext does not become public TEL opening material."""
    from keri.acdc.messaging import regcept, blindate
    from keri.core import Blinder, Encrypter, Salter
    c = groupServiceNetwork
    salt = Salter()
    copies = c.services[0].custody.sealMembers(c.groups[0], salt)
    opening = Blinder.blind(sn=1, acdc='', state='') if kind == 'bup' else None
    event = (blindate(c.rip.said, c.rip.said, opening.said) if opening is not None
             else regcept(c.groups[0].pre))
    first, attachments = c.owners[0].approveRegistry(event, salts=copies)
    assert first.sad['a']['salts'] == copies
    assert salt.qb64.encode() not in first.raw + attachments
    proposed, anchor, disclosed = c.owners[1].registryProposal(first.raw + attachments)
    assert proposed.said == event.said and disclosed is None
    second, attachments = c.owners[1].approveRegistry(proposed, anchor, salts=copies)
    c.owners[0].receive(second.raw + attachments)
    regid = event.said if kind == 'rip' else c.rip.said
    assert c.rgys[0].store.headEvent(regid).said == event.said
    assert second.sad['a']['salts'] == copies
    for service, group in zip(c.services[:2], c.groups[:2]):
        service.custody.retainMemberCopy(regid, group, copies)
        assert service.custody._load(regid).salt == salt.qb64
        service.custody.retainMemberCopy(regid, group, copies)
    # A different proposal cannot silently replace a salt already retained here.
    competing = c.services[0].custody.sealMembers(c.groups[0], Salter())
    with pytest.raises(ValidationError, match='different registry custody'):
        c.services[1].custody.retainMemberCopy(regid, c.groups[1], competing)


def test_invalid_salt_copy_is_rejected_before_group_anchor_signing(groupServiceNetwork):
    """A malformed cipher cannot cause a partial KEL event as a side effect."""
    from keri.acdc.messaging import regcept
    c = groupServiceNetwork
    before = c.groups[0].kever.sn
    event = regcept(c.groups[0].pre)
    with pytest.raises(ValidationError, match='exact encrypted salt'):
        c.owners[0].approveRegistry(event, salts={c.groups[1].mhab.pre: 'not-ciphertext'})
    assert c.groups[0].kever.sn == before
    assert c.hbys[0].db.pses.getLast(keys=c.groups[0].pre, on=before + 1) is None


def test_join_retains_member_salt_after_real_registry_quorum(groupServiceNetwork, unused_tcp_port_factory):
    """The existing join path approves the anchor and retains only its member copy."""
    from keri.acdc.messaging import regcept
    from keri.core import Salter
    from tests.app.test_acdc_v2_groups import groupNetwork
    from tests.cli.commands.multisig.test_join_v2 import joining, drive

    c = groupServiceNetwork
    root = Salter()
    copies = c.services[0].custody.sealMembers(c.groups[0], root)
    event = regcept(c.groups[0].pre)
    first, attachments = c.owners[0].approveRegistry(event, salts=copies)
    with joining(c.members) as (command, clock), groupNetwork(c.members, unused_tcp_port_factory) as (until, _):
        c.owners[1].receive(first.raw + attachments)
        assert c.services[1].custody.db.custody.get((event.said,)) is None
        result = drive(command, clock, command.registry(dict(r=first.route, d=first.said)), until)
        assert result is True
        assert c.rgys[1].store.seqEvent(event.said, 0).said == event.said
        assert c.services[1].custody._load(event.said).salt == root.qb64
