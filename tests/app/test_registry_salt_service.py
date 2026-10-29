"""Authenticated live salt establishment and explicit same-root provisioning."""

from base64 import b64encode
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, replace
from pathlib import Path
from time import time
from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0
from keri.acdc import Registrar
from keri.acdc.regeventing import Rever
from keri.app import registry_salt_replies as replies
from keri.app.credentialing import Wallet, WalletBaser
from keri.app.evidencing import ServiceConfig
from keri.app.registry_custody import RegistryCustody
from keri.app.registry_salt_service import RegistrySaltService
from keri.app.registry_salt_state import RegistrySaltState
from keri.core import Diger, Encrypter, Kevery, Kramer, Parser, Revery, Salter, Signer, Texter, reply
from keri.kering import AuthError, ConfigurationError, Kinds, UnverifiedReplyError, ValidationError
from keri.peer.exchanging import serializeParsedSubstream
from keri.app.replying import parseReply
from tests.app.test_acdc_v2_wallet import encrypted, regery, anchored
from tests.app.test_acdc_v2_groups import Notices


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
        services = []
        for hby, rgy in zip(hbys, rgys):
            db = WalletBaser(name=hby.name, headDirPath=str(tmp_path))
            stack.callback(db.close)
            custody = RegistryCustody(hby, rgy, db=db)
            wallet = Wallet(hby, rgy, db=db, custody=custody)
            rvy = Revery(db=hby.db)
            kvy = Kevery(db=hby.db, rvy=rvy,
                kramer=Kramer(db=hby.db, cf=ServiceConfig()), lax=False, local=False)
            kvy.registerReplyRoutes(rvy.rtr)
            parser = Parser(kvy=kvy, rvy=rvy, version=Vrsn_2_0)
            service = RegistrySaltService(hby, rgy, wallet, custody, RegistrySaltState(custody), parser, rvy)
            service.register()
            for hab in habs:
                service.trustRoster(hab.pre, [hab.pre])
            services.append(service)
        yield SimpleNamespace(hbys=hbys, habs=habs, services=services, rip=rip)


@contextmanager
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
            custody = RegistryCustody(hby, rgy, db=db)
            wallet = Wallet(hby, rgy, db=db, custody=custody)
            if index < 3:
                parser, rvy = owners[index].parser, owners[index].mux.rvy
                # The existing coordinator originally needed EXN/TEL only.
                # Reply service composition explicitly shares its Revery too.
                parser.rvy = rvy
                owners[index].mailbox.parser.rvy = rvy
                extra = dict(exc=owners[index].exc, mux=owners[index].mux)
            else:
                rvy = Revery(db=hby.db)
                kvy = Kevery(db=hby.db, rvy=rvy,
                    kramer=Kramer(db=hby.db, cf=ServiceConfig()), lax=False, local=False)
                kvy.registerReplyRoutes(rvy.rtr)
                parser, extra = Parser(kvy=kvy, rvy=rvy, version=Vrsn_2_0), {}
            service = RegistrySaltService(hby, rgy, wallet, custody, RegistrySaltState(custody), parser, rvy, **extra)
            service.register()
            service.trustRoster(groups[0].pre, [group.mhab.pre for group in groups])
            service.trustRoster(discloser.pre, [discloser.pre])
            services.append(service)
        yield SimpleNamespace(members=members, hbys=hbys, groups=groups, rgys=rgys,
            owners=owners, services=services, discloser=discloser, rip=rip, habs=people)


def groupInitiate(case):
    """Reach real init quorum through exact member wrappers, never a representative-only signature."""
    first, second = case.services[:2]
    init = first.prepareInit(issuer=case.groups[0].pre, discloser=case.discloser.pre,
        party=case.groups[0].pre, representative=case.groups[0].mhab.pre)
    proposed = first.approveReply(init)
    case.owners[1].receive(proposed.proposal.raw + proposed.attachments)
    body = second.inspectProposal(proposed.proposal.said)
    approved = second.approveReply(body, proposal=proposed.proposal.said)
    case.owners[0].receive(approved.proposal.raw + approved.attachments)
    assert first.state.proof(init.said) and second.state.proof(init.said)
    return init


def groupBound(case):
    """Authenticate both original statements on each group peer without new local DH."""
    init = groupInitiate(case)
    single = case.services[3]
    single.receive(case.services[0].state.proof(init.said))
    bind = single.prepareBind(init.said, case.rip.said, case.discloser.pre)
    outgoing = single.approveReply(bind)
    for service in case.services[:3]:
        if service.state.proof(init.said) is None:
            service.receive(case.services[0].state.proof(init.said))
        service.receive(outgoing.stream)
    return init, bind


def groupEstablished(case):
    """Confirm with real group quorum while the second signer has no root or DH state."""
    init, bind = groupBound(case)
    first, second = case.services[:2]
    confirm = first.prepareConfirm(init.said, bind.said)
    proposed = first.approveReply(confirm)
    case.owners[1].receive(proposed.proposal.raw + proposed.attachments)
    exact = second.inspectProposal(proposed.proposal.said)
    assert second.custody.db.custody.get((case.rip.said,)) is None
    approved = second.approveReply(exact, proposal=proposed.proposal.said)
    assert second.custody.db.custody.get((case.rip.said,)) is None
    case.owners[0].receive(approved.proposal.raw + approved.attachments)
    case.services[3].receive(first.state.proof(confirm.said))
    return init, bind, confirm


def establish(case, starter=0):
    """Run two explicit local actions and issuer confirmation through live KRAM/Revery."""
    issuer, discloser = case.habs[:2]
    left, right = case.services[starter], case.services[1 - starter]
    init = left.prepareInit(issuer=issuer.pre, discloser=discloser.pre,
        party=case.habs[starter].pre, representative=case.habs[starter].pre)
    first = left.approveReply(init)
    right.receive(first.stream)
    bind = right.prepareBind(init.said, case.rip.said, case.habs[1 - starter].pre)
    second = right.approveReply(bind)
    left.receive(second.stream)
    confirm = case.services[0].prepareConfirm(init.said, bind.said)
    third = case.services[0].approveReply(confirm)
    case.services[1].receive(third.stream)
    return init, bind, confirm


def changed(body, **updates):
    """Construct an independently SAIDed altered public body using core.reply."""
    data = dict(body.sad['a'])
    data.update(updates)
    return reply(pre=body.pre, route=body.route, data=data, version=Vrsn_2_0,
                 gvrsn=Vrsn_2_0, kind=Kinds.json)


def assignedProvision(case):
    """Prepare a real same-root issuer assignment and durable member provision attempt."""
    _, _, confirm = establish(case)
    source = case.services[0]
    assignment = source.prepareAssign(confirm.said, case.habs[2].pre)
    source.approveReply(assignment)
    job = source.reconcile(case.rip.said, case.habs[2].pre)[0]
    body, signed, outer = source.prepareProvision(job, case.habs[0].pre)
    now = time()
    source.state.recordAttempt(job, body, signed, outer, body.sad['a']['recipientEst'], now, now + source.maxAge)
    return body, signed, assignment


def reopenedService(service):
    """Rebuild borrowed reply owners after reopening durable identity and wallet stores."""
    service.state.db.close()
    service.hby.db.close()
    service.hby.db.reopen()
    service.state.db.reopen()
    rvy = Revery(db=service.hby.db)
    kvy = Kevery(db=service.hby.db, rvy=rvy,
        kramer=Kramer(db=service.hby.db, cf=ServiceConfig()), lax=False, local=False)
    parser = Parser(kvy=kvy, rvy=rvy, version=Vrsn_2_0)
    result = RegistrySaltService(service.hby, service.rgy, service.wallet, service.custody,
        RegistrySaltState(service.custody), parser, rvy)
    result.register()
    return result


@pytest.mark.parametrize('starter', [0, 1])
def test_single_parties_establish_same_root_with_explicit_pending_recovery(network, starter):
    """Either party starts; exact pending keys survive retries and produce one immutable root."""
    case = network
    init, bind, confirm = establish(case, starter)
    roots = [service.custody._load(case.rip.said).salt for service in case.services[:2]]
    assert roots[0] == roots[1]
    for index, service in enumerate(case.services[:2]):
        assert service.state.origin(case.rip.said).confirm == confirm.said
        assert service.state.proof(init.said) and service.state.proof(bind.said)
        assert service.state.proof(confirm.said)
        assert [job.member for job in service.state.deliveryCandidates(time()).items] == [case.habs[1 - index].pre]


def test_incoming_request_never_creates_local_dh_or_approval(network):
    """Authenticated init reception alone cannot generate a bind, private key or root."""
    case = network
    issuer, discloser = case.habs[:2]
    first = case.services[0].prepareInit(issuer=issuer.pre, discloser=discloser.pre,
        party=issuer.pre, representative=issuer.pre)
    outbound = case.services[0].approveReply(first)
    case.services[1].receive(outbound.stream)
    assert case.services[1].state.proof(first.said)
    assert not case.services[1].state.hasPending(first.said, discloser.pre)
    assert case.services[1].state.origin(case.rip.said) is None
    assert case.services[1].custody.db.custody.get((case.rip.said,)) is None


def test_pending_and_confirmation_retry_keep_exact_bytes(network):
    """Recovery preserves both DH statements and the append-once confirmation identity."""
    case = network
    issuer, discloser = case.habs[:2]
    init = case.services[0].prepareInit(issuer=issuer.pre, discloser=discloser.pre,
        party=issuer.pre, representative=issuer.pre)
    assert case.services[0].resume(init.said, issuer.pre).raw == init.raw
    first = case.services[0].approveReply(init)
    case.services[1].receive(first.stream)
    bind = case.services[1].prepareBind(init.said, case.rip.said, discloser.pre)
    again = case.services[1].prepareBind(init.said, case.rip.said, discloser.pre, stamp='2026-01-01T00:00:00.000000+00:00')
    assert again.raw == bind.raw
    second = case.services[1].approveReply(bind)
    case.services[0].receive(second.stream)
    confirm = case.services[0].prepareConfirm(init.said, bind.said)
    case.services[0].state.db.close()
    case.services[0].state.db.reopen()
    assert case.services[0].prepareConfirm(init.said, bind.said).raw == confirm.raw


def test_lost_local_bind_private_state_never_generates_a_substitute(network, monkeypatch):
    """A retained signed bind is evidence of loss, not permission for another DH key."""
    from keri.app import registry_salts

    case = network
    issuer, discloser = case.habs[:2]
    first, second = case.services[:2]
    init = first.prepareInit(issuer=issuer.pre, discloser=discloser.pre,
        party=issuer.pre, representative=issuer.pre)
    second.receive(first.approveReply(init).stream)
    bind = second.prepareBind(init.said, case.rip.said, discloser.pre)
    second.approveReply(bind)
    assert second.state.db.saltPending.rem((init.said, discloser.pre))
    monkeypatch.setattr(registry_salts, 'generateKeypair', lambda: pytest.fail('replacement DH is forbidden'))
    with pytest.raises(ConfigurationError, match='private state is lost'):
        second.prepareBind(init.said, case.rip.said, discloser.pre)


def test_third_party_receives_original_root_only_after_issuer_assignment(network):
    """Fresh unsolicited provisioning admits a new party without changing original metadata."""
    case = network
    init, bind, confirm = establish(case)
    issuer, discloser, later = case.habs
    source, recipient = case.services[0], case.services[2]
    with pytest.raises(ValidationError, match='entitlement'):
        source.reconcile(case.rip.said, later.pre)
    assignment = source.prepareAssign(confirm.said, later.pre)
    approved = source.approveReply(assignment)
    jobs = source.reconcile(case.rip.said, later.pre)
    assert len(jobs) == 1
    provision, signed, outer = source.prepareProvision(jobs[0], issuer.pre)
    now = time()
    current = source.state.recordAttempt(jobs[0], provision, signed, outer,
        provision.sad['a']['recipientEst'], now, now + source.maxAge)
    assert current is not None
    reused, saved, envelope = source.prepareProvision(current, issuer.pre)
    assert (reused.raw, saved, envelope) == (provision.raw, signed, outer)
    recipient.receive(signed)
    assert recipient.state.receipt(provision.said) is not None
    assert recipient.custody._load(case.rip.said).salt == source.custody._load(case.rip.said).salt
    assert recipient.state.origin(case.rip.said).discloser == discloser.pre
    assert recipient.state.assignment(case.rip.said, later.pre) == assignment.said
    credential = Diger(ser=b'credential').qb64
    expected = source.custody.derive(case.rip.said, 1, credential, 'issued')
    assert recipient.custody.derive(case.rip.said, 1, credential, 'issued').qb64 == expected.qb64
    receipt, ack, sealed = recipient.prepareReceipt(provision.said)
    source.receive(ack)
    assert source.state.delivery(*jobs[0].key).state == 'confirmed'
    assert source.state.delivery(*jobs[0].key).receipt == receipt.said
    for service in case.services:
        stored = Path(service.custody.db.path, 'data.mdb').read_bytes()
        assert Salter(qb64=source.custody._load(case.rip.said).salt).raw not in stored
    assert all(source.custody._load(case.rip.said).salt.encode() not in body.raw
               for body in (init, bind, confirm, assignment, provision, receipt))


@pytest.mark.parametrize('fault', ['source', 'recipient-key', 'admission', 'wrong-root', 'wrong-recipient', 'archive-signature'])
def test_provision_authority_key_history_and_commitment_fail_closed(network, fault):
    """A fresh authenticated sender cannot override source membership, recipient or root evidence."""
    case = network
    provision, _, _ = assignedProvision(case)
    updates = {}
    if fault == 'source':
        updates['source'] = case.habs[2].pre
    elif fault == 'recipient-key':
        updates['recipientEst'] = dict(s='0', d=case.habs[0].kever.lastEst.d)
    elif fault == 'admission':
        updates['admission'] = dict(s='0', d=case.habs[0].kever.lastEst.d)
    elif fault == 'wrong-root':
        key = Encrypter(verkey=case.habs[2].kever.verfers[0].qb64)
        updates['cipher'] = key.encrypt(prim=Salter(raw=b'fedcba9876543210')).qb64
    elif fault == 'wrong-recipient':
        key = Encrypter(verkey=case.habs[1].kever.verfers[0].qb64)
        updates['cipher'] = case.services[0].custody.sealRoot(case.rip.said, key).qb64
    else:
        proofs = dict(provision.sad['a']['proofs'])
        frame = bytearray(Texter(qb64=proofs['confirm']).raw)
        frame[-5] = ord('A') if frame[-5] != ord('A') else ord('B')
        proofs['confirm'] = Texter(raw=bytes(frame)).qb64
        updates['proofs'] = proofs
    forged = changed(provision, **updates)
    stream = case.habs[0].endorse(forged, gvrsn=Vrsn_2_0)
    recipient = case.services[2]
    with pytest.raises((ValidationError, AuthError)):
        recipient.receive(stream)
    assert recipient.state.origin(case.rip.said) is None
    assert recipient.custody.db.custody.get((case.rip.said,)) is None
    assert recipient.state.receipt(forged.said) is None


def test_receipt_intent_and_root_roll_back_together(network, monkeypatch):
    """A real wallet transaction failure cannot leave custody, grants or an acknowledgement intent."""
    case = network
    provision, signed, _ = assignedProvision(case)
    recipient = case.services[2]
    original = recipient.custody.retainPrepared

    def failDuringTransaction(prepared, txn):
        """Abort after the root write while the actual transaction is still open."""
        original(prepared, txn)
        raise RuntimeError('wallet transaction failed')

    monkeypatch.setattr(recipient.custody, 'retainPrepared', failDuringTransaction)
    with pytest.raises(UnverifiedReplyError, match='pending retry'):
        recipient.receive(signed)
    assert recipient.custody.db.custody.get((case.rip.said,)) is None
    assert recipient.state.origin(case.rip.said) is None
    assert recipient.state.assignment(case.rip.said, case.habs[2].pre) is None
    assert recipient.state.receipt(provision.said) is None
    with pytest.raises(ConfigurationError, match='committed intent'):
        recipient.prepareReceipt(provision.said)
    assert recipient.hby.db.rpes.get((replies.PROVISION_ROUTE,))
    monkeypatch.setattr(recipient.custody, 'retainPrepared', original)
    recipient.process()
    assert recipient.state.receipt(provision.said) is not None
    assert recipient.state.origin(case.rip.said) is not None


def test_known_unreadable_root_cannot_bypass_confirmation_consistency(network, monkeypatch):
    """Present locked/corrupt custody fails instead of being treated as a rootless co-signer."""
    _, _, confirm = establish(network)
    service = network.services[0]

    def locked(_):
        """Represent an existing private record whose authentication is unavailable."""
        raise AuthError('custody is locked')

    monkeypatch.setattr(service.custody, '_load', locked)
    with pytest.raises(AuthError, match='locked'):
        service.approveReply(confirm)


def test_reconciliation_queues_public_work_with_old_aeid_but_never_sends(network):
    """Unavailable root decryption blocks a delivery, not independent accepted-roster work."""
    establish(network)
    service = network.services[0]
    replacement = Signer(transferable=False)
    service.hby.mgr.updateAeid(replacement.verfer.qb64, replacement.qb64)
    jobs = service.reconcile(network.rip.said, network.habs[1].pre)
    assert len(jobs) == 1 and jobs[0].attempts == 0
    with pytest.raises(AuthError, match='AEID changed'):
        service.prepareProvision(jobs[0], network.habs[0].pre)
    assert service.state.currentAttempt(jobs[0].key) is None


def test_live_msgprocess_keeps_kram_freshness_and_deny_policy(network):
    """Direct MsgProcess and service intake both preserve the borrowed live policy."""
    case = network
    issuer, discloser = case.habs[:2]
    source, target = case.services[:2]
    old = source.prepareInit(issuer=issuer.pre, discloser=discloser.pre,
        party=issuer.pre, representative=issuer.pre, stamp='2020-01-01T00:00:00.000000+00:00')
    with pytest.raises(ConfigurationError, match='live KRAM window'):
        source.approveReply(old)
    stale = bytes(issuer.endorse(old, gvrsn=Vrsn_2_0))
    parsed = parseReply(target.parser, stale, {replies.INIT_ROUTE})
    target.parser.msgProcess(asdict(parsed), kvy=target.parser.kvy,
        tvy=None, exc=None, rvy=target.rvy, vry=None)
    assert target.state.proof(old.said) is None
    fresh = source.prepareInit(issuer=issuer.pre, discloser=discloser.pre,
        party=issuer.pre, representative=issuer.pre)
    outgoing = source.approveReply(fresh)
    target.parser.kvy.denyList = [issuer.pre]
    target.receive(outgoing.stream)
    assert target.state.proof(fresh.said) is None
    assert not target.state.hasPending(fresh.said, discloser.pre)


def test_archival_import_survives_rotation_and_pruning_without_live_side_effects(network):
    """Historical proof verification neither needs current representatives nor dispatches old replies."""
    case = network
    init, bind, confirm = establish(case)
    source, target = case.services[0], case.services[2]
    frames = [source.state.proof(body.said) for body in (init, bind, confirm)]
    for hab in case.habs[:2]:
        message = hab.rotate(version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        Parser(kvy=target.hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(message), local=True)
    before = list(target.hby.db.kramMSGC.getTopItemIter())
    for frame, body in zip(frames, (init, bind, confirm)):
        assert target.importProof(frame).raw == body.raw
        assert target.hby.db.rpys.get((body.said,)) is None
    assert list(target.hby.db.kramMSGC.getTopItemIter()) == before
    assert target.state.origin(case.rip.said) is None
    assert target.custody.db.custody.get((case.rip.said,)) is None


def test_confirm_before_dependencies_recovers_after_reopen_without_kram_redrive(network):
    """A live-admitted confirmation survives missing exact statements and an owner restart."""
    case = network
    init, bind, confirm = establish(case)
    source, target = case.services[0], case.services[2]
    with pytest.raises(UnverifiedReplyError, match='waiting'):
        target.receive(source.state.proof(confirm.said))
    assert target.state.proof(confirm.said) is None
    cached = target.hby.db.kramMSGC.get((confirm.pre, confirm.said))
    assert cached is not None and target.hby.db.rpes.get((replies.CONFIRM_ROUTE,))
    target = reopenedService(target)
    target.importProof(source.state.proof(init.said))
    target.importProof(source.state.proof(bind.said))
    target.process()
    assert target.state.proof(confirm.said)
    assert target.hby.db.kramMSGC.get((confirm.pre, confirm.said)) == cached
    assert not target.hby.db.rpes.get((replies.CONFIRM_ROUTE,))
    assert target.state.origin(case.rip.said) is None  # no local initial action


def test_provision_before_accepted_rip_recovers_after_reopen(network):
    """Encrypted authenticated work remains durable until real accepted registry evidence arrives."""
    case = network
    provision, signed, _ = assignedProvision(case)
    recipient = case.services[2]
    # This test-owned recipient starts with no registry prefix while retaining
    # the issuer's accepted KEL anchor, exactly as an offline recipient can.
    baser = recipient.rgy.baser
    assert baser.tels.rem(keys=case.rip.said, on=0)
    for table in (baser.heads, baser.supported, baser.ancs, baser.evts):
        table.rem(keys=case.rip.said)
    with pytest.raises(UnverifiedReplyError, match='waiting'):
        recipient.receive(signed)
    assert recipient.custody.db.custody.get((case.rip.said,)) is None
    recipient = reopenedService(recipient)
    Rever(db=recipient.hby.db, reger=recipient.rgy.baser).processEvent(case.rip)
    assert recipient.rgy.store.seqEvent(case.rip.said, 0).said == case.rip.said
    recipient.process()
    assert recipient.state.origin(case.rip.said)
    assert recipient.state.receipt(provision.said)


@pytest.mark.parametrize('network', [False], indirect=True)
def test_nontransferable_bind_dependency_uses_normal_reply_escrow(network):
    """Cigar-authenticated live work survives dependency delay with the same borrowed Revery."""
    case = network
    init, bind, _ = establish(case)
    source, target = case.services[1], case.services[2]
    with pytest.raises(UnverifiedReplyError, match='waiting'):
        target.receive(source.state.proof(bind.said))
    target = reopenedService(target)
    cached = target.hby.db.kramMSGC.get((bind.pre, bind.said))
    target.importProof(case.services[0].state.proof(init.said))
    target.process()
    assert target.state.proof(bind.said)
    assert target.hby.db.kramMSGC.get((bind.pre, bind.said)) == cached
    assert not target.hby.db.rpes.get((replies.BIND_ROUTE,))


def test_group_confirmation_needs_no_root_on_nonrepresentative_signer(tmp_path):
    """Existing threshold reply approval works before encrypted replication to the co-signer."""
    with groupServiceNetwork(tmp_path) as case:
        _, _, confirm = groupEstablished(case)
        first, second = case.services[:2]
        assert first.state.origin(case.rip.said).confirm == confirm.said
        assert second.state.origin(case.rip.said) is None
        jobs = first.reconcile(case.rip.said, case.groups[0].pre)
        job = next(job for job in jobs if job.member == case.groups[1].mhab.pre)
        provision, signed, _ = first.prepareProvision(job, case.groups[0].pre)
        second.receive(signed)
        assert second.state.origin(case.rip.said).confirm == confirm.said
        assert second.custody._load(case.rip.said).salt == first.custody._load(case.rip.said).salt
        assert second.state.receipt(provision.said) is not None


def test_group_separate_signature_packets_archive_the_accepted_aggregate(tmp_path):
    """A final packet with only one contribution still archives the verified threshold proof."""
    from keri.app.registry_salt_proofs import verifyArchivedReply

    with groupServiceNetwork(tmp_path) as case:
        first, second = case.services[:2]
        init = first.prepareInit(issuer=case.groups[0].pre, discloser=case.discloser.pre,
            party=case.groups[0].pre, representative=case.groups[0].mhab.pre)
        proposed = first.approveReply(init)
        assert first.state.proof(init.said) is None
        case.owners[1].receive(proposed.proposal.raw + proposed.attachments)
        second.approveReply(second.inspectProposal(proposed.proposal.said), proposal=proposed.proposal.said)
        final = bytes(case.groups[1].endorse(init, gvrsn=Vrsn_2_0))
        assert {siger.index for group in parseReply(first.parser, final, {init.route}).tsgs
                for siger in group[3]} == {1}
        first.receive(final)
        archived = first.state.proof(init.said)
        assert verifyArchivedReply(first.hby, first.parser, archived, init.route, init.pre).raw == init.raw
        assert {siger.index for group in parseReply(first.parser, archived, {init.route}).tsgs
                for siger in group[3]} == {0, 1}


def test_group_confirmation_requires_approved_representative_provenance(tmp_path):
    """A member's authenticated wrapper alone cannot invent the opaque DH commitment."""
    from keri.app.grouping import multisigRpyExn

    with groupServiceNetwork(tmp_path) as case:
        init, bind = groupBound(case)
        fabricated = replies.confirmReply(init, bind, case.rip, Salter(raw=b'fedcba9876543210'))
        wrapper, attachments = multisigRpyExn(case.groups[1],
            case.groups[1].endorse(fabricated, gvrsn=Vrsn_2_0))
        case.owners[2].receive(wrapper.raw + attachments)
        with pytest.raises(ValidationError, match='representative contribution'):
            case.services[2].inspectProposal(wrapper.said)
        assert case.services[2].state.origin(case.rip.said) is None
        assert not case.services[2].state.hasPending(init.said, case.groups[2].mhab.pre)


def test_unsupported_independent_member_key_does_not_stall_other_jobs(tmp_path):
    """A recipient's unsupported current key blocks only that target, not its unchanged group roster."""
    from keri.core import MtrDex

    with groupServiceNetwork(tmp_path) as case:
        groupEstablished(case)
        first = case.services[0]
        rotating = case.groups[2].mhab
        for _ in range(2):
            message = rotating.rotate(ncode=MtrDex.ECDSA_256r1_Seed, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
            Parser(kvy=first.hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(message), local=True)
        jobs = first.reconcileKnown(case.groups[0].pre)
        good = next(job for job in jobs if job.member == case.groups[1].mhab.pre)
        bad = next(job for job in jobs if job.member == rotating.pre)
        body, _, _ = first.prepareProvision(good, case.groups[0].pre)
        assert body.sad['a']['target'] == good.member
        with pytest.raises(ValidationError, match='single accepted Ed25519 key'):
            first.prepareProvision(bad, case.groups[0].pre)
        assert first.state.delivery(*good.key).attempts == 0
