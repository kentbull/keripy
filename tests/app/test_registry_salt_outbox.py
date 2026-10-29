"""Feature-specific proof, grant and outbound recovery across actual wallet commits."""
from base64 import b64encode
from dataclasses import replace

import pytest

from keri import Vrsn_2_0
from keri.app import registry_salt_replies as replies, registry_salts
from keri.app.essring import envelope
from keri.app.registry_salt_state import SaltDelivery, SaltReceiptIntent
from keri.app.replying import parseReply
from keri.core import Diger, Encrypter, Parser, Revery
from keri.kering import ValidationError
from tests.app.test_registry_salt_state import negotiation, retainPending
from tests.app.test_registry_root_retention import roots


def signed(hab, body, *, framed=False):
    """Use actual explicit establishment signatures for one exact reply body."""
    return bytes(hab.endorse(body, last=False, framed=framed, gvrsn=Vrsn_2_0))


def provision(case, *, stamp=None):
    """Build a real signed root provision and ultimate-recipient envelope."""
    est = dict(s=f'{case.discloser.kever.lastEst.s:x}', d=case.discloser.kever.lastEst.d)
    proofs = replies.encodeProofs(signed(case.issuer, case.init), signed(case.discloser, case.bind),
                                  signed(case.issuer, case.confirm))
    cipher = Encrypter(verkey=case.discloser.kever.verfers[0].qb64).encrypt(prim=case.root)
    body = replies.provisionReply(case.confirm, sender=case.issuer.pre, source=case.issuer.pre,
        party=case.discloser.pre, target=case.discloser.pre, admission=est,
        recipientEst=est, cipher=cipher.qb64, proofs=proofs, stamp=stamp)
    frame = signed(case.issuer, body)
    packet = bytes(envelope(case.issuer, frame, case.discloser.pre,
        case.discloser.kever.verfers[0], version=Vrsn_2_0,
        establishment=(case.discloser.kever.lastEst.s, est['d'])))
    return body, frame, packet, est


def establish(case):
    """Retain the established root and two concrete initial-party operations."""
    case.state.retainEstablished(case.info, case.root, case.origin, case.jobs)
    return case.state.delivery(*case.jobs[1].key)


def test_first_full_proof_survives_revery_pruning_and_other_valid_frames(negotiation):
    """Archive original signed bytes once; ordinary BADA cleanup cannot lose them."""
    case = negotiation
    frame = signed(case.issuer, case.init)
    parsed = parseReply(Parser(version=Vrsn_2_0), frame, {replies.INIT_ROUTE})
    rvy = Revery(db=case.custody.hby.db, lax=True, local=True)
    old = Diger(qb64=case.init.said)
    assert rvy.acceptReply(case.init, old, replies.INIT_ROUTE, case.issuer.pre, tsgs=parsed.tsgs)
    assert case.state.retainProof(case.init, frame) == frame
    assert case.state.retainProof(case.init, signed(case.issuer, case.init, framed=True)) == frame
    public, _ = registry_salts.generateKeypair()
    newer = replies.initReply(sender=case.issuer.pre, issuer=case.issuer.pre,
        discloser=case.discloser.pre, rep=case.issuer.pre, est=case.init.sad['a']['est'], key=public.qb64)
    proof = parseReply(Parser(version=Vrsn_2_0), signed(case.issuer, newer), {replies.INIT_ROUTE})
    assert rvy.acceptReply(newer, Diger(qb64=newer.said), replies.INIT_ROUTE, case.issuer.pre,
                           osaider=old, tsgs=proof.tsgs)
    assert case.custody.hby.db.rpys.get((case.init.said,)) is None
    case.state.db.close()
    case.state.db.reopen()
    assert case.state.proof(case.init.said) == frame


def test_confirmation_draft_is_append_once_and_does_not_replace_pending_key(negotiation):
    """Crashing before group quorum must not fork confirmation timestamp/SAID."""
    case = negotiation
    retainPending(case)
    saved = case.state.retainConfirmationDraft(case.init.said, case.issuer.pre, case.confirm.raw)
    assert saved.private == case.private.qb64 and saved.body == case.init.raw
    assert retainPending(case) == saved
    case.state.db.close()
    case.state.db.reopen()
    assert case.state.openPending(case.init.said, case.issuer.pre).confirmation == case.confirm.raw
    changed = replies.confirmReply(case.init, case.bind,
        case.custody.rgy.store.seqEvent(case.info.registry, 0), case.root)
    with pytest.raises(ValidationError, match='different registry-salt confirmation draft'):
        case.state.retainConfirmationDraft(case.init.said, case.issuer.pre, changed.raw)
    with pytest.raises(ValidationError, match='pending confirmation differs'):
        case.state.retainEstablished(case.info, case.root, replace(case.origin, confirm=changed.said),
                                     pendingKey=(case.init.said, case.issuer.pre))
    assert case.state.db.custody.get((case.info.registry,)) is None


def test_later_grant_indexes_same_origin_and_queues_without_changing_discloser(negotiation):
    """Only an explicit issuer grant extends this root to another logical party."""
    case = negotiation
    other = case.custody.hby.makeHab(name='later party')
    grant = replies.assignReply(case.confirm, party=other.pre)
    frame = signed(case.issuer, grant)
    job = SaltDelivery(case.info.registry, other.pre, other.pre, other.kever.lastEst.d, grant.said)
    # Public authority may arrive before this wallet has the root.
    assert case.state.retainAssignment(case.origin, grant, frame) == grant.said
    assert case.state.assignment(case.info.registry, other.pre) == grant.said
    assert case.state.db.custody.get((case.info.registry,)) is None
    case.state.retainEstablished(case.info, case.root, case.origin, (job,), assignments=((grant, frame),))
    assert case.state.delivery(*job.key) == job
    assert case.state.origins() == (case.origin,)
    assert case.custody._load(case.info.registry).info['discloser'] == case.info.discloser
    changed = replies.assignReply(case.confirm, party=other.pre)
    with pytest.raises(ValidationError, match='different registry-salt assignment'):
        case.state.retainAssignment(case.origin, changed, signed(case.issuer, changed))
    assert case.state.assignment(case.info.registry, other.pre) == grant.said


def test_durable_unsent_attempt_launch_counts_and_late_receipt_cas(negotiation):
    """Exact envelopes survive restart and a late old receipt wins over retry callbacks."""
    case = negotiation
    job = establish(case)
    body, frame, packet, est = provision(case)
    prepared = case.state.recordAttempt(job, body, frame, packet, est, 100.0, 1000.0)
    assert prepared.retryAt == 0 and prepared.attempts == 0
    case.state.db.close()
    case.state.db.reopen()
    saved = case.state.currentAttempt(job.key)
    assert saved.signedBytes == frame and saved.essrBytes == packet
    assert saved.reply == body.said and saved.recipientEst == est
    waiting = case.state.markAttempt(prepared, 110.0, 120.0)
    assert waiting.attempts == 1 and waiting.retryAt == 120.0
    assert case.state.failAttempt(prepared, 111.0, 2.0) is None
    due = case.state.failAttempt(waiting, 121.0, 2.0)
    assert due.attempts == 1 and due.retryAt == 123.0
    newer, secondFrame, secondPacket, est = provision(case)
    retry = case.state.recordAttempt(due, newer, secondFrame, secondPacket, est, 123.0, 1000.0)
    assert retry.provision == newer.said and retry.attempts == 1 and retry.retryAt == 0
    assert case.state.attempt(body.said).signedBytes == frame
    receipt = replies.receiptReply(body, case.confirm)
    confirmed = case.state.confirmDelivery(job.key, body.said, receipt.said)
    assert confirmed.state == 'confirmed' and confirmed.receipt == receipt.said
    assert case.state.markAttempt(retry, 124.0, 130.0) is None
    assert case.state.failAttempt(retry, 124.0, 2.0) is None
    assert case.state.confirmDelivery(job.key, newer.said, Diger(ser=b'another receipt').qb64) == confirmed
    reconciled = case.state.queueDeliveries(case.info.registry, case.jobs)
    assert confirmed in reconciled
    with pytest.raises(ValidationError, match='no matching retained provision'):
        case.state.confirmDelivery(case.jobs[0].key, body.said, receipt.said)


def test_root_commit_receipt_intent_and_exact_ack_attempt_survive_restart(negotiation):
    """A crash after retaining root cannot lose the obligation to acknowledge it."""
    case = negotiation
    body, _, _, _ = provision(case)
    intent = SaltReceiptIntent(body.said, case.info.registry, case.discloser.pre,
        case.discloser.pre, case.discloser.kever.lastEst.d, case.issuer.pre,
        b64encode(body.raw).decode('ascii'))
    case.state.retainEstablished(case.info, case.root, case.origin, receiptIntent=intent)
    case.state.db.close()
    case.state.db.reopen()
    assert case.state.receiptCandidates(0) == [intent]
    assert case.state.receipt(body.said).bodyBytes == body.raw
    receipt = replies.receiptReply(body, case.confirm)
    frame = signed(case.discloser, receipt)
    est = dict(s=f'{case.issuer.kever.lastEst.s:x}', d=case.issuer.kever.lastEst.d)
    packet = bytes(envelope(case.discloser, frame, case.issuer.pre, case.issuer.kever.verfers[0],
        version=Vrsn_2_0, establishment=(case.issuer.kever.lastEst.s, est['d'])))
    prepared = case.state.recordReceiptAttempt(intent, receipt, frame, packet, est, 100.0, 1000.0)
    assert prepared.attempts == 0 and prepared.retryAt == 0
    launched = case.state.markReceiptAttempt(prepared, 101.0, 110.0)
    sent = case.state.markReceiptSent(launched)
    assert sent.state == 'sent' and sent.attempts == 1
    case.state.retainEstablished(case.info, case.root, case.origin, receiptIntent=intent)
    assert case.state.receipt(body.said) == sent
    assert case.state.receiptCandidates(1000.0) == []
    assert case.state.attempt(receipt.said).essrBytes == packet
    assert case.state.markReceiptSent(launched) is None


def test_receipt_conflict_rolls_back_root_grants_jobs_and_pending(negotiation):
    """The final intent guard rolls back preceding private/public transaction writes."""
    case = negotiation
    retainPending(case)
    body, _, _, _ = provision(case)
    intent = SaltReceiptIntent(body.said, case.info.registry, case.discloser.pre,
        case.discloser.pre, case.discloser.kever.lastEst.d, case.issuer.pre,
        b64encode(body.raw).decode('ascii'))
    # Simulate an existing conflicting intent, not a whole mocked transaction.
    conflict = replace(intent, source=case.discloser.pre)
    case.state.db.saltReceipts.put((intent.provision,), conflict)
    other = case.custody.hby.makeHab(name='grant rollback')
    grant = replies.assignReply(case.confirm, party=other.pre)
    with pytest.raises(ValidationError, match='different registry-salt receipt intent'):
        case.state.retainEstablished(case.info, case.root, case.origin, case.jobs,
            (case.init.said, case.issuer.pre), receiptIntent=intent,
            assignments=((grant, signed(case.issuer, grant)),))
    assert case.state.db.custody.get((case.info.registry,)) is None
    assert case.state.origin(case.info.registry) is None
    assert case.state.assignment(case.info.registry, other.pre) is None
    assert case.state.proof(grant.said) is None
    assert case.state.deliveryCandidates(0) == []
    assert case.state.hasPending(case.init.said, case.issuer.pre)
    assert case.state.receipt(intent.provision) == conflict


def test_volatile_candidate_cursor_advances_past_unready_first_rows(negotiation):
    """A bounded worker can reach later jobs without delaying unready members."""
    case = negotiation
    establish(case)
    first = case.state.deliveryCandidates(0, limit=1)[0]
    second = case.state.deliveryCandidates(0, limit=1, after=first.key)[0]
    assert second.key > first.key
    assert case.state.deliveryCandidates(0, limit=1, after=second.key) == []
    assert case.state.delivery(*first.key).retryAt == 0
    assert case.state.delivery(*first.key).attempts == 0
    for _ in range(2):
        body, _, _, _ = provision(case)
        intent = SaltReceiptIntent(body.said, case.info.registry, case.discloser.pre,
            case.discloser.pre, case.discloser.kever.lastEst.d, case.issuer.pre,
            b64encode(body.raw).decode('ascii'))
        case.state.retainEstablished(case.info, case.root, case.origin, receiptIntent=intent)
    one = case.state.receiptCandidates(0, limit=1)[0]
    two = case.state.receiptCandidates(0, limit=1, after=one.provision)[0]
    assert two.provision > one.provision
    assert case.state.receiptCandidates(0, limit=1, after=two.provision) == []
