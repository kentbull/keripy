"""Real finite HTTP delivery, restart recovery and authenticated custody receipts."""

from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import time
from types import SimpleNamespace

import pytest
from hio.base import doing
from hio.core import tcp

from keri import Vrsn_2_0
from keri.app import openHby, registry_salt_replies as replies, registry_salts
from keri.app.credentialing import Wallet
from keri.app.evidencing import ServiceConfig
from keri.app.registry_salt_delivery import RegistrySaltDelivery, SaltTransportAttempt
from keri.app.registry_salt_service import RegistrySaltService
from keri.app.registry_salt_state import RegistrySaltState, SaltDelivery, SaltOrigin
from keri.core import Encrypter, Kramer, Parser, SerderKERI, Signer
from keri.kering import Roles, Schemes
from keri.recording import EndpointRecord, LocationRecord
from tests.app.test_registry_root_retention import roots
from tests.app.test_tcp_stream_delivery import advance, received


def coordinate(hab):
    """Return the current public establishment coordinate."""
    return dict(s=f'{hab.kever.lastEst.s:x}', d=hab.kever.lastEst.d)


@pytest.fixture
def delivery(roots):
    """Compose actual custody, state, KRAM/Revery service and a remote individual."""
    custody, originalInfo, _, issuer, _ = roots
    hby = custody.hby
    with openHby(name='delivery-target', temp=True, version=Vrsn_2_0) as remote:
        target = remote.makeHab(name='target', version=Vrsn_2_0)
        parser = Parser(kvy=hby.kvy, rvy=hby.rvy, version=Vrsn_2_0)
        parser.parse(ims=target.replay(gvrsn=Vrsn_2_0), local=False)
        hby.kvy.kramer = Kramer(db=hby.db, cf=ServiceConfig(), cues=hby.kvy.cues)
        state = RegistrySaltState(custody)
        wallet = Wallet(hby, custody.rgy, db=custody.db, custody=custody)
        service = RegistrySaltService(hby, custody.rgy, wallet, custody, state, parser, hby.rvy)
        service.register()
        service.trustRoster(issuer.pre, [issuer.pre])
        service.trustRoster(target.pre, [target.pre])
        first, secret = registry_salts.generateKeypair()
        second, _ = registry_salts.generateKeypair()
        info = replace(originalInfo, discloser=target.pre)
        rip = custody.rgy.store.seqEvent(info.registry, 0)
        init = replies.initReply(sender=issuer.pre, issuer=issuer.pre, discloser=target.pre,
            rep=issuer.pre, est=coordinate(issuer), key=first.qb64)
        bind = replies.bindReply(init, rip, sender=target.pre, rep=target.pre,
                                est=coordinate(target), key=second.qb64)
        root = registry_salts.deriveRoot(secret, second, init.raw, bind.raw)
        confirm = replies.confirmReply(init, bind, rip, root)
        for body, hab in ((init, issuer), (bind, target), (confirm, issuer)):
            service.importProof(bytes(hab.endorse(body, gvrsn=Vrsn_2_0)))
        origin = SaltOrigin(info.registry, issuer.pre, target.pre, init.said,
                            bind.said, confirm.said, confirm.sad['a']['commitment'])
        job = SaltDelivery(info.registry, target.pre, target.pre, target.kever.lastEst.d, confirm.said)
        state.retainEstablished(info, root, origin, [job])
        yield SimpleNamespace(service=service, state=state, hby=hby, parser=parser,
            issuer=issuer, target=target, job=job, root=root, confirm=confirm,
            init=init, bind=bind, info=info, custody=custody)


@contextmanager
def endpoint(case, status=204):
    """Serve real HIO HTTP PUTs and observe durable state before receipt of bytes."""
    control = dict(status=status, received=[], durable=[])

    class Handler(BaseHTTPRequestHandler):
        def do_PUT(self):
            """Record exact transport bytes after the attempt is durably retained."""
            body = self.rfile.read(int(self.headers['Content-Length']))
            control['received'].append(body)
            control['durable'].append(any(saved.essrBytes == body for _, saved in
                case.state.db.saltAttempts.getTopItemIter()))
            self.send_response(control['status'])
            self.end_headers()

        def log_message(self, *args):
            """Keep test HTTP diagnostics free of envelope bodies."""

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    hby, target = case.hby, case.target
    hby.db.ends.pin((target.pre, Roles.controller, target.pre), EndpointRecord(allowed=True))
    hby.db.locs.pin((target.pre, Schemes.http), LocationRecord(url=f'http://127.0.0.1:{server.server_port}'))
    try:
        yield control
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def run(case, duration=0.15, receiptTimeout=1.0, **kwa):
    """Run one worker on one real existing HIO scheduler, then close its I/O."""
    worker = RegistrySaltDelivery(case.service, case.issuer.pre, limit=1, timeout=0.5,
                                  receiptTimeout=receiptTimeout, tock=0.01, **kwa)
    doing.Doist(tock=0.01, real=True, limit=duration).do(doers=[worker])
    return worker


def test_readiness_preserves_unsent_exact_attempt_then_restart_sends_it(delivery):
    """Missing endpoints consume no attempts/backoff; reopening sends the saved frame."""
    c = delivery
    run(c)
    pending = c.state.delivery(*c.job.key)
    first = c.state.currentAttempt(c.job.key)
    assert first is not None and pending.attempts == 0 and pending.retryAt == 0
    c.state.db.close()
    c.state.db.reopen()
    with endpoint(c) as server:
        run(c)
        assert server['received'] == [first.essrBytes]
        assert server['durable'] == [True]
    pending = c.state.delivery(*c.job.key)
    assert pending.provision == first.reply and pending.attempts == 1
    assert pending.state == 'pending' and pending.receipt == ''


def test_http_failure_is_not_done_success_and_only_actual_send_counts(delivery):
    """An HTTP 500 keeps custody pending and schedules one actual failure retry."""
    c = delivery
    with endpoint(c, status=500) as server:
        worker = run(c)
        assert len(server['received']) == 1
        pending = c.state.delivery(*c.job.key)
        assert pending.attempts == 1 and pending.state == 'pending'
        assert pending.retryAt > time.time()
        assert worker.error == 'HTTP delivery rejected'
        first = c.state.currentAttempt(c.job.key)
        time.sleep(max(0, pending.retryAt - time.time()) + 0.01)
        server['status'] = 204
        run(c)
        newer = c.state.currentAttempt(c.job.key)
        assert newer.reply != first.reply and newer.jobKey == first.jobKey
        assert c.state.delivery(*c.job.key).attempts == 2
        assert c.state.delivery(*c.job.key).state == 'pending'


def test_bounded_cursor_reaches_ready_job_after_unready_candidates(delivery):
    """Missing member evidence cannot starve a later ready job or add retries."""
    c = delivery
    unready = [replace(c.job, member=Signer().verfer.qb64) for _ in range(3)]
    # Basic D prefixes sort before the real recipient's self-addressing E AID.
    c.state.queueDeliveries(c.job.registry, unready)
    with endpoint(c) as server:
        run(c, duration=0.3, receiptTimeout=30.0)
        assert len(server['received']) == 1
    assert c.state.delivery(*c.job.key).attempts == 1
    assert all(c.state.delivery(*job.key).attempts == 0 and
               c.state.delivery(*job.key).retryAt == 0 for job in unready)


def test_only_authenticated_target_receipt_completes_job(delivery):
    """Successful HTTP submission cannot complete the job before a real target reply."""
    c = delivery
    with endpoint(c) as server:
        run(c)
        attempt = c.state.currentAttempt(c.job.key)
        provision = SerderKERI(raw=attempt.signedBytes)
        receipt = replies.receiptReply(provision, c.confirm)
        signed = c.target.endorse(receipt, gvrsn=Vrsn_2_0)
        c.parser.parse(ims=bytearray(signed), local=False)
        assert c.state.delivery(*c.job.key).state == 'confirmed'
        assert c.state.delivery(*c.job.key).receipt == receipt.said
        run(c)
        assert len(server['received']) == 1


def test_real_tcp_buffer_drain_is_only_transport_completion(delivery):
    """One borrowed HIO schedule carries exact bytes and still awaits custody ack."""
    c = delivery
    server = tcp.Server(ha=('127.0.0.1', 0))
    assert server.reopen()
    server.eha = server.ha
    c.hby.db.ends.pin((c.target.pre, Roles.controller, c.target.pre), EndpointRecord(allowed=True))
    c.hby.db.locs.pin((c.target.pre, Schemes.tcp), LocationRecord(url=f'tcp://127.0.0.1:{server.ha[1]}'))
    worker = RegistrySaltDelivery(c.service, c.issuer.pre, limit=1, timeout=0.5, tock=0.01)
    doist = doing.Doist(tock=0.01)
    try:
        doist.deeds.extend(doist.enter(doers=[tcp.ServerDoer(server), worker]))
        advance(doist, lambda: received(server) and not worker.active)
        attempt = c.state.currentAttempt(c.job.key)
        assert received(server) == attempt.essrBytes
        assert c.state.delivery(*c.job.key).state == 'pending'
        assert c.state.delivery(*c.job.key).attempts == 1
    finally:
        doist.exit()
        server.close()


def test_expired_unsent_envelope_refreshes_only_same_original_operation(delivery):
    """Expiry refreshes live member authentication without changing DH/origin/root."""
    c = delivery
    run(c)
    first = c.state.currentAttempt(c.job.key)
    # Use the real service clock/expiry; modifying immutable saved bytes would
    # test corruption instead of expiration.
    time.sleep(max(0, first.expiresAt - time.time()) + 0.01)
    with endpoint(c):
        run(c)
    newer = c.state.currentAttempt(c.job.key)
    assert newer.reply != first.reply and newer.jobKey == first.jobKey
    assert c.state.delivery(*c.job.key).attempts == 1
    assert c.state.origin(c.job.registry).confirm == c.confirm.said
    assert c.state.proof(c.init.said) and c.state.proof(c.bind.said)


def test_committed_receipt_intent_survives_restart_and_failed_transport(delivery):
    """A root-commit receipt obligation survives both pre-send and failed-send restarts."""
    c = delivery
    c.state.blockDelivery(c.state.delivery(*c.job.key))
    proof = replies.encodeProofs(c.state.proof(c.init.said), c.state.proof(c.bind.said),
                                 c.state.proof(c.confirm.said))
    provision = replies.provisionReply(c.confirm, sender=c.target.pre, source=c.target.pre,
        party=c.issuer.pre, target=c.issuer.pre, admission=coordinate(c.issuer),
        recipientEst=coordinate(c.issuer), cipher=c.custody.sealRoot(c.job.registry,
            Encrypter(verkey=c.issuer.kever.verfers[0].qb64)).qb64, proofs=proof)
    c.parser.parse(ims=c.target.endorse(provision, gvrsn=Vrsn_2_0), local=False)
    assert c.state.receipt(provision.said).reply == ''
    c.state.db.close()
    c.state.db.reopen()
    with endpoint(c, status=500) as server:
        run(c)
        failed = c.state.receipt(provision.said)
        assert failed.state == 'pending' and failed.attempts == 1
        first = c.state.attempt(failed.reply)
        assert server['received'] == [first.essrBytes]
        assert server['durable'] == [True]
        c.state.db.close()
        c.state.db.reopen()
        time.sleep(max(0, failed.retryAt - time.time()) + 0.01)
        server['status'] = 204
        run(c)
    complete = c.state.receipt(provision.said)
    assert complete.state == 'sent' and complete.attempts == 2
    assert complete.reply != first.reply


def test_finite_transport_exception_is_failure_and_owned_doers_close():
    """A TCP-style connection error is isolated from the enclosing HIO runtime."""
    class Cutoff(doing.Doer):
        def recur(self, tyme):
            """Represent the finite messenger's actual cutoff failure contract."""
            raise ConnectionError('closed before stream delivery completed')

    attempt = SaltTransportAttempt([Cutoff()], timeout=0.1, tock=0.01)
    doing.Doist(tock=0.01, real=True, limit=0.1).do(doers=[attempt])
    assert attempt.done and attempt.error == 'transport failure'
    assert attempt.deeds == [] or not attempt.deeds
