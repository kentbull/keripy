"""Live signed salt replies retain ordinary KRAM and native transaction boundaries."""
import pytest
from keri import Vrsn_2_0
from keri.core import Encrypter, Salter, reply
from keri.kering import ValidationError
from tests.app.test_registry_salt_direct import network, receive


def test_live_intake_preserves_kram_and_sender_deny_policy(network):
    """Stale or denied replies cannot install custody; fresh allowed intake can."""
    case = network
    source, target = case.services[:2]
    issuer, holder = case.habs[:2]
    source.custody.createCustody(case.rip.said, holder.pre)
    fresh = source.makeReply(issuer, case.rip.said, holder.pre)
    stale = reply(pre=issuer.pre, route=fresh.route, data=fresh.sad['a'],
        stamp='2020-01-01T00:00:00.000000+00:00', version=Vrsn_2_0)
    parser = case.parsers[1]
    parser.parse(ims=issuer.endorse(stale, gvrsn=Vrsn_2_0), local=False)
    assert target.custody.db.custody.get((case.rip.said,)) is None
    parser.kvy.denyList = [issuer.pre]
    signed = bytes(issuer.endorse(fresh, gvrsn=Vrsn_2_0))
    parser.parse(ims=bytearray(signed), local=False)
    assert target.custody.db.custody.get((case.rip.said,)) is None
    parser.kvy.denyList = []
    parser.parse(ims=bytearray(signed), local=False)
    assert target.custody._load(case.rip.said).salt == source.custody._load(case.rip.said).salt


def test_native_transaction_aborts_partial_custody_write(network, monkeypatch):
    """An exception inside the existing LMDB transaction cannot leave a partial root row."""
    case = network
    source, target = case.services[:2]
    source.custody.createCustody(case.rip.said, case.habs[1].pre)
    body = source.makeReply(case.habs[0], case.rip.said, case.habs[1].pre)
    original = target.custody.retainPrepared

    def fail_after_write(prepared, txn):
        """Raise after the real row write, before the native transaction commits."""
        original(prepared, txn)
        raise RuntimeError('interrupted writer')

    monkeypatch.setattr(target.custody, 'retainPrepared', fail_after_write)
    with pytest.raises(RuntimeError, match='interrupted writer'):
        receive(target, case.habs[0].endorse(body, gvrsn=Vrsn_2_0))
    assert target.custody.db.custody.get((case.rip.said,)) is None


def test_issuer_cannot_replace_retained_salt_with_different_ciphertext_root(network):
    """A new valid issuer signature does not overwrite this vault's immutable root."""
    case = network
    source, target = case.services[:2]
    source.custody.createCustody(case.rip.said, case.habs[1].pre)
    body = source.makeReply(case.habs[0], case.rip.said, case.habs[1].pre)
    receive(target, case.habs[0].endorse(body, gvrsn=Vrsn_2_0))
    stored = target.custody.db.custody.get((case.rip.said,))
    cipher = Encrypter(verkey=case.habs[1].kever.verfers[0].qb64).encrypt(prim=Salter())
    changed = reply(pre=body.pre, route=body.route,
        data=dict(body.sad['a'], cipher=cipher.qb64), version=Vrsn_2_0)
    with pytest.raises(ValidationError, match='different registry custody'):
        receive(target, case.habs[0].endorse(changed, gvrsn=Vrsn_2_0))
    assert target.custody.db.custody.get((case.rip.said,)) == stored
