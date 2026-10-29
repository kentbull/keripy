"""Replacement salt profile: exact grants, real signatures and encrypted copies."""

from copy import deepcopy
from hashlib import sha256
from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0
from keri.acdc.messaging import regcept
from keri.app import openHby, registry_salt_messages as messages
from keri.app.registry_salt_proofs import verifyArchivedReply
from keri.core import Cipher, Diger, Encrypter, MtrDex, Parser, Salter, Signer, reply
from keri.kering import Kinds, ValidationError


STAMP = '2026-10-29T00:00:00.000000+00:00'


def test_fixed_assignment_wire_vector():
    """Pin commitment, ordered fields and SAID for the later TypeScript port.

    This deterministic test seed is public fixture material, never a live identity.
    The commitment's independent hash oracle is checked separately below.
    """
    issuer = Signer(raw=bytes(range(32)), transferable=False).verfer.qb64
    rip = regcept(issuer, uuid=Salter(raw=bytes(range(16, 32))).qb64, stamp=STAMP)
    digest = messages.commitment(Salter(raw=bytes(range(16))), issuer, rip.said)
    assert digest.qb64 == 'IKIvUy8W6PT_WEW1pD4YNXsBm0tUr98pF8ka-rZJ-D26'
    assignment = messages.assignReply(rip, digest=digest.qb64, party=issuer, stamp=STAMP)
    assert assignment.raw == (
        b'{"v":"KERICAACAAJSONAAHO.","t":"rpy",'
        b'"d":"EBo6ZEpkISb5mi3ag9wmKQ_mzBxGhK5e4f3N7dYnzkHS",'
        b'"i":"BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4",'
        b'"dt":"2026-10-29T00:00:00.000000+00:00",'
        b'"r":"/keri-rnd/registry-salt/2/assign",'
        b'"a":{"registry":"EJOZtV80Bi2h11IeCnagNSxkC95fu2lp1bAMr6Wre4vp",'
        b'"commitment":"IKIvUy8W6PT_WEW1pD4YNXsBm0tUr98pF8ka-rZJ-D26",'
        b'"party":"BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4",'
        b'"profile":"keripy-blinder-snh-low-v1","purpose":"registry-state"}}')


def changed(body, *, sender=None, route=None, **fields):
    """Re-SAID a semantic mutation rather than failing only the integrity check."""
    data = deepcopy(body.sad['a'])
    data.update(fields)
    return reply(pre=sender or body.pre, route=route or body.route, data=data,
                 stamp=body.stamp, version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)


def coordinate(hab):
    """Return accepted public establishment coordinates for the test recipient."""
    return dict(s=f'{hab.kever.lastEst.s:x}', d=hab.kever.lastEst.d)


@pytest.fixture
def case():
    """Real threshold issuer and distinct recipients; no DH establishment fixture."""
    with openHby(name='salt-messages-v2', temp=True, version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name='issuer', icount=3, ncount=3, isith='2', nsith='2')
        holder, discloser = [hby.makeHab(name=name) for name in ('holder', 'discloser')]
        root = Salter(raw=bytes(range(16)))
        rip = regcept(issuer.pre, uuid=Salter(raw=bytes(range(16, 32))).qb64, stamp=STAMP)
        digest = messages.commitment(root, issuer.pre, rip.said).qb64
        grants = [messages.assignReply(rip, digest=digest, party=hab.pre, stamp=STAMP)
                  for hab in (issuer, holder, discloser)]
        yield SimpleNamespace(hby=hby, issuer=issuer, holder=holder, discloser=discloser,
            root=root, rip=rip, digest=digest, grants=grants, parser=Parser(version=Vrsn_2_0))


def provision(c, source=0, target=1):
    """Use only source and target assignment frames, with no ceremony evidence."""
    people = (c.issuer, c.holder, c.discloser)
    grants = [c.grants[i] for i in dict.fromkeys((source, target))]
    frames = [c.issuer.endorse(grant, gvrsn=Vrsn_2_0) for grant in grants]
    recipient = people[target]
    cipher = Encrypter(verkey=recipient.kever.verfers[0].qb64).encrypt(prim=c.root)
    body = messages.provisionReply(c.grants[target], sender=people[source].pre,
        source=people[source].pre, target=recipient.pre, admission=coordinate(recipient),
        recipientEst=coordinate(recipient), cipher=cipher.qb64,
        proofs=messages.encodeProofs(frames), stamp=STAMP)
    return body, grants


def test_context_commitment_uses_framed_registry_not_a_transcript(case):
    """Independent hashlib oracle and substitutions pin the new commitment contract."""
    c = case
    parts = [b'keri-rnd/registry-salt/2/commitment', b'keripy-blinder-snh-low-v1',
             c.issuer.pre.encode(), c.rip.said.encode(), bytes(range(16))]
    expected = sha256(b''.join(len(p).to_bytes(4, 'big') + p for p in parts)).digest()
    assert Diger(qb64=c.digest).raw == expected
    assert messages.commitment(c.root, c.holder.pre, c.rip.said).qb64 != c.digest
    assert messages.commitment(c.root, c.issuer.pre, Diger(ser=b'other').qb64).qb64 != c.digest
    assert messages.commitment(Salter(raw=b'x' * 16), c.issuer.pre, c.rip.said).qb64 != c.digest
    with pytest.raises(ValidationError):
        messages.commitment(c.root.qb64, c.issuer.pre, c.rip.said)


@pytest.mark.parametrize('source,target', [(0, 1), (0, 2), (1, 2), (1, 1)])
def test_assignment_provision_receipt_with_real_signature_and_cipher(case, source, target):
    """Each authorized direction uses one salt and only its exact assignment proofs."""
    c = case
    body, grants = provision(c, source, target)
    assert messages.validateProvision(body, c.rip, assignments=grants, parser=c.parser) is body
    for stream, grant in zip(messages.decodeProofs(body), grants):
        assert verifyArchivedReply(c.hby, c.parser, stream, messages.ASSIGN_ROUTE,
                                   c.issuer.pre).raw == grant.raw
    recipient = (c.issuer, c.holder, c.discloser)[target]
    assert recipient.mgr.decrypt(qb64=Cipher(qb64=body.sad['a']['cipher']).raw,
                                 verfers=recipient.kever.verfers) == c.root.qb64b
    assert c.root.qb64b not in body.raw
    receipt = messages.receiptReply(body, stamp=STAMP)
    assert messages.validateReceipt(body, receipt) is receipt
    signed = recipient.endorse(receipt, gvrsn=Vrsn_2_0)
    assert verifyArchivedReply(c.hby, c.parser, signed, messages.RECEIPT_ROUTE,
                               recipient.pre).raw == receipt.raw
    assert len(body.sad['a']['proofs']) == (1 if source == target else 2)


def test_assignment_requires_exact_controller_and_profile(case):
    """No member or holder can substitute itself as registry controller."""
    c = case
    for bad in (changed(c.grants[1], sender=c.holder.pre),
                changed(c.grants[1], registry=Diger(ser=b'wrong').qb64),
                changed(c.grants[1], profile='other'), changed(c.grants[1], extra=True),
                changed(c.grants[1], route='/keri-rnd/registry-salt/1/assign')):
        with pytest.raises(ValidationError):
            messages.validateAssign(bad, c.rip)


def test_missing_duplicate_or_substituted_entitlement_proofs_fail(case):
    """Source and target need the exact issuer grants for the same committed root."""
    c = case
    body, grants = provision(c, 1, 2)
    for invalid in ([], [grants[0]], [grants[1], grants[1]], list(reversed(grants))):
        with pytest.raises(ValidationError):
            messages.validateProvision(body, c.rip, assignments=invalid, parser=c.parser)
    for bad in (changed(body, commitment=Diger(ser=b'wrong', code=MtrDex.SHA2_256).qb64),
                changed(body, assignment=c.grants[0].said),
                changed(body, source=c.issuer.pre), changed(body, issuer=c.holder.pre),
                changed(body, cipher=c.root.qb64), changed(body, proofs=[]),
                changed(body, admission={'s': '00', 'd': c.holder.kever.lastEst.d})):
        with pytest.raises(ValidationError):
            messages.validateProvision(bad, c.rip, assignments=grants, parser=c.parser)


def test_receipt_cannot_acknowledge_another_recipient_or_assignment(case):
    """An acknowledgement is bound to the exact provision, not just the registry."""
    body, _ = provision(case)
    receipt = messages.receiptReply(body, stamp=STAMP)
    for bad in (changed(receipt, sender=case.discloser.pre),
                changed(receipt, retained=1), changed(receipt, retained=False),
                changed(receipt, assignment=case.grants[0].said),
                changed(receipt, provision=Diger(ser=b'other provision').qb64)):
        with pytest.raises(ValidationError):
            messages.validateReceipt(body, bad)
