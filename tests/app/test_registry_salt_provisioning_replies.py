"""Local unsolicited root-transfer wire semantics, with real archived signatures."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0
from keri.acdc.messaging import regcept
from keri.app import openHby, registry_salt_replies as replies, registry_salts
from keri.app.registry_salt_proofs import verifyArchivedReply
from keri.core import Cipher, Diger, Encrypter, MtrDex, Parser, Texter, reply
from keri.kering import Kinds, ValidationError


STAMP = '2026-10-29T00:00:00.000000+00:00'


def est(hab):
    """Return one accepted public establishment coordinate."""
    return dict(s=f'{hab.kever.lastEst.s:x}', d=hab.kever.lastEst.d)


def changed(original, *, sender=None, **fields):
    """Re-SAID altered attributes so tests reach semantic validation boundaries."""
    data = deepcopy(original.sad['a'])
    data.update(fields)
    return reply(pre=sender or original.pre, route=original.route, data=data,
                 stamp=original.stamp, version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)


@pytest.fixture
def context():
    """Yield logical AIDs with real 2-of-3 key thresholds and an encrypted root."""
    with openHby(name='salt-provision-profile', temp=True, version=Vrsn_2_0) as hby:
        issuer, discloser, holder, other = [hby.makeHab(name=name, icount=3, ncount=3,
            isith='2', nsith='2', version=Vrsn_2_0) for name in ('issuer', 'discloser', 'holder', 'other')]
        sender, target = [hby.makeHab(name=name, version=Vrsn_2_0) for name in ('sender', 'target')]
        firstPub, firstSecret = registry_salts.generateKeypair()
        secondPub, _ = registry_salts.generateKeypair()
        rip = regcept(issuer.pre, stamp=STAMP)
        init = replies.initReply(sender=issuer.pre, issuer=issuer.pre, discloser=discloser.pre,
            rep=sender.pre, est=est(sender), key=firstPub.qb64, stamp=STAMP)
        bind = replies.bindReply(init, rip, sender=discloser.pre, rep=target.pre,
                                est=est(target), key=secondPub.qb64, stamp=STAMP)
        root = registry_salts.deriveRoot(firstSecret, secondPub, init.raw, bind.raw)
        confirm = replies.confirmReply(init, bind, rip, root, stamp=STAMP)
        cipher = Encrypter(verkey=target.kever.verfers[0].qb64).encrypt(prim=root).qb64
        yield SimpleNamespace(hby=hby, parser=Parser(version=Vrsn_2_0), issuer=issuer,
            discloser=discloser, holder=holder, other=other, sender=sender, target=target,
            init=init, bind=bind, confirm=confirm, rip=rip, root=root, cipher=cipher)


def proofs(c, assignments=()):
    """Encode actual threshold-endorsed transcript and issuer assignment frames."""
    return replies.encodeProofs(c.issuer.endorse(c.init, gvrsn=Vrsn_2_0),
        c.discloser.endorse(c.bind, gvrsn=Vrsn_2_0), c.issuer.endorse(c.confirm, gvrsn=Vrsn_2_0),
        [c.issuer.endorse(body, gvrsn=Vrsn_2_0) for body in assignments])


def provision(c, *, source=None, party=None, assignments=()):
    """Construct a member reply without asserting any roster membership."""
    return replies.provisionReply(c.confirm, sender=c.sender.pre, source=source or c.issuer.pre,
        party=party or c.discloser.pre, target=c.target.pre,
        admission=est(c.holder if party == c.holder.pre else c.discloser),
        recipientEst=est(c.target), cipher=c.cipher, proofs=proofs(c, assignments), stamp=STAMP)


def validate(c, body, assignments=()):
    """Validate exact transfer semantics without authenticating member/roster policy."""
    return replies.validateProvision(c.init, c.bind, c.confirm, body, c.rip,
                                      assignments=assignments, parser=c.parser)


def test_initial_and_added_logical_parties_use_one_original_root(context):
    """Issuer/discloser provision directly; holder needs issuer's same-origin assign."""
    c = context
    grant = replies.assignReply(c.confirm, party=c.holder.pre, stamp=STAMP)
    assert replies.validateAssign(c.confirm, grant) is grant
    for source, party, assignments in ((c.issuer.pre, c.discloser.pre, ()),
            (c.discloser.pre, c.issuer.pre, ()), (c.issuer.pre, c.holder.pre, (grant,)),
            (c.holder.pre, c.discloser.pre, (grant,)), (c.holder.pre, c.holder.pre, (grant,))):
        body = provision(c, source=source, party=party, assignments=assignments)
        assert validate(c, body, assignments) is body
        assert c.root.qb64b not in body.raw
        assert c.target.mgr.decrypt(qb64=Cipher(qb64=body.sad['a']['cipher']).raw,
                                     verfers=c.target.kever.verfers) == c.root.qb64b
        signed = c.sender.endorse(body, gvrsn=Vrsn_2_0)
        assert verifyArchivedReply(c.hby, c.parser, signed, replies.PROVISION_ROUTE,
                                   c.sender.pre).raw == body.raw
        streams = replies.decodeProofs(body)
        for name, expected, route in (('init', c.init, replies.INIT_ROUTE),
                ('bind', c.bind, replies.BIND_ROUTE), ('confirm', c.confirm, replies.CONFIRM_ROUTE)):
            original = verifyArchivedReply(c.hby, c.parser, streams[name], route, expected.pre)
            assert original.raw == expected.raw
        for stream in streams['assignments']:
            assert verifyArchivedReply(c.hby, c.parser, stream, replies.ASSIGN_ROUTE,
                                       c.issuer.pre).raw == grant.raw


def test_both_noninitial_parties_require_distinct_exact_assignments(context):
    """Source authority and recipient entitlement are checked independently."""
    c = context
    sourceGrant = replies.assignReply(c.confirm, party=c.holder.pre)
    recipientGrant = replies.assignReply(c.confirm, party=c.other.pre)
    grants = (sourceGrant, recipientGrant)
    body = provision(c, source=c.holder.pre, party=c.other.pre, assignments=grants)
    assert validate(c, body, grants) is body
    for bad in ((), (sourceGrant,), (recipientGrant,), (sourceGrant, sourceGrant)):
        with pytest.raises(ValidationError):
            validate(c, provision(c, source=c.holder.pre, party=c.other.pre, assignments=bad), bad)
    with pytest.raises(ValidationError):
        validate(c, provision(c, assignments=(sourceGrant,)), (sourceGrant,))


def test_assign_requires_issuer_new_party_and_exact_origin(context):
    """No representative or unrelated origin can expand the original entitlement."""
    c = context
    grant = replies.assignReply(c.confirm, party=c.holder.pre)
    for bad in (changed(grant, sender=c.sender.pre), changed(grant, party=c.issuer.pre),
                changed(grant, origin=Diger(ser=b'foreign origin').qb64),
                changed(grant, registry=Diger(ser=b'foreign registry').qb64),
                changed(grant, purpose='other-purpose'), changed(grant, extra=True)):
        with pytest.raises(ValidationError):
            replies.validateAssign(c.confirm, bad)


def test_exact_proof_bytes_and_qualified_cipher_are_required(context):
    """Reject swapped/unlinked proofs, missing assignments and non-Cipher_Salt data."""
    c = context
    body = provision(c)
    original = deepcopy(body.sad['a']['proofs'])
    variants = []
    for value in ('malformed', original['init'] + 'AAAA', Texter(raw=b'').qb64):
        variants.append(dict(original, init=value))
    variants.extend([dict(original, init=original['bind']),
                     dict(original, assignments=[original['confirm']]),
                     dict(original, assignments=[original['confirm']] * 3),
                     dict(original, extra=original['init'])])
    anotherInit = changed(c.init, key=registry_salts.generateKeypair()[0].qb64)
    variants.append(dict(original, init=Texter(raw=c.issuer.endorse(anotherInit,
                                                          gvrsn=Vrsn_2_0)).qb64))
    for value in variants:
        with pytest.raises(ValidationError):
            validate(c, changed(body, proofs=value))
    for fields in (dict(origin=Diger(ser=b'other origin').qb64),
                   dict(source=c.other.pre), dict(party=c.other.pre),
                   dict(purpose='another-purpose'),
                   dict(cipher=c.root.qb64), dict(cipher=c.cipher + 'AAAA'),
                   dict(recipientEst={'s': '00', 'd': est(c.target)['d']})):
        with pytest.raises(ValidationError):
            validate(c, changed(body, **fields))
    with pytest.raises(ValidationError):
        replies.encodeProofs(b'', b'bind', b'confirm')


def test_receipt_binds_exact_target_retention_and_literal_true(context):
    """A member acknowledgement cannot switch provisions, admissions or status."""
    c = context
    body = provision(c)
    receipt = replies.receiptReply(body, c.confirm, stamp=STAMP)
    assert receipt.pre == c.target.pre and receipt.sad['a']['retained'] is True
    assert replies.validateReceipt(body, receipt, c.confirm) is receipt
    stream = c.target.endorse(receipt, gvrsn=Vrsn_2_0)
    assert verifyArchivedReply(c.hby, c.parser, stream, replies.RECEIPT_ROUTE,
                               c.target.pre).raw == receipt.raw
    changes = [dict(sender=c.sender.pre), dict(retained=False), dict(retained=1),
        dict(provision=Diger(ser=b'other provision').qb64), dict(origin=Diger(ser=b'other').qb64),
        dict(registry=Diger(ser=b'other registry').qb64), dict(party=c.issuer.pre),
        dict(admission={'s': '1', 'd': est(c.discloser)['d']}),
        dict(commitment=Diger(ser=b'other commitment', code=MtrDex.SHA2_256).qb64),
        dict(source=c.issuer.pre)]
    for fields in changes:
        with pytest.raises(ValidationError):
            replies.validateReceipt(body, changed(receipt, **fields), c.confirm)
    with pytest.raises(ValidationError):
        replies.validateReceipt(changed(body, target=c.sender.pre), receipt, c.confirm)
