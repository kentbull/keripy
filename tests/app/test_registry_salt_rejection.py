"""Permanent live reply rejection must not strand generic reply artifacts."""

import pytest

from keri import Vrsn_2_0
from keri.app import registry_salt_replies as replies
from keri.app.replying import parseReply
from keri.core.routing import fetchTsgs
from keri.core import Diger
from keri.kering import ValidationError
from tests.app.test_registry_salt_service import changed, network


def assertRemoved(service, body):
    """Check all artifacts owned by Revery, leaving KRAM's bounded replay record alone."""
    db = service.hby.db
    assert db.rpys.get((body.said,)) is None
    assert db.sdts.get((body.said,)) is None
    assert not db.scgs.get((body.said,))
    assert not fetchTsgs(db.tsgs, Diger(qb64=body.said))
    assert body.said not in [item.qb64 for item in db.rpes.get((body.route,))]
    assert service.state.proof(body.said) is None


@pytest.mark.parametrize('network', [True, False], indirect=True)
def test_authenticated_but_unauthorized_replies_leave_no_reply_artifacts(network):
    """Fresh individually signed requests cannot accumulate rejected bodies/signatures."""
    case = network
    sender, target = case.services[1:]
    valid = sender.prepareInit(issuer=case.habs[0].pre, discloser=case.habs[1].pre,
        party=case.habs[1].pre, representative=case.habs[1].pre)
    for _ in range(4):
        rejected = changed(valid, rep=case.habs[2].pre)
        with pytest.raises(ValidationError, match='current accepted member'):
            target.receive(case.habs[1].endorse(rejected, gvrsn=Vrsn_2_0))
        assertRemoved(target, rejected)
        assert target.hby.db.kramMSGC.get((rejected.pre, rejected.said)) is not None


@pytest.mark.parametrize('previously_accepted', [False, True])
def test_current_key_rejection_cleans_new_artifacts_but_preserves_accepted_history(network, previously_accepted):
    """Post-signature policy rejection cannot erase a previously accepted exact proof."""
    case = network
    sender, target = case.services[:2]
    body = sender.prepareInit(issuer=case.habs[0].pre, discloser=case.habs[1].pre,
        party=case.habs[0].pre, representative=case.habs[0].pre)
    signed = case.habs[0].endorse(body, gvrsn=Vrsn_2_0)
    if previously_accepted:
        target.receive(signed)
        original = target.state.proof(body.said)
        assert original is not None
    target.parser.parse(ims=case.habs[0].rotate(version=Vrsn_2_0, gvrsn=Vrsn_2_0))
    parsed = parseReply(target.parser, signed, {replies.INIT_ROUTE})
    # Ordinary Revery escrow dispatch can encounter historical valid signatures
    # after accepted key rotation; exercise that boundary without bypassing
    # signature verification or weakening live KRAM's separate replay rule.
    with pytest.raises(ValidationError, match='current explicit establishment'):
        target.rvy.processReply(serder=body, tsgs=parsed.tsgs, cigars=parsed.cigars)
    if previously_accepted:
        assert target.state.proof(body.said) == original
        assert target.hby.db.rpys.get((body.said,)).raw == body.raw
    else:
        assertRemoved(target, body)
