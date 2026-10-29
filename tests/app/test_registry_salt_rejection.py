"""Ordinary reply authentication rejects unauthorized salt sharing without custom proofs."""
import pytest
from keri import Vrsn_2_0
from keri.core import Diger, Parser, reply
from keri.db import fetchTsgs
from keri.kering import ValidationError
from tests.app.test_registry_salt_direct import network, receive


@pytest.mark.parametrize('network', [True, False], indirect=True)
def test_nonissuer_signature_cannot_authorize_individual_salt_sharing(network):
    """A valid transferable or nontransferable signature is not issuer authority."""
    case = network
    issuer, sender, target = case.services
    issuer.custody.createCustody(case.rip.said, case.habs[2].pre)
    valid = issuer.makeReply(case.habs[0], case.rip.said, case.habs[2].pre)
    body = reply(pre=case.habs[1].pre, route=valid.route, data=valid.sad['a'], version=Vrsn_2_0)
    with pytest.raises(ValidationError, match='issuer or recipient group'):
        receive(target, case.habs[1].endorse(body, gvrsn=Vrsn_2_0))
    db = target.hby.db
    assert db.rpys.get((body.said,)) is None
    assert db.sdts.get((body.said,)) is None
    assert not db.scgs.get((body.said,))
    assert not list(fetchTsgs(db.tsgs, Diger(qb64=body.said)))
    assert target.custody.db.custody.get((case.rip.said,)) is None


def test_accepted_reply_retains_root_after_issuer_rotation(network):
    """Existing Revery verifies historical signatures; no separate archive verifier is needed."""
    case = network
    issuer, holder = case.services[:2]
    issuer.custody.createCustody(case.rip.said, case.habs[1].pre)
    body = issuer.makeReply(case.habs[0], case.rip.said, case.habs[1].pre)
    wire = bytes(case.habs[0].endorse(body, gvrsn=Vrsn_2_0))
    receive(holder, wire)
    stored = holder.custody.db.custody.get((case.rip.said,))
    rotation = case.habs[0].rotate(version=Vrsn_2_0, gvrsn=Vrsn_2_0)
    Parser(kvy=holder.hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(rotation), local=True)
    receive(holder, wire)
    assert holder.hby.db.rpys.get((body.said,)).raw == body.raw
    assert holder.custody.db.custody.get((case.rip.said,)) == stored
