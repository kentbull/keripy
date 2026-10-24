"""Presentation evidence must establish more than a controller-selected date."""
from dataclasses import asdict
import pytest

from keri import Vrsn_2_0
from keri.acdc import messaging, ipexing, regeventing
from keri.acdc.regbasing import RegBaser
from keri.app import openHby
from keri.app.evidencing import ServiceConfig
from keri.core import Parser, Kevery, Kramer, Blinder
from keri.db import openLMDB
from keri.kering import ValidationError, MisbindingError


def test_later_registry_binding_does_not_establish_earlier_observation():
    """Reject receiver-time cutoffs as historical proof; an explicitly anchored TEL prefix remains stable across later bindings.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with openHby(name='history-holder', version=Vrsn_2_0) as holderHby, \
            openHby(name='history-verifier', version=Vrsn_2_0) as verifierHby, \
            openLMDB(cls=RegBaser, name='history-registry', temp=True) as reger:
        holder = holderHby.makeHab(name='holder')
        verifier = verifierHby.makeHab(name='verifier')
        rip = messaging.regcept(israid=holder.pre)
        holder.interact(data=[dict(s='0', d=rip.said)], gvrsn=Vrsn_2_0)
        kvy = Kevery(db=verifierHby.db, lax=False, local=False)
        parser = Parser(kvy=kvy, version=Vrsn_2_0)
        parser.parse(ims=bytearray(holder.replay(gvrsn=Vrsn_2_0)))
        rever = regeventing.Rever(db=verifierHby.db, reger=reger)
        assert rever.processEvent(rip)
        # A real signed immutable IPEX grant is authenticated by the receiver.
        credential = messaging.acdcmap(israid=holder.pre,
            attribute=dict(d='', i=holder.pre, rd=rip.said, entitlement='entry'))
        grant, attachment = ipexing.grant(holder, verifier.pre, 'present', origin=credential)
        dom = Parser().parseOne(ims=bytearray(grant.raw + attachment), processive=False)
        kramer = Kramer(db=verifierHby.db, cf=ServiceConfig())
        assert kramer.intake(grant, asdict(dom)) is not None
        cache = verifierHby.db.kramTMSC.get((holder.pre, grant.ked['x'], grant.said))
        assert cache.rdt
        observed = verifierHby.kevers[holder.pre].sn
        # The binding is created/anchored only AFTER receiver authentication,
        # but its controller-authored date equals the earlier grant date.
        proof = Blinder.blind(acdc=grant.said, state='presented')
        update = messaging.blindate(rip.said, rip.said, proof.said, stamp=grant.ked['dt'])
        holder.interact(data=[dict(s='1', d=update.said)], gvrsn=Vrsn_2_0)
        later = holder.kever.serder
        assert later.sn > observed
        parser.parse(ims=bytearray(holder.replay(gvrsn=Vrsn_2_0)))
        assert rever.processEvent(update)
        # Request timeliness does not prove that this anchor preceded receipt.
        # Its later arrival is ordinary dependency recovery, not a forgery.
        with pytest.raises(ValidationError, match='datetime cutoff'):
            regeventing.vetBinds(rip, [update], db=verifierHby.db,
                blinders=[proof], target=grant.said, controller=holder.pre,
                sources={update.said: later.said}, cutoff=cache.rdt, requireSource=True)
        result = regeventing.vetBinds(rip, [update], db=verifierHby.db,
            blinders=[proof], target=grant.said, controller=holder.pre,
            sources={update.said: later.said}, at=update.said, requireSource=True)
        assert result.said == update.said
        assert result.anchors[-1][0] > observed

        # A second actual grant supersedes current presentation state. Its old
        # controller date cannot make it part of the earlier named TEL prefix.
        other, _ = ipexing.grant(holder, verifier.pre, 'another presentation', origin=credential)
        otherProof = Blinder.blind(acdc=other.said, state='presented')
        otherUpdate = messaging.blindate(rip.said, update.said, otherProof.said,
                                         sn=2, stamp=rip.sad['dt'])
        holder.interact(data=[dict(s='2', d=otherUpdate.said)], gvrsn=Vrsn_2_0)
        holder.rotate(gvrsn=Vrsn_2_0)
        parser.parse(ims=bytearray(holder.replay(gvrsn=Vrsn_2_0)))
        assert rever.processEvent(otherUpdate)
        old = regeventing.vetBinds(rip, [otherUpdate, update], db=verifierHby.db,
            blinders=[proof], target=grant.said, controller=holder.pre,
            sources={update.said: later.said}, at=update.said, requireSource=True)
        assert old == result
        with pytest.raises(MisbindingError):
            regeventing.vetBinds(rip, [update, otherUpdate], db=verifierHby.db,
                blinders=[proof, otherProof], target=grant.said, controller=holder.pre)
