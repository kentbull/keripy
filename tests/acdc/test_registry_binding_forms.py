"""Generic TEL bindings and the narrower IPEX issuer-authentication profile."""
from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0
from keri.acdc import messaging, ipexing, regeventing
from keri.acdc.regbasing import RegBaser
from keri.app import openHby
from keri.core import Blinder, Diger, Number, Parser, Kevery, SealEvent, messagize
from keri.db import openLMDB
from keri.kering import MisbindingError
from keri.peer import Exchanger


class Notices:
    def add(self, attrs):
        """Ignore accepted-notification attributes for this verifier-only test.

        Args:
            attrs (dict): Notification payload deliberately unused by the test.

        Returns:
            None. No notification side effects are needed to observe acceptance."""
        pass


@pytest.mark.parametrize('form', ['top-level', 'attribute', 'aggregate', 'oneway'])
def test_issuer_registry_forms_use_actual_anchored_tel(form):
    """Vet generic TEL forms while IPEX selects only a top-level issuer rd.

    Parameters:
        form: Top-level, protected attribute/aggregate, or one-way binding form.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with (openHby(name='binding-author', version=Vrsn_2_0) as author,
          openHby(name='binding-receiver', version=Vrsn_2_0) as receiver,
          openLMDB(cls=RegBaser, name='binding-tel') as reger):
        issuer = author.makeHab(name='issuer')
        recipient = receiver.makeHab(name='recipient')
        rip = messaging.regcept(israid=issuer.pre)
        issuer.interact(data=[dict(s='0', d=rip.said)], gvrsn=Vrsn_2_0)
        attributes = dict(d='', i=recipient.pre, status='issued')
        if form in ('attribute', 'aggregate'):
            attributes['rd'] = rip.said
        credential = (messaging.acdcagg(israid=issuer.pre, aggregate=['', attributes])
                      if form == 'aggregate' else
                      messaging.acdcmap(israid=issuer.pre, attribute=attributes,
                          regid=rip.said if form == 'top-level' else None))
        opening = Blinder.blind(acdc=credential.said, state='issued')
        issued = messaging.blindate(rip.said, rip.said, opening.said)
        issuer.interact(data=[dict(s='1', d=issued.said)], gvrsn=Vrsn_2_0)
        kvy = Kevery(db=receiver.db, lax=False, local=False)
        parser = Parser(kvy=kvy, version=Vrsn_2_0)
        parser.parse(ims=bytearray(issuer.replay(gvrsn=Vrsn_2_0)))
        rever = regeventing.Rever(db=receiver.db, reger=reger)
        assert rever.processEvent(rip)
        assert rever.processEvent(issued)
        record = regeventing.vet(rip, [issued], db=receiver.db,
                                 acdc=credential, blinder=opening)
        assert record.binding == ('oneway' if form == 'oneway' else 'mutual')
        assert regeventing.vetBindings(credential, regid=rip.said,
            issuer=issuer.pre, td=credential.said) == record.binding
        with pytest.raises(MisbindingError):
            regeventing.vetBindings(credential, regid=rip.said,
                issuer=issuer.pre, td=Diger(ser=b'other credential').qb64)
        if form != 'oneway':
            with pytest.raises(MisbindingError):
                regeventing.vetBindings(credential, regid=Diger(ser=b'substitute').qb64,
                                        issuer=issuer.pre, td=credential.said)

        if form == 'top-level':
            # Explicit source couples belong to the shared anchor verifier. The
            # general vetAnchor source argument is only a lookup hint, not a claim.
            source = dict(db=receiver.db, issuer=issuer.pre,
                          number=Number(num=issuer.kever.sn),
                          diger=Diger(qb64=issuer.kever.serder.said))
            assert regeventing._verifyAnchorCouple(issued, **source)
            assert not regeventing._verifyAnchorCouple(issued,
                **dict(source, diger=Diger(ser=b'wrong')))
            assert not regeventing._verifyAnchorCouple(issued,
                **dict(source, number=Number(num=issuer.kever.sn - 1)))

        exc = Exchanger(receiver, handlers=[])
        ipexing.loadHandlers(receiver, exc, Notices(), SimpleNamespace(store=rever.store))
        bonds = [opening.data]
        if form == 'oneway':
            bonds.append(SealEvent(i=rip.said, s='1', d=issued.said))
        exn, atc = ipexing.grant(issuer, recipient.pre, 'protected registry',
            origin=messagize(credential, bonds=bonds, gvrsn=Vrsn_2_0))
        Parser(kvy=kvy, exc=exc, version=Vrsn_2_0).parse(ims=bytearray(exn.raw + atc))
        if form == 'top-level':
            # The supported IPEX form authenticates against the actual TEL.
            assert exc.complete(exn.said)
        else:
            # Generic inner/one-way TEL support does not select an IPEX issuer
            # factor. Aggregate rd is application data; it needs issuer auth.
            assert not exc.complete(exn.said)
            assert receiver.db.exns.get(keys=(exn.said,)) is None
        assert receiver.db.epse.get(keys=(exn.said,)) is None
        assert [cue for cue in exc.cues if cue['kin'] == 'proof'] == []
        assert ipexing.IpexHandler._presentationRegistries(credential) == (
            None if form == 'attribute' else [])
        if form == 'oneway':
            # Preserve generic one-way binding checks against genuine accepted
            # later TEL states, independently of IPEX's narrower wire profile.
            otherOpening = Blinder.blind(
                acdc=Diger(ser=b'other credential').qb64, state='issued')
            other = messaging.blindate(rip.said, issued.said,
                                       otherOpening.said, sn=2)
            currentOpening = Blinder.blind(acdc=credential.said, state='issued')
            current = messaging.blindate(rip.said, other.said,
                                         currentOpening.said, sn=3)
            for event in (other, current):
                issuer.interact(data=[dict(s=event.sad['n'], d=event.said)], gvrsn=Vrsn_2_0)
            parser.parse(ims=bytearray(issuer.replay(gvrsn=Vrsn_2_0)))
            assert rever.processEvent(other)
            assert rever.processEvent(current)
            with pytest.raises(MisbindingError):
                regeventing.vet(rip, [issued, other], db=receiver.db,
                                acdc=credential, blinder=otherOpening)
            currentRecord = regeventing.vet(rip, [issued, other, current],
                db=receiver.db, acdc=credential, blinder=currentOpening)
            assert currentRecord.said == current.said
            assert currentRecord.binding == 'oneway'
