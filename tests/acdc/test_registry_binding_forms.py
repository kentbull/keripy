"""Protected issuer registry declarations and explicit one-way TEL references."""
from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0
from keri.acdc import messaging, ipexing, regeventing
from keri.acdc.regbasing import RegBaser
from keri.app import openHby
from keri.core import Blinder, Diger, Parser, Kevery, SealEvent, messagize
from keri.db import openLMDB
from keri.kering import MisbindingError
from keri.peer import Exchanger


class Notices:
    def add(self, attrs):
        pass


@pytest.mark.parametrize('form', ['attribute', 'aggregate', 'oneway'])
def test_issuer_registry_forms_use_actual_anchored_tel(form):
    with (openHby(name='binding-author', version=Vrsn_2_0) as author,
          openHby(name='binding-receiver', version=Vrsn_2_0) as receiver,
          openLMDB(cls=RegBaser, name='binding-tel') as reger):
        issuer = author.makeHab(name='issuer')
        recipient = receiver.makeHab(name='recipient')
        rip = messaging.regcept(israid=issuer.pre)
        issuer.interact(data=[dict(s='0', d=rip.said)], gvrsn=Vrsn_2_0)
        attributes = dict(d='', i=recipient.pre, status='issued')
        if form != 'oneway':
            attributes['rd'] = rip.said
        credential = (messaging.acdcagg(israid=issuer.pre, aggregate=['', attributes])
                      if form == 'aggregate' else
                      messaging.acdcmap(israid=issuer.pre, attribute=attributes))
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
        exc = Exchanger(receiver, handlers=[])
        ipexing.loadHandlers(receiver, exc, Notices(), SimpleNamespace(store=rever.store))
        bonds = [opening.data]
        if form == 'oneway':
            bonds.append(SealEvent(i=rip.said, s='1', d=issued.said))
        exn, atc = ipexing.grant(issuer, recipient.pre, 'protected registry',
            origin=messagize(credential, bonds=bonds, gvrsn=Vrsn_2_0))
        Parser(kvy=kvy, exc=exc, version=Vrsn_2_0).parse(ims=bytearray(exn.raw + atc))
        assert exc.complete(exn.said)
        assert ipexing.IpexHandler._presentationRegistries(credential) == []
        if form == 'oneway':
            # A real registry identity with a false TEL-event digest cannot be
            # treated as an unsigned hint or silently replaced by cached state.
            bad, batc = ipexing.grant(issuer, recipient.pre, 'wrong reference',
                origin=messagize(credential, bonds=[opening.data,
                    SealEvent(i=rip.said, s='1', d=Diger(ser=b'wrong').qb64)], gvrsn=Vrsn_2_0))
            Parser(kvy=kvy, exc=exc, version=Vrsn_2_0).parse(ims=bytearray(bad.raw + batc))
            assert not exc.complete(bad.said)
            wrong, watc = ipexing.grant(issuer, recipient.pre, 'inception is not issuance',
                origin=messagize(credential, bonds=[opening.data,
                    SealEvent(i=rip.said, s='0', d=rip.said)], gvrsn=Vrsn_2_0))
            Parser(kvy=kvy, exc=exc, version=Vrsn_2_0).parse(ims=bytearray(wrong.raw + watc))
            assert not exc.complete(wrong.said)
            other = messaging.update(rip.said, issued.said,
                Diger(ser=b'other credential').qb64, 'issued', sn=2)
            current = messaging.update(rip.said, other.said, credential.said, 'issued', sn=3)
            for event in (other, current):
                issuer.interact(data=[dict(s=event.sad['n'], d=event.said)], gvrsn=Vrsn_2_0)
            parser.parse(ims=bytearray(issuer.replay(gvrsn=Vrsn_2_0)))
            assert rever.processEvent(other)
            assert rever.processEvent(current)
            wrong, watc = ipexing.grant(issuer, recipient.pre, 'wrong accepted target',
                origin=messagize(credential, bonds=[
                    SealEvent(i=rip.said, s='2', d=other.said)], gvrsn=Vrsn_2_0))
            Parser(kvy=kvy, exc=exc, version=Vrsn_2_0).parse(ims=bytearray(wrong.raw + watc))
            assert not exc.complete(wrong.said)
        else:
            with pytest.raises(MisbindingError):
                regeventing.vetBindings(credential, regid=Diger(ser=b'substitute').qb64,
                                        issuer=issuer.pre, td=credential.said)
