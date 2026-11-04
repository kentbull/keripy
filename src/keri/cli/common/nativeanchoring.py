"""Cooperative ordinary KEL completion for individual native registry events."""
from ... import Kinds, Vrsn_2_0
from ...app import Anchorer, Receiptor
from ...core import Diger, Number, NumDex, SerderKERI
from ...kering import ConfigurationError


def anchor(owner, registry, event, auths, background):
    """Anchor one exact event using the caller's finite lifecycle and children."""
    seal = dict(i=registry.regk, s=event.sad['n'], d=event.said)
    author = owner.hab.rotate if owner.hab.kever.estOnly else owner.hab.interact
    signed = SerderKERI(raw=author(data=[seal], version=Vrsn_2_0,
                                 gvrsn=Vrsn_2_0, kind=Kinds.json))
    receipts = Receiptor(hby=owner.hby)
    background.append(receipts)
    owner.extend([receipts])
    if signed.ilk == 'drt':
        swain = Anchorer(hby=owner.hby, version=Vrsn_2_0, kind=Kinds.json)
        background.append(swain)
        owner.extend([swain])
        swain.delegation(pre=owner.hab.pre, sn=signed.sn, auths=auths)
        while not swain.complete(owner.hab.kever.prefixer,
                                  Number(num=signed.sn, code=NumDex.Huge)):
            owner.check()
            yield owner.tock
    elif owner.hab.kever.wits:
        for tick in receipts.receipt(owner.hab.pre, sn=signed.sn, auths=auths):
            owner.check()
            yield tick
    if not registry.anchorMsg(event.said, number=Number(num=signed.sn),
                              diger=Diger(qb64=signed.said)):
        raise ConfigurationError('native registry did not accept the exact witnessed BUP anchor')
    owner.rgy.processEscrows()
    accepted = owner.rgy.store.headEvent(registry.regk)
    if accepted is None or accepted.said != event.said:
        raise ConfigurationError('native registry has not accepted the selected BUP')
    return signed
