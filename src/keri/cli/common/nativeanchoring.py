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


def groupAnchor(owner, registry, event, mux, background, *, grant=None):
    """Propose one BUP; existing join, Multiplexor and Counselor own approval."""
    from ...app import Counselor, multisigBupExn
    from ...core import SealSource, messagize
    seal = dict(i=registry.regk, s=event.sad['n'], d=event.said)
    author = owner.hab.rotate if owner.hab.kever.estOnly else owner.hab.interact
    kwa = {}
    if owner.hab.kever.estOnly:
        kwa = dict(verfers=[owner.hby.kevers[mid].verfers[0] for mid in owner.hab.smids],
                   digers=[owner.hby.kevers[mid].ndigers[0] for mid in owner.hab.rmids])
    signed = author(data=[seal], version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json, **kwa)
    anchor = SerderKERI(raw=signed)
    number, diger = Number(num=anchor.sn), Diger(qb64=anchor.said)
    tel = messagize(event, bonds=[SealSource(s=anchor.snh, d=anchor.said)], gvrsn=Vrsn_2_0)
    proposal, atc = multisigBupExn(owner.hab, tel, signed, rgy=owner.rgy)
    owner.psr.parse(ims=bytearray(proposal.raw + atc), local=True)
    counselor = Counselor(hby=owner.hby, version=Vrsn_2_0, kind=Kinds.json)
    background.append(counselor)
    owner.extend([counselor])
    counselor.start(owner.hab, owner.hab.kever.prefixer, number, diger)
    for member in owner.hby.db.signingMembers(pre=owner.hab.pre):
        if member != owner.hab.mhab.pre:
            yield from owner.send(proposal.raw + atc, member, topic='multisig')
    import json
    result = dict(phase='group_bup_proposed', registry=registry.regk, bup=event.said, anchor=anchor.said)
    if grant is not None:
        result['grant'] = grant
    print(json.dumps(result), flush=True)
    while True:
        owner.check()
        mux.kvy.processEscrows()
        owner.rgy.processEscrows()
        accepted = owner.rgy.store.headEvent(registry.regk)
        if (accepted is not None and accepted.said == event.said
                and counselor.complete(owner.hab.kever.prefixer, number, diger)):
            break
        yield owner.tock
    from ...acdc import regeventing
    regeventing.vetAnchor(accepted, db=owner.hby.db, issuer=owner.hab.pre)
    return anchor
