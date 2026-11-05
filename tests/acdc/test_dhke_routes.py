"""Serialized individual DH, authenticated pending Grants and real issuance."""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0 as V2
from keri.acdc import Regery, Registrar, acdcmap, grant, admit, apply, loadHandlers
from keri.acdc.dhking import Dhke, generateKeyPair
from keri.acdc.ipexing import _normalizeNodeStream, _sign
from keri.app import openCF, openHby
from keri.core import (Blinder, Diger, Kevery, Kramer, Matter, MtrDex,
                       Parser, Salter, SealSource, SerderKERI, Signer, messagize)
from keri.kering import AuthError, ValidationError
from keri.help import helping
from keri.peer import Exchanger


@contextmanager
def parties(enabled=False, count=1, opener="grant", approve_issuee=True):
    """Two isolated encrypted Haberies; TEL crosses authenticated parser intake."""
    with ExitStack() as stack:
        sides = []
        for number, name in enumerate(("issuer", "issuee"), 1):
            signer = Signer(raw=bytes([number]) * 32, transferable=False)
            hby = stack.enter_context(openHby(name=name, base="test", version=V2,
                salt=Salter(raw=bytes([number]) * 16).qb64,
                seed=signer.qb64, aeid=signer.verfer.qb64))
            hab = hby.makeHab(name=name, icount=2, isith="2", ncount=2, nsith="2")
            rgy = Regery(hby=hby, name=name, temp=True)
            stack.callback(rgy.close)
            exc = Exchanger(hby=hby, handlers=[])
            exc.TimeoutPSE = 300
            loadHandlers(hby=hby, exc=exc, notifier=SimpleNamespace(add=lambda **_: None), rgy=rgy)
            cf = stack.enter_context(openCF(name=name, base="test"))
            cf.put({"kram": {"enabled": enabled, "denials": [],
                    "caches": {"~": [1000, 5000, 60000, 300000, 5000, 60000, 300000]}}})
            dh = Dhke(hab, exc)
            hby.rtr.addRoute(Dhke.Route, dh)
            kvy = Kevery(db=hby.db, rvy=hby.rvy, exc=exc, qvy=dh,
                         kramer=Kramer(db=hby.db, cf=cf))
            psr = Parser(version=V2, kvy=kvy, exc=exc, rvy=hby.rvy, rgy=rgy)
            sides.append(SimpleNamespace(hby=hby, hab=hab, rgy=rgy, exc=exc,
                                          dh=dh, kvy=kvy, psr=psr))
        issuer, issuee = sides
        receive(issuee, issuer.hab.msgOwnEvent(sn=0, framed=False, gvrsn=V2))
        receive(issuer, issuee.hab.msgOwnEvent(sn=0, framed=False, gvrsn=V2))
        registrar = Registrar(rgy=issuer.rgy)
        registries, nodes = [], []
        for number in range(count):
            registry = registrar.makeRegistry(name=f"registry{number}", prefix=issuer.hab.pre)
            event = issuer.rgy.store.event(registry.regk)
            transfer(issuer, issuee, registry, event)
            registries.append(registry)
            nodes.append(acdcmap(israid=issuer.hab.pre, iseaid=issuee.hab.pre,
                regid=registry.regk, attribute=dict(d="", role=f"role{number}")))
        if count > 1:
            nodes[0] = acdcmap(israid=issuer.hab.pre, iseaid=issuee.hab.pre,
                regid=registries[0].regk, attribute=dict(d="", role="root"),
                edge=dict(d="", **{f"child{n}": dict(d="", n=node.said, o="E1E")
                                     for n, node in enumerate(nodes[1:])}))
        plan = [[nodes[0].schema["$id"], "/", []]] + [
            [node.schema["$id"], f"/e/child{n}/_/", []] for n, node in enumerate(nodes[1:])]
        prior = {}
        if opener == "apply":
            application, atc = apply(hab=issuee.hab, recp=issuer.hab.pre, message="apply",
                                     modifiers=dict(dp=[plan]))
            for side in sides:
                receive(side, application.raw + atc)
            prior["apply"] = application
        message, atc = grant(hab=issuer.hab, recp=issuee.hab.pre, message="issue",
                             origin=nodes[0], artifacts=nodes[1:] or None,
                             modifiers=dict(dp=[plan]), **prior)
        xid = message.said if message.ilk == "xip" else message.ked["x"]
        for side in sides:
            receive(side, message.raw + atc)
            assert side.hby.db.epse.get((message.said,)) is not None
            assert side.hby.db.exns.get((message.said,)) is None
            if side is issuer or approve_issuee:
                assert side.dh.approve(message.said) == xid
        yield SimpleNamespace(issuer=issuer, issuee=issuee, registrar=registrar,
                              registries=registries, nodes=nodes, grant=message,
                              xid=xid, prior=prior)


def receive(side, raw):
    ims = bytearray(raw)
    side.psr.parse(ims=ims, framed=False)
    assert not ims


def transfer(issuer, issuee, registry, event):
    """Commit a real KEL anchor, then deliver KEL and TEL bytes to the peer."""
    anchor = issuer.hab.interact(data=[dict(i=registry.regk, s=event.sad["n"], d=event.said)],
                                 framed=False, gvrsn=V2)
    assert registry.anchorMsg(event.said)
    receive(issuee, anchor)
    anchorSerder = SerderKERI(raw=anchor)
    receive(issuee, messagize(serder=event,
        bonds=[SealSource(s=anchorSerder.snh, d=anchorSerder.said)], gvrsn=V2))
    assert issuee.rgy.store.headEvent(registry.regk).said == event.said


def roots(side, setup):
    return [side.hab.mgr.getRegistryRoot(side.hab.pre, reg.regk) for reg in setup.registries]


@pytest.mark.parametrize("enabled", [False, True])
def test_pending_dh_issue_and_admit(enabled):
    with parties(enabled, count=2) as setup:
        issuer, issuee, message = setup.issuer, setup.issuee, setup.grant
        stream = issuer.dh.start(message.said)
        assert issuer.dh.start(message.said) == stream
        receive(issuee, stream)
        response = issuee.dh.cues.popleft()["msg"]
        receive(issuer, response)
        assert issuer.dh.complete(message.said) and issuee.dh.complete(message.said)
        assert [root.qb64 for root in roots(issuer, setup)] == [root.qb64 for root in roots(issuee, setup)]
        assert not issuer.dh._operations[message.said]["private"]
        assert not issuee.dh._operations[message.said]["private"]
        # KRAM may suppress duplicate delivery; the owner still returns exact bytes.
        assert issuer.dh.start(message.said) == stream
        if not enabled:
            receive(issuee, stream)
            assert issuee.dh.cues.popleft()["msg"] == response
        early, atc = admit(hab=issuee.hab, message="premature", grant=message)
        receive(issuee, early.raw + atc)
        assert issuee.hby.db.exns.get((early.said,)) is None
        nests = []
        for registry, node, root in zip(setup.registries, setup.nodes, roots(issuer, setup)):
            opening, event = setup.registrar.issue(registry, acdc=node, salt=root.qb64)
            transfer(issuer, issuee, registry, event)
            # The holder derives the opening itself from its retained root.
            localRoot = issuee.hab.mgr.getRegistryRoot(issuee.hab.pre, registry.regk)
            recovered = Blinder.unblind(said=event.sad["b"],
                uuid=Blinder.makeUUID(salt=localRoot.qb64, sn=1), acdc=node.said, states=["issued"])
            assert recovered.qb64 == opening.qb64
            nests.append(_normalizeNodeStream(messagize(serder=node, bonds=[recovered.data], gvrsn=V2)))
        issued = _sign(hab=issuer.hab, serder=message, nests=nests)
        for side in (issuer, issuee):
            if enabled:
                # KRAM still refuses duplicate wire delivery with new openings.
                receive(side, issued)
                assert side.hby.db.exns.get((message.said,)) is None
            assert side.dh.finish(message.said) is True
            assert side.hby.db.exns.get((message.said,)).raw == message.raw
            assert side.hby.db.epse.get((message.said,)) is None
            for node in setup.nodes:
                assert side.hby.db.exrs.get((message.said, node.said)).state == "issued"
        final, atc = admit(hab=issuee.hab, message="verified", grant=message)
        receive(issuer, final.raw + atc)
        assert issuer.hby.db.exns.get((final.said,)) is not None
        with pytest.raises(ValidationError):
            issuer.dh.start(message.said)


def resign(side, message, index=None):
    if index is None:
        return side.hab.endorse(message, last=message.ilk == "qry", gvrsn=V2)
    signatures = side.hab.sign(ser=message.raw, indexed=True)
    if message.ilk == "qry":
        return messagize(serder=message, lsgs=[(side.hab.kever.prefixer, [signatures[index]])], gvrsn=V2)
    from keri.core import Number
    return messagize(serder=message, tsgs=[(side.hab.kever.prefixer,
        Number(sn=side.hab.kever.lastEst.s), Diger(qb64=side.hab.kever.lastEst.d),
        [signatures[index]])], gvrsn=V2)


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("fault", ["sender", "scope", "shape", "return-route", "forged",
    "partial", "low-order-last", "malformed-last", "expired", "abandoned", "restarted", "root", "xid", "recipient"])
def test_query_refusals_write_no_roots(enabled, fault, fakeHelpingClock):
    with parties(enabled, count=2) as setup:
        issuer, issuee = setup.issuer, setup.issuee
        original = SerderKERI(raw=issuer.dh.start(setup.grant.said))
        sad = deepcopy(original.sad)
        signing = issuer
        registry = setup.registries[-1].regk
        if fault == "sender":
            sad["i"] = issuee.hab.pre
            signing = issuee
        elif fault == "scope":
            sad["q"]["pk"].pop(registry)
        elif fault == "shape":
            sad["q"]["grant"] = setup.grant.said
        elif fault == "xid":
            sad["q"]["x"] = Diger(ser=b"another transaction").qb64
        elif fault == "recipient":
            # Even a fully signed query cannot be used by the wrong local role.
            issuee.kvy.qvy = issuer.dh
        elif fault == "return-route":
            sad["rr"] = "/other"
        elif fault == "forged":
            signing = issuee
        elif fault == "low-order-last":
            sad["q"]["pk"][registry] = Matter(raw=bytes(32), code=MtrDex.X25519).qb64
        elif fault == "malformed-last":
            sad["q"]["pk"][registry] = Diger(ser=b"not a public key").qb64
        elif fault == "expired":
            fakeHelpingClock.advance(seconds=301)
            sad["dt"] = helping.nowIso8601()  # Fresh auxiliary message, expired Grant.
        elif fault == "abandoned":
            issuee.dh.abandon(setup.grant.said)
        elif fault == "restarted":
            issuee.dh = issuee.kvy.qvy = Dhke(issuee.hab, issuee.exc)
        elif fault == "root":
            issuee.hab.mgr.putRegistryRoot(issuee.hab.pre, registry, Salter())
        message = SerderKERI(sad=sad, makify=True)
        receive(issuee, resign(signing, message, 0 if fault == "partial" else None))
        assert not issuee.dh.cues
        assert all(root is None for root in roots(issuee, setup)[:1])
        if fault != "root":
            assert all(root is None for root in roots(issuee, setup))


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("fault", ["sender", "scope", "forged", "partial", "low-order-last",
                                    "expired", "abandoned", "restarted"])
def test_reply_refusals_write_no_roots(enabled, fault, fakeHelpingClock):
    with parties(enabled, count=2) as setup:
        issuer, issuee = setup.issuer, setup.issuee
        receive(issuee, issuer.dh.start(setup.grant.said))
        original = SerderKERI(raw=issuee.dh.cues.popleft()["msg"])
        sad = deepcopy(original.sad)
        signing = issuee
        if fault == "sender":
            sad["i"] = issuer.hab.pre
            signing = issuer
        elif fault == "scope":
            sad["a"]["pk"].pop(setup.registries[-1].regk)
        elif fault == "forged":
            signing = issuer
        elif fault == "low-order-last":
            sad["a"]["pk"][setup.registries[-1].regk] = Matter(raw=bytes(32), code=MtrDex.X25519).qb64
        elif fault == "expired":
            fakeHelpingClock.advance(seconds=301)
            sad["dt"] = helping.nowIso8601()  # Fresh auxiliary message, expired Grant.
        elif fault == "abandoned":
            issuer.dh.abandon(setup.grant.said)
        elif fault == "restarted":
            issuer.dh = Dhke(issuer.hab, issuer.exc)
            issuer.hby.rtr.routes[-1].resource = issuer.dh
        receive(issuer, resign(signing, SerderKERI(sad=sad, makify=True),
                               0 if fault == "partial" else None))
        assert all(root is None for root in roots(issuer, setup))


def test_kram_query_and_reply_accumulate_real_partial_signatures(fakeHelpingClock):
    with parties(True, approve_issuee=False) as setup:
        issuer, issuee = setup.issuer, setup.issuee
        stream = issuer.dh.start(setup.grant.said)
        qry = SerderKERI(raw=stream)
        deadlines = [side.exc.exchangeDeadline(setup.grant) for side in (issuer, issuee)]
        key = (issuer.hab.pre, qry.said)
        issuee.kvy.qvy = None
        receive(issuee, stream)
        assert issuee.hby.db.kramMSGC.get(key) is None
        issuee.kvy.qvy = issuee.dh
        receive(issuee, resign(issuer, qry, 0))
        receive(issuee, resign(issuer, qry, 0))
        assert not issuee.dh.cues and roots(issuee, setup) == [None]
        receive(issuee, resign(issuer, qry, 1))
        key = (issuer.hab.pre, qry.said)
        assert issuee.hby.db.kramPMKS.get(key) == []
        assert not issuee.dh.cues and roots(issuee, setup) == [None]
        originalCache = deepcopy(issuee.hby.db.kramMSGC.get(key))
        assert originalCache is not None
        # Approval replays retained authenticated input locally, never through KRAM.
        assert issuee.dh.approve(setup.grant.said) == setup.xid
        rpy = SerderKERI(raw=issuee.dh.cues.popleft()["msg"])
        assert roots(issuee, setup)[0] is not None
        receive(issuee, resign(issuer, qry, 0))
        receive(issuee, stream)
        assert not issuee.dh.cues
        assert issuee.hby.db.kramPMKM.get(key) is None
        receive(issuer, resign(issuee, rpy, 0))
        assert roots(issuer, setup) == [None]
        receive(issuer, resign(issuee, rpy, 1))
        assert roots(issuer, setup)[0].qb64 == roots(issuee, setup)[0].qb64
        assert issuee.hby.db.kramMSGC.get(key) == originalCache
        assert [side.exc.exchangeDeadline(setup.grant) for side in (issuer, issuee)] == deadlines
        # Cache timing, not a renewed approval or successful retry, limits later delivery.
        fakeHelpingClock.advance(seconds=62)
        receive(issuee, stream)
        assert not issuee.dh.cues
        assert issuee.hby.db.kramMSGC.get(key) == originalCache
        assert [side.exc.exchangeDeadline(setup.grant) for side in (issuer, issuee)] == deadlines


def test_same_operation_conflict_and_local_approval(fakeHelpingClock):
    with parties() as setup:
        issuer, issuee, grantSaid = setup.issuer, setup.issuee, setup.grant.said
        outsider = issuee.hby.makeHab(name="outsider")
        with pytest.raises(ValidationError, match="not a DH party"):
            Dhke(outsider, issuee.exc).approve(grantSaid)
        qry = SerderKERI(raw=issuer.dh.start(grantSaid))
        receive(issuee, resign(issuer, qry))
        response = issuee.dh.cues.popleft()["msg"]
        previous = roots(issuee, setup)[0].qb64
        changed = deepcopy(qry.sad)
        changed["q"]["pk"][setup.registries[0].regk] = generateKeyPair()[1]
        receive(issuee, resign(issuer, SerderKERI(sad=changed, makify=True)))
        assert not issuee.dh.cues and roots(issuee, setup)[0].qb64 == previous
        receive(issuee, resign(issuer, qry))
        assert issuee.dh.cues.popleft()["msg"] == response
        fakeHelpingClock.advance(seconds=301)
        receive(issuee, resign(issuer, qry))
        assert not issuee.dh.cues
        with pytest.raises(ValidationError):
            issuer.dh.start(grantSaid)


@pytest.mark.parametrize("fault", ["revoked", "placeholder", "wrong-target", "signatures", "expired", "terminated"])
def test_finish_refuses_without_mutating_pending_evidence(fault, fakeHelpingClock):
    with parties(True, count=2) as setup:
        issuer, issuee = setup.issuer, setup.issuee
        receive(issuee, issuer.dh.start(setup.grant.said))
        receive(issuer, issuee.dh.cues.popleft()["msg"])
        for index, (registry, node, root) in enumerate(zip(setup.registries, setup.nodes, roots(issuer, setup))):
            state = "issued"
            if index == 1 and fault == "revoked":
                state = "revoked"
            if index == 1 and fault == "wrong-target":
                node = acdcmap(israid=issuer.hab.pre, iseaid=issuee.hab.pre,
                               regid=registry.regk, attribute=dict(d="", role="unrelated"))
            _, event = setup.registrar.issue(registry, acdc=node, state=state, salt=root.qb64)
            transfer(issuer, issuee, registry, event)
            if index == 1 and fault == "placeholder":
                _, event = setup.registrar.vacate(registry, salt=root.qb64)
                transfer(issuer, issuee, registry, event)
        if fault == "signatures":
            issuee.hby.db.esigs.trim(keys=(setup.grant.said,))
        elif fault == "expired":
            fakeHelpingClock.advance(seconds=301)
        elif fault == "terminated":
            # Model the accepted terminal index supplied by the ordinary owner.
            issuee.hby.db.erpy.pin((setup.grant.said,), Diger(ser=b"accepted terminal reply"))
        before = issuee.hby.db.enst.get((setup.grant.said,))
        with pytest.raises(ValidationError):
            issuee.dh.finish(setup.xid)
        assert issuee.hby.db.enst.get((setup.grant.said,)) == before
        assert issuee.hby.db.exns.get((setup.grant.said,)) is None
        assert list(issuee.hby.db.exrs.getTopItemIter(keys=(setup.grant.said,))) == []


def test_apply_xid_and_second_grant_cannot_replace_approval():
    with parties(opener="apply") as setup:
        issuer, issuee = setup.issuer, setup.issuee
        assert setup.xid != setup.grant.said
        original = issuer.dh.start(setup.grant.said)
        assert SerderKERI(raw=original).sad["q"]["x"] == setup.xid
        alternative, atc = grant(hab=issuer.hab, recp=issuee.hab.pre,
            message="different Grant", origin=setup.nodes[0], **setup.prior)
        for side in (issuer, issuee):
            receive(side, alternative.raw + atc)
            assert side.hby.db.epse.get((alternative.said,)) is not None
            with pytest.raises(ValidationError, match="another Grant"):
                side.dh.approve(alternative.said)
        receive(issuee, original)
        receive(issuer, issuee.dh.cues.popleft()["msg"])
        assert issuer.dh.complete(setup.xid)
        assert roots(issuer, setup)[0].qb64 == roots(issuee, setup)[0].qb64


@pytest.mark.parametrize("action", ["forged", "duplicate", "poll"])
def test_post_bup_packet_or_poll_does_not_abandon_completion(action):
    with parties() as setup:
        issuer, issuee = setup.issuer, setup.issuee
        qry = SerderKERI(raw=issuer.dh.start(setup.grant.said))
        receive(issuee, resign(issuer, qry))
        receive(issuer, issuee.dh.cues.popleft()["msg"])
        _, event = setup.registrar.issue(setup.registries[0], acdc=setup.nodes[0],
                                         salt=roots(issuer, setup)[0].qb64)
        transfer(issuer, issuee, setup.registries[0], event)
        if action == "poll":
            assert issuee.dh.complete(setup.xid)
        else:
            receive(issuee, resign(issuee if action == "forged" else issuer, qry))
            assert not issuee.dh.cues
        assert issuee.dh.finish(setup.xid) is True


def test_dh_requires_encrypted_keeper_before_approval():
    with openHby(name="unencrypted-dh", base="test", version=V2) as hby:
        hab = hby.makeHab(name="unencrypted-dh")
        owner = Dhke(hab, Exchanger(hby=hby, handlers=[]))
        with pytest.raises(AuthError, match="encrypted, unlocked"):
            owner.approve(Diger(ser=b"unavailable Grant").qb64)
        assert owner._operations == {}
