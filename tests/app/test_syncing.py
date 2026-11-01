# -*- encoding: utf-8 -*-
"""Focused proof for the deliberately bounded multisig add core."""

import pytest
from hio.help import decking

from keri import core, kering, syncing
from keri.app import habbing, signing
from keri.core import coring, eventing, parsing, serdering
from keri.db import dbing
from keri.help import helping
from keri.peer import exchanging
from keri.vc import proving
from keri.vdr import credentialing, eventing as teventing, verifying


SCHEMA = "EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC"


def _feed(msg, *keverys):
    for kevery in keverys:
        parsing.Parser().parse(ims=bytearray(msg), kvy=kevery, local=True)
        for _ in range(3):
            kevery.processEscrows()


def _complete_group_event(msg, ghab_b, hby_a, hby_b):
    serder = serdering.SerderKERI(raw=msg)
    bmsg = eventing.messagize(serder=serder,
                              sigers=ghab_b.sign(serder.raw))
    _feed(msg, hby_b.kvy)
    _feed(bmsg, hby_a.kvy, hby_b.kvy)
    return serder


def _group_reply(route, data, ghab_a, ghab_b, hby_a, hby_b):
    serder = eventing.reply(route=route, data=data)
    sigers = [ghab_a.sign(serder.raw)[0], ghab_b.sign(serder.raw)[0]]
    seal = eventing.SealEvent(i=ghab_a.pre,
                              s=f"{ghab_a.kever.lastEst.s:x}",
                              d=ghab_a.kever.lastEst.d)
    msg = eventing.messagize(serder=serder,
                             sigers=sigers,
                             seal=seal,
                             pipelined=True)
    hby_a.psr.parseOne(ims=bytearray(msg))
    hby_b.psr.parseOne(ims=bytearray(msg))


@pytest.mark.parametrize(
    "kind,callback",
    (("kel", "kvy.event"),
     ("tel", "tvy.event"),
     ("acdc", "vry.credential"),
     ("schema", "schema"),
     ("rpy", "rvy.reply")),
)
def test_canonical_frame_duck_dispatch(kind, callback, seeder):
    salt = core.Salter(raw=b"0123456789abcdef").qb64
    with habbing.openHby(name=f"sync-duck-{kind}",
                         temp=True,
                         salt=salt) as hby:
        hab = hby.makeHab(name="source")
        kel_raw = syncing._canonical_kel(hby.db, hab.pre)[0].raw
        kel = serdering.SerderKERI(raw=kel_raw)
        registry = teventing.incept(
            hab.pre,
            baks=[],
            cnfg=[eventing.TraitDex.NoBackers])
        seal = coring.Seqner(sn=kel.sn).qb64b + kel.saidb
        tel = syncing._grouped(
            registry.raw,
            [(core.Codens.SealSourceCouples, [seal])])

        subject = dict(d="",
                       i=hab.pre,
                       dt=helping.nowIso8601(),
                       LEI="test")
        _, subject = coring.Saider.saidify(sad=subject,
                                           label=coring.Saids.d)
        creder = proving.credential(issuer=hab.pre,
                                    schema=SCHEMA,
                                    data=subject,
                                    source={},
                                    status=registry.pre)
        acdc = signing.serialize(
            creder,
            coring.Prefixer(qb64=creder.said),
            coring.Seqner(sn=0),
            coring.Saider(qb64=registry.said))

        seeder.seedSchema(hby.db)
        schema = hby.db.schema.get(keys=(SCHEMA,)).raw
        rpy = hab.makeLocScheme(eid=hab.pre,
                                scheme=kering.Schemes.http,
                                url="http://127.0.0.1:3901")
        raw = dict(kel=kel_raw,
                   tel=tel,
                   acdc=acdc,
                   schema=schema,
                   rpy=rpy)[kind]

    frame = syncing.Frame.from_raw(kind, raw)
    preflight = syncing.preflight_frame(frame)
    assert callback in preflight.trace
    assert syncing.Frame.from_raw(kind, frame.raw) == frame


def test_minimal_multisig_add_core(seeder):
    salt = core.Salter(raw=b"0123456789abcdef").qb64
    with (habbing.openHby(name="sync-a", temp=True, salt=salt) as hby_a,
          habbing.openHby(name="sync-b", temp=True, salt=salt) as hby_b,
          habbing.openHby(name="sync-c", temp=True, salt=salt) as hby_c,
          habbing.openHby(name="sync-h", temp=True, salt=salt) as hby_h):
        source_rgy = peer_rgy = target_rgy = None
        try:
            hab_a = hby_a.makeHab(name="a")
            hab_b = hby_b.makeHab(name="b")
            hab_c = hby_c.makeHab(name="c")
            hab_h = hby_h.makeHab(name="holder")
            hab_e = hby_a.makeHab(name="endpoint")
            hab_u = hby_a.makeHab(name="unrelated")

            _feed(hab_b.makeOwnEvent(sn=0), hby_a.kvy)
            _feed(hab_c.makeOwnEvent(sn=0), hby_a.kvy)
            _feed(hab_h.makeOwnEvent(sn=0), hby_a.kvy)
            _feed(hab_a.makeOwnEvent(sn=0), hby_b.kvy)
            _feed(hab_c.makeOwnEvent(sn=0), hby_b.kvy)
            _feed(hab_h.makeOwnEvent(sn=0), hby_b.kvy)
            _feed(hab_e.makeOwnEvent(sn=0), hby_b.kvy)

            old_smids = [hab_a.pre, hab_b.pre]
            final_mids = [hab_a.pre, hab_b.pre, hab_c.pre]
            group_a = hby_a.makeGroupHab(group="group-a",
                                         mhab=hab_a,
                                         smids=old_smids,
                                         rmids=final_mids,
                                         isith="2",
                                         nsith="3",
                                         toad=0,
                                         wits=[])
            group_b = hby_b.makeGroupHab(group="group-b",
                                         mhab=hab_b,
                                         smids=old_smids,
                                         rmids=final_mids,
                                         isith="2",
                                         nsith="3",
                                         toad=0,
                                         wits=[])
            assert group_a.pre == group_b.pre
            _feed(group_a.makeOwnInception(allowPartiallySigned=True), hby_b.kvy)
            _feed(group_b.makeOwnInception(allowPartiallySigned=True),
                  hby_a.kvy, hby_b.kvy)
            assert group_a.kever.tholder.num == 2

            seeder.seedSchema(hby_a.db)
            _group_reply(
                route="/end/role/add",
                data=dict(cid=group_a.pre,
                          role=kering.Roles.controller,
                          eid=hab_e.pre),
                ghab_a=group_a,
                ghab_b=group_b,
                hby_a=hby_a,
                hby_b=hby_b)
            loc = hab_e.makeLocScheme(eid=hab_e.pre,
                                      scheme=kering.Schemes.http,
                                      url="http://127.0.0.1:3901")
            hby_a.psr.parseOne(ims=bytearray(loc))
            hby_b.psr.parseOne(ims=bytearray(loc))

            source_rgy = credentialing.Regery(hby=hby_a,
                                              name="sync-a-reg",
                                              temp=True)
            issuer = source_rgy.makeRegistry(prefix=group_a.pre,
                                             name="registry",
                                             noBackers=True)
            seal = eventing.SealEvent(issuer.regk, "0", issuer.regd)._asdict()
            ixn = _complete_group_event(group_a.interact(data=[seal]),
                                        group_b, hby_a, hby_b)
            issuer.anchorMsg(pre=issuer.regk,
                             regd=issuer.regd,
                             seqner=coring.Seqner(sn=ixn.sn),
                             saider=coring.Saider(qb64=ixn.said))
            source_rgy.processEscrows()

            subject = dict(d="",
                           i=hab_h.pre,
                           dt=helping.nowIso8601(),
                           LEI="test")
            _, subject = coring.Saider.saidify(sad=subject,
                                               label=coring.Saids.d)
            creder = proving.credential(issuer=group_a.pre,
                                        schema=SCHEMA,
                                        data=subject,
                                        source={},
                                        status=issuer.regk)
            iss = issuer.issue(said=creder.said)
            seal = eventing.SealEvent(iss.pre, "0", iss.said)._asdict()
            ixn = _complete_group_event(group_a.interact(data=[seal]),
                                        group_b, hby_a, hby_b)
            issuer.anchorMsg(pre=iss.pre,
                             regd=iss.said,
                             seqner=coring.Seqner(sn=ixn.sn),
                             saider=coring.Saider(qb64=ixn.said))
            source_rgy.processEscrows()
            verifying.Verifier(hby=hby_a,
                               reger=source_rgy.reger).processCredential(
                                   creder,
                                   coring.Prefixer(qb64=creder.said),
                                   coring.Seqner(sn=0),
                                   coring.Saider(qb64=iss.said))

            # Advance only member KELs.  The group remains at its pre-add state.
            amsg = hab_a.rotate()
            bmsg = hab_b.rotate()
            cmsg = hab_c.rotate()
            _feed(bmsg, hby_a.kvy)
            _feed(cmsg, hby_a.kvy)
            _feed(amsg, hby_b.kvy)
            _feed(cmsg, hby_b.kvy)

            rotation = eventing.rotate(
                pre=group_a.pre,
                keys=[hby_a.kevers[mid].verfers[0].qb64 for mid in final_mids],
                dig=group_a.kever.serder.said,
                sn=group_a.kever.sn + 1,
                isith="3",
                ndigs=[hby_a.kevers[mid].ndigers[0].qb64 for mid in final_mids],
                nsith="3",
                toad=0,
                wits=[],
                cuts=[],
                adds=[])

            pending = (coring.Seqner(sn=rotation.sn),
                       coring.Saider(qb64=rotation.said))
            hby_a.db.gpse.add(keys=(hab_u.pre,), val=pending)
            try:
                catalog = syncing.prepare(
                    group_a,
                    source_rgy.reger,
                    target=hab_c.pre,
                    smids=final_mids,
                    rmids=final_mids,
                    rotation=rotation.raw,
                    registry=issuer.regk,
                    credential=creder.said,
                    schema=SCHEMA,
                    endpoint=(group_a.pre,
                              kering.Roles.controller,
                              hab_e.pre),
                    location=(hab_e.pre, kering.Schemes.http))
            finally:
                hby_a.db.gpse.rem(keys=(hab_u.pre,), val=pending)
            assert {frame.kind for frame in catalog.frames} == {
                "kel", "schema", "tel", "acdc", "rpy"}
            assert all(syncing.preflight_frame(frame) for frame in catalog.frames)

            # The second prior member independently reaches the same source
            # state and must produce the exact same catalog bytes.
            peer_rgy = credentialing.Regery(hby=hby_b,
                                            name="sync-b-reg",
                                            temp=True)
            syncing.replay_catalog(catalog, hby=hby_b, reger=peer_rgy.reger)
            catalog_b = syncing.prepare(
                group_b,
                peer_rgy.reger,
                target=hab_c.pre,
                smids=final_mids,
                rmids=final_mids,
                rotation=rotation.raw,
                registry=issuer.regk,
                credential=creder.said,
                schema=SCHEMA,
                endpoint=(group_a.pre, kering.Roles.controller, hab_e.pre),
                location=(hab_e.pre, kering.Schemes.http))
            assert catalog_b.raw == catalog.raw

            approval_a = group_a.sign(catalog.raw)[0]
            approval_b = group_b.sign(catalog.raw)[0]
            assert syncing.verify_approvals(
                catalog, [approval_a, approval_b]) == (0, 1)

            corrupted = bytearray(catalog.raw)
            corrupted[-1] ^= 1
            with pytest.raises(syncing.SyncError):
                syncing.Catalog.from_raw(corrupted)
            dekey = dbing.snKey(group_a.pre, group_a.kever.sn)
            hby_a.db.addDe(dekey, rotation.saidb)
            try:
                with pytest.raises(syncing.SyncError,
                                   match="pending source state"):
                    syncing.prepare(
                        group_a,
                        source_rgy.reger,
                        target=hab_c.pre,
                        smids=final_mids,
                        rmids=final_mids,
                        rotation=rotation.raw,
                        registry=issuer.regk,
                        credential=creder.said,
                        schema=SCHEMA,
                        endpoint=(group_a.pre,
                                  kering.Roles.controller,
                                  hab_e.pre),
                        location=(hab_e.pre, kering.Schemes.http))
            finally:
                hby_a.db.delDes(dekey)

            target_rgy = credentialing.Regery(hby=hby_c,
                                              name="sync-c-reg",
                                              temp=True)
            msgs = decking.Deck()
            handler = syncing.MultisigAddHandler(msgs=msgs)
            processor, converger = syncing.bind_delivery(hby_c,
                                                         target_rgy.reger)
            syncer = syncing.SyncDoer(msgs=msgs,
                                      processor=processor,
                                      converger=converger)

            for op, status in (("propose", "proposed"),
                               ("approve", "approved"),
                               ("reject", "rejected")):
                control, _ = exchanging.exchange(
                    route=syncing.Route,
                    sender=hab_c.pre,
                    recipient=hab_c.pre,
                    payload=dict(op=op,
                                 gid=group_a.pre,
                                 target=hab_c.pre,
                                 manifest=catalog.said))
                handler.handle(control)
                syncer.recur(0.0)
                assert syncer.status(catalog.said)["status"] == status

            delivery, _ = exchanging.exchange(
                route=syncing.Route,
                sender=hab_c.pre,
                recipient=hab_c.pre,
                payload=dict(
                    op="deliver",
                    gid=group_a.pre,
                    target=hab_c.pre,
                    manifest=catalog.said,
                    catalog=syncing._encode(catalog.raw),
                    approvals=[approval_a.qb64, approval_b.qb64]))
            assert handler.verify(delivery)
            handler.handle(delivery)
            syncer.recur(0.0)
            assert syncer.status(catalog.said)["status"] == "state-verified"
            rejection, _ = exchanging.exchange(
                route=syncing.Route,
                sender=hab_c.pre,
                recipient=hab_c.pre,
                payload=dict(op="reject",
                             gid=group_a.pre,
                             target=hab_c.pre,
                             manifest=catalog.said))
            handler.handle(rejection)
            syncer.recur(0.0)
            assert syncer.status(catalog.said)["status"] == "state-verified"
            handler.handle(delivery)
            syncer.recur(0.0)
            assert syncer.status(catalog.said)["status"] == "state-verified"
            assert syncing.state_verified(catalog,
                                          hby=hby_c,
                                          reger=target_rgy.reger)
            for frame in (frame for frame in catalog.frames
                          if frame.kind == "kel"):
                dig = hby_c.db.getKeLast(dbing.snKey(frame.pre, frame.sn))
                assert bytes(dig).decode("utf-8") == frame.said
            tever = target_rgy.reger.tevers[issuer.regk]
            state = tever.vcState(creder.said)
            assert state.et == kering.Ilks.iss
            assert state.d == next(
                frame.said for frame in catalog.frames
                if frame.kind == "tel" and frame.pre == creder.said)
            assert [saider.qb64 for saider in
                    target_rgy.reger.issus.get(group_a.pre)] == [creder.said]
            assert [saider.qb64 for saider in
                    target_rgy.reger.subjs.get(hab_h.pre)] == [creder.said]
            assert [saider.qb64 for saider in
                    target_rgy.reger.schms.get(SCHEMA)] == [creder.said]
            assert all(escrow.get(creder.said) is None for escrow in (
                target_rgy.reger.mre,
                target_rgy.reger.mce,
                target_rgy.reger.mse,
            ))
            assert hab_h.pre in hby_c.kevers
            assert hab_e.pre in hby_c.kevers
            assert not syncing.core_converged(catalog,
                                              hby=hby_c,
                                              reger=target_rgy.reger)

            siger_a = group_a.sign(rotation.raw,
                                       verfers=rotation.verfers,
                                       rotated=True)[0]
            siger_b = group_b.sign(rotation.raw,
                                       verfers=rotation.verfers,
                                       rotated=True)[0]
            siger_c = hab_c.mgr.sign(rotation.raw,
                                     verfers=hab_c.kever.verfers,
                                     indexed=True,
                                     indices=[2],
                                     ondices=[2])[0]
            processors = syncing.ReplayProcessors.open(hby_c,
                                                       target_rgy.reger)
            parsing.Parser().parseOne(
                ims=eventing.messagize(
                    rotation, sigers=[siger_a, siger_b, siger_c]),
                kvy=processors.kvy,
                local=False)
            syncer.recur(0.0)
            assert syncing.core_converged(catalog,
                                          hby=hby_c,
                                          reger=target_rgy.reger)
            assert syncer.status(catalog.said)["status"] == "core-converged"
            insufficient, _ = exchanging.exchange(
                route=syncing.Route,
                sender=hab_c.pre,
                recipient=hab_c.pre,
                payload=dict(
                    op="deliver",
                    gid=group_a.pre,
                    target=hab_c.pre,
                    manifest=catalog.said,
                    catalog=syncing._encode(catalog.raw),
                    approvals=[approval_a.qb64]))
            handler.handle(insufficient)
            syncer.recur(0.0)
            assert syncer.status(catalog.said)["status"] == "core-converged"
        finally:
            if target_rgy is not None:
                target_rgy.close()
            if peer_rgy is not None:
                peer_rgy.close()
            if source_rgy is not None:
                source_rgy.close()
