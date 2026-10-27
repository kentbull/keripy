"""Restart gates for retired ACDC v2 registry and IPEX profiles."""

from contextlib import contextmanager

import pytest

from keri import Vrsn_2_0
from keri.acdc import messaging
from keri.acdc.ipexing import AcdcV2IpexVerification
from keri.acdc.regbasing import RegBaser
from keri.app import configing, habbing
from keri.app.evidencing import EvidenceContext
from keri.core import Diger, Noncer, Parser, Saider, exchange
from keri.kering import ValidationError
from keri.peer import Exchanger


@contextmanager
def openPersistentHabery(path):
    """Reopen one pytest-owned identity environment without cached state."""
    with configing.openCF(name="migration-gate", headDirPath=str(path),
                          temp=False) as cf:
        with habbing.openHby(name="migration-gate", headDirPath=str(path),
                             temp=False, cf=cf, version=Vrsn_2_0) as hby:
            yield hby


class LegacyNestedApplyHandler:
    """Model the former route policy that admitted nested disclosure plans."""

    resource = "/ipex/apply"

    @staticmethod
    def verify(serder, **kwa):
        return True


@pytest.mark.parametrize("marker", ("missing", "stale"))
def test_preexisting_accepted_upd_reopens_as_read_only_history(tmp_path, marker):
    """Retain exact upd rows, but derive no standing or new publication from them."""
    with habbing.openHby(name="retired-upd-reopen",
                         version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="issuer")
        rip = messaging.regcept(israid=hab.pre)
        target = messaging.acdcmap(
            israid=hab.pre,
            regid=rip.said,
            attribute=dict(d="", entitlement="legacy"),
        )
        upd = messaging.update(rip.said, rip.said, target.said, "issued")

        baser = RegBaser(name="retired-upd-reopen", temp=False,
                         headDirPath=str(tmp_path))
        try:
            assert baser.accept(rip.said, 0, rip)
            # Reproduce the accepted-row shape written before upd retirement.
            baser.evts.pin(keys=upd.said, val=upd)
            baser.tels.pin(keys=rip.said, on=1, val=Saider(qb64=upd.said))
            baser.heads.pin(keys=rip.said, val=Saider(qb64=upd.said))
            if marker == "missing":
                # Deployed stores predate the supported-prefix marker.
                baser.supported.rem(keys=rip.said)
            else:
                # A stale marker for the formerly clean inception must not
                # hide the later accepted historical row.
                assert baser.supported.get(keys=rip.said).qb64 == rip.said
        finally:
            baser.close()

        reopened = RegBaser(name="retired-upd-reopen", temp=False,
                            headDirPath=str(tmp_path))
        evidence = EvidenceContext(hby, reger=reopened)
        try:
            historical = evidence.store.seqEvent(rip.said, 1)
            assert historical.raw == upd.raw
            assert evidence.store.headEvent(rip.said).raw == upd.raw
            assert evidence.store.cloneTel(rip.said) == rip.raw + upd.raw

            # Low-level history stays readable; semantic standing and export do not.
            assert evidence.registries() == []
            with pytest.raises(ValidationError, match="retired"):
                evidence.clone([rip.said])

            # Exact supported-prefix replay remains idempotent despite the
            # later historical row.
            assert evidence.store.accept(rip.said, 0, rip) is False

            direct = messaging.blindate(
                rip.said, upd.said, Diger(ser=b"direct continuation").qb64,
                sn=2)
            with pytest.raises(ValidationError, match="retired"):
                evidence.store.accept(rip.said, 2, direct)
            assert evidence.store.event(direct.said) is None

            ordinary = messaging.blindate(
                rip.said, upd.said, Diger(ser=b"ordinary continuation").qb64,
                sn=2)
            with pytest.raises(ValidationError, match="retired"):
                evidence.rever.processEvent(ordinary)
            assert evidence.store.event(ordinary.said) is None
            assert reopened.maes.get(keys=rip.said, on=2) == []
            assert reopened.ooes.get(keys=rip.said, on=2) == []
            supported = reopened.supported.get(keys=rip.said)
            assert (supported.qb64 if supported is not None else None) == (
                rip.said if marker == "stale" else None)
            assert evidence.store.headEvent(rip.said).raw == upd.raw
        finally:
            evidence.close()


def test_supported_prefix_marker_bootstraps_and_survives_reopen(tmp_path):
    """Scan an old bup-only prefix once, then advance its durable marker."""
    rip = messaging.regcept(israid=Diger(ser=b"marker issuer").qb64)
    first = messaging.blindate(
        rip.said, rip.said, Diger(ser=b"first opening").qb64)
    second = messaging.blindate(
        rip.said, first.said, Diger(ser=b"second opening").qb64, sn=2)

    baser = RegBaser(name="supported-prefix-marker", temp=False,
                     headDirPath=str(tmp_path))
    try:
        assert baser.accept(rip.said, 0, rip)
        assert baser.accept(rip.said, 1, first)
        baser.supported.rem(keys=rip.said)  # reproduce a pre-marker store
    finally:
        baser.close()

    baser = RegBaser(name="supported-prefix-marker", temp=False,
                     headDirPath=str(tmp_path))
    try:
        assert baser.supported.get(keys=rip.said) is None
        baser.requireSupportedHistory(rip.said)
        assert baser.supported.get(keys=rip.said).qb64 == first.said
        assert baser.accept(rip.said, 2, second)
        assert baser.supported.get(keys=rip.said).qb64 == second.said
    finally:
        baser.close()

    baser = RegBaser(name="supported-prefix-marker", temp=False,
                     headDirPath=str(tmp_path))
    try:
        assert baser.supported.get(keys=rip.said).qb64 == second.said
        assert baser.heads.get(keys=rip.said).qb64 == second.said
    finally:
        baser.close()


def test_signed_nested_disclosure_plan_reopens_but_fails_current_semantics(tmp_path):
    """Preserve a formerly accepted signed EXN while refusing its retired q.dp shape."""
    nested_plan = None
    said = None
    raw = None

    with openPersistentHabery(tmp_path) as hby:
        sender = hby.makeHab(name="sender")
        receiver = hby.makeHab(name="receiver")
        schema = messaging.acdcmap(
            israid=sender.pre,
            attribute=dict(d="", role="member"),
        ).schema["$id"]
        nested_plan = [[[schema, "/", ["a/role"]]]]
        exn = exchange(
            sender=sender.pre,
            receiver=receiver.pre,
            xid=Noncer().qb64,
            route="/ipex/apply",
            modifiers=dict(dp=nested_plan),
            attributes=dict(m="Historical nested disclosure request"),
            pvrsn=Vrsn_2_0,
            gvrsn=Vrsn_2_0,
            kind=sender.kever.serder.kind,
        )
        signed = bytes(sender.endorse(
            serder=exn, framed=False, gvrsn=Vrsn_2_0))

        ims = bytearray(signed)
        parsed = Parser(version=Vrsn_2_0).parse(
            ims=ims, framed=False, processive=False)
        assert ims == bytearray()
        assert len(parsed) == 1
        assert parsed[0].serder.raw == exn.raw
        assert parsed[0].serder.ked["q"]["dp"] == nested_plan

        # Persist the exact signed message under the former permissive policy.
        legacy = Exchanger(hby=hby, handlers=[LegacyNestedApplyHandler()])
        Parser(version=Vrsn_2_0).parse(
            ims=bytearray(signed), framed=False, exc=legacy)
        assert legacy.complete(exn.said)
        said = exn.said
        raw = bytes(exn.raw)

    with openPersistentHabery(tmp_path) as reopened:
        stored = reopened.db.exns.get(keys=(said,))
        assert bytes(stored.raw) == raw
        assert stored.ked["q"]["dp"] == nested_plan

        # Stored sender authentication still verifies after reopen. The current
        # flat-plan policy, rather than missing bytes or keys, rejects the EXN.
        verification = AcdcV2IpexVerification(reopened)
        assert verification.verifyAccepted(said, "/ipex/apply") is False
        assert bytes(reopened.db.exns.get(keys=(said,)).raw) == raw
