# -*- encoding: utf-8 -*-
"""
tests.acdc.test_registering module

"""

import pytest

from keri.acdc import messaging
from keri.acdc.registering import RegistryStore
from keri.acdc.regbasing import RegBaser
from keri.core import Diger
from keri.db import openLMDB
from keri.kering import ValidationError


def test_registry_store_clone_tel():
    """Accepted TEL events dump as a contiguous CESR stream keyed by registry SAID."""
    with openLMDB(cls=RegBaser, name="test-clone-tel", temp=True) as baser:
        store = RegistryStore(baser)
        issuer = "EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ"
        stamp = "2020-08-22T17:50:09.988921+00:00"
        rip = messaging.regcept(
            israid=issuer,
            uuid="0AAxyHwW6htOZ_rANOaZb2N2",
            stamp=stamp,
        )
        blid = Diger(ser=b"clone-tel-blid").qb64
        bup = messaging.blindate(
            regid=rip.said,
            prior=rip.said,
            blid=blid,
            sn=1,
            stamp=stamp,
        )

        store.accept(rip.said, 0, rip)
        store.accept(rip.said, 1, bup)

        assert list(store.cloneTelIter(rip.said)) == [bytes(rip.raw), bytes(bup.raw)]
        assert store.cloneTel(rip.said) == bytes(rip.raw) + bytes(bup.raw)
        assert store.cloneTel(rip.said, sn=1) == bytes(bup.raw)
        assert store.cloneTel(rip.said, sn=2) == b""
        assert store.cloneTel("EunknownRegistrySaidxxxxxxxxxxxxxx") == b""


def test_registry_store_replay_and_conflicting_ordinal():
    """An old prefix is harmless, while a fork never changes accepted state."""
    with openLMDB(cls=RegBaser, name="registry-replay", temp=True) as baser:
        store = RegistryStore(baser)
        rip = messaging.regcept(israid=Diger(ser=b"issuer").qb64)
        issued = messaging.blindate(rip.said, rip.said, Diger(ser=b"issued").qb64)
        revoked = messaging.blindate(rip.said, issued.said,
                                      Diger(ser=b"revoked").qb64, sn=2)
        for sn, event in enumerate((rip, issued, revoked)):
            assert store.accept(rip.said, sn, event) is True

        for sn, event in enumerate((rip, issued, revoked)):
            assert store.accept(rip.said, sn, event) is False
            assert store.headEvent(rip.said).said == revoked.said

        fork = messaging.blindate(rip.said, rip.said, Diger(ser=b"fork").qb64)
        with pytest.raises(ValidationError, match="conflicting registry event"):
            store.accept(rip.said, 1, fork)
        assert store.event(fork.said) is None
        assert store.headEvent(rip.said).said == revoked.said
        assert store.seqEvent(rip.said, 1).said == issued.said
        assert store.cloneTel(rip.said) == rip.raw + issued.raw + revoked.raw


def test_registry_store_rejects_gap_bad_prior_and_slot_mismatch():
    """Only a matching contiguous event can extend accepted state."""
    with openLMDB(cls=RegBaser, name="registry-order", temp=True) as baser:
        store = RegistryStore(baser)
        rip = messaging.regcept(israid=Diger(ser=b"issuer").qb64)
        issued = messaging.blindate(rip.said, rip.said, Diger(ser=b"issued").qb64)
        with pytest.raises(ValidationError, match="noncontiguous"):
            store.accept(rip.said, 1, issued)
        assert store.event(issued.said) is None
        assert store.head(rip.said) is None
        assert store.seqSaider(rip.said, 1) is None

        store.accept(rip.said, 0, rip)
        gap = messaging.blindate(rip.said, issued.said, Diger(ser=b"gap").qb64, sn=2)
        badprior = messaging.blindate(rip.said, Diger(ser=b"badprior").qb64,
                                       Diger(ser=b"update").qb64)
        for regk, sn, event, reason in (
                (rip.said, 2, gap, "noncontiguous"),
                (rip.said, 1, badprior, "mismatched registry prior"),
                (rip.said, 2, issued, "does not match"),
                (Diger(ser=b"other").qb64, 1, issued, "does not match")):
            with pytest.raises(ValidationError, match=reason):
                store.accept(regk, sn, event)
            assert store.event(event.said) is None
        assert store.headEvent(rip.said).said == rip.said
        assert store.seqSaider(rip.said, 1) is None
