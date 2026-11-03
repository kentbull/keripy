# -*- encoding: utf-8 -*-
"""
tests.acdc.test_registering module

"""

import lmdb
import pytest

from keri.acdc import messaging
from keri.acdc.registering import RegistryStore
from keri.acdc.regbasing import RegBaser
from keri.core import Diger, Number
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


@pytest.fixture
def registry_events():
    stamp = "2020-08-22T17:50:09.988921+00:00"
    rip = messaging.regcept(
        israid="EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ",
        uuid="0AAxyHwW6htOZ_rANOaZb2N2", stamp=stamp)
    bup = messaging.blindate(regid=rip.said, prior=rip.said,
                             blid=Diger(ser=b"accepted-blid").qb64,
                             sn=1, stamp=stamp)
    return rip, bup


@pytest.mark.parametrize("staged", [False, True])
def test_registry_accept_failure_is_atomic_on_reopen(tmp_path, monkeypatch,
                                                   registry_events, staged):
    """A failed head write rolls back acceptance while preserving staged evidence."""
    rip, bup = registry_events
    options = dict(cls=RegBaser, name="atomic", temp=False,
                   headDirPath=str(tmp_path))
    anchor = (Number(num=1), Diger(ser=b"verified-anchor"))
    with openLMDB(**options) as baser:
        store = RegistryStore(baser)
        store.accept(rip.said, 0, rip)
        if staged:
            store.putEvent(bup)
        store.putAnchor(bup.said, *anchor)
        env = baser.env

        class FaultTransaction:
            def __init__(self, txn, defaultdb):
                self.txn, self.defaultdb = txn, defaultdb

            def __enter__(self):
                self.txn.__enter__()
                return self

            def __exit__(self, *args):
                return self.txn.__exit__(*args)

            def __getattr__(self, name):
                return getattr(self.txn, name)

            def put(self, key, value, **kwa):
                if kwa.get("db", self.defaultdb) == baser.heads.sdb:
                    raise lmdb.MapFullError("injected head write failure")
                return self.txn.put(key, value, **kwa)

        class FaultEnvironment:
            def begin(self, **kwa):
                return FaultTransaction(env.begin(**kwa), kwa.get("db"))

            def __getattr__(self, name):
                return getattr(env, name)

        with monkeypatch.context() as patch:
            patch.setattr(baser, "env", FaultEnvironment())
            with pytest.raises(lmdb.MapFullError, match="head write failure"):
                store.accept(rip.said, 1, bup)

    with openLMDB(**options) as baser:
        store = RegistryStore(baser)
        assert store.seqSaider(rip.said, 1) is None
        assert store.head(rip.said).qb64 == rip.said
        assert store.event(rip.said).raw == rip.raw
        if staged:
            assert store.event(bup.said).raw == bup.raw
        else:
            assert store.event(bup.said) is None
        stored_anchor = store.anchor(bup.said)
        assert [item.qb64 for item in stored_anchor] == [item.qb64 for item in anchor]
        assert store.accept(rip.said, 1, bup) is True
        assert store.head(rip.said).qb64 == bup.said


def test_registry_accept_replay_preserves_head(tmp_path, registry_events):
    """Replaying an earlier accepted event cannot rewind the durable frontier."""
    rip, bup = registry_events
    options = dict(cls=RegBaser, name="replay", temp=False,
                   headDirPath=str(tmp_path))
    with openLMDB(**options) as baser:
        store = RegistryStore(baser)
        store.accept(rip.said, 0, rip)
        store.accept(rip.said, 1, bup)
        replayed = store.accept(rip.said, 0, rip)
        assert store.head(rip.said).qb64 == bup.said
        assert replayed is False

    with openLMDB(**options) as baser:
        store = RegistryStore(baser)
        assert store.head(rip.said).qb64 == bup.said
        assert store.seqSaider(rip.said, 0).qb64 == rip.said
        assert store.seqSaider(rip.said, 1).qb64 == bup.said


def test_registry_accept_occupied_ordinal_preserves_head(tmp_path, registry_events):
    """A refused occupied slot cannot leave the head pointing at its competitor."""
    rip, bup = registry_events
    sibling = messaging.blindate(regid=rip.said, prior=rip.said,
                                 blid=Diger(ser=b"competing-blid").qb64,
                                 sn=1, stamp=bup.sad['dt'])
    options = dict(cls=RegBaser, name="occupied", temp=False,
                   headDirPath=str(tmp_path))
    with openLMDB(**options) as baser:
        store = RegistryStore(baser)
        store.accept(rip.said, 0, rip)
        store.accept(rip.said, 1, bup)
        with pytest.raises(ValidationError):
            store.accept(rip.said, 1, sibling)

    with openLMDB(**options) as baser:
        store = RegistryStore(baser)
        assert store.head(rip.said).qb64 == bup.said
        assert store.seqSaider(rip.said, 1).qb64 == bup.said
        assert store.event(sibling.said) is None
