"""Encrypted local custody, deterministic future openings and real IPEX inventory."""
from dataclasses import asdict
import json
import os
from pathlib import Path

import pytest

from keri import Vrsn_2_0, Kinds
from keri.acdc import Regery, Registrar, acdcmap, blindate, update, grant, admit, loadHandlers
from keri.acdc.regbasing import RegBaser
from keri.acdc.regeventing import Rever
from keri.app.credentialing import Wallet, WalletBaser
from keri.app.registry_custody import RegistryCustody
from keri.app.configing import Configer
from keri.app.habbing import openHby
from keri.core import Kevery, Parser, Signer, Number, Diger, Compactor, Noncer, Blinder, messagize
from keri.kering import AuthError, ConfigurationError, ValidationError
from keri.peer.exchanging import Exchanger, loadParsedNestedSubstreams


class Notices:
    def __init__(self):
        """Create an in-memory notification recorder for accepted native exchanges.

        Returns:
            None. Each instance starts with an independent empty items list."""
        self.items = []

    def add(self, attrs):
        """Record one accepted-notification payload without altering verification.

        Args:
            attrs (dict): Attributes emitted by the concrete IPEX handler.

        Returns:
            None. Appends attrs so tests can observe notifier effects."""
        self.items.append(attrs)
def encrypted(name, root, key):
    """Open the same persistent test identity using an explicit encryption key.

    Args:
        name (str): Isolated identity/database name.
        root (Path): Pytest-owned persistent store directory.
        key (Signer): Nontransferable encryption seed and matching AEID.

    Returns:
        contextmanager: Habery that closes on exit; repeated calls reopen existing
        identity state without changing its encryption identity."""
    return openHby(name=name, temp=False, headDirPath=str(root),
        cf=Configer(name=name, temp=True), seed=key.qb64, aeid=key.verfer.qb64,
        version=Vrsn_2_0)
def regery(hby, root):
    """Open the persistent native registry environment beside one test identity.

    Args:
        hby (Habery): Caller-owned KEL evidence environment.
        root (Path): Pytest-owned persistent registry directory.

    Returns:
        Regery: Caller-owned native registry manager; tests explicitly close it."""
    return Regery(hby=hby, name=hby.name,
        baser=RegBaser(name=hby.name, temp=False, headDirPath=str(root)))
def receive(hby, raw, *, rgy=None, exc=None):
    """Ingest real remote KEL/EXN/TEL bytes through ordinary protocol processors.

    Args:
        hby (Habery): Destination identity/evidence environment.
        raw (bytes): Exact signed remote replay or native stream.
        rgy (Regery | None): Native TEL owner, when the stream contains registry events.
        exc (Exchanger | None): Shared exchange processor for IPEX route validation.

    Returns:
        None. Retries destination KEL escrows; accepted state is asserted separately."""
    remote = Kevery(db=hby.db, lax=False, local=False)
    Parser(version=Vrsn_2_0, local=False).parse(ims=bytearray(raw), kvy=remote, exc=exc,
        rgy=Rever(db=hby.db, reger=rgy.baser) if rgy else None)
    remote.processEscrows()
def anchored(hab, registry, event):
    """Seal one native event in a real controller interaction and require acceptance.

    Args:
        hab (Hab): Registry controller creating the KEL seal.
        registry (Registry): Concrete issuer-side registry engine.
        event (SerderACDC): Candidate TEL event already staged by that engine.

    Returns:
        None. Assertion fails if the real KEL anchor cannot advance registry state."""
    hab.interact(data=[dict(i=registry.regk, s=event.sad['n'], d=event.said)])
    assert registry.anchorMsg(event.said)
def signed(acdc, hab):
    """Build current-establishment issuer evidence over exact credential bytes.

    Args:
        acdc (SerderACDC): Disclosed credential view to authenticate.
        hab (Hab): Issuer habitat whose current keys sign the view.

    Returns:
        bytearray: Native node stream with a real transferable signature group."""
    return messagize(acdc, tsgs=[(hab.kever.prefixer, Number(sn=hab.kever.lastEst.s),
        Diger(qb64=hab.kever.lastEst.d), hab.sign(ser=acdc.raw))], framed=False, gvrsn=Vrsn_2_0)
def test_unencrypted_keeper_cannot_create_private_custody(tmp_path):
    """Refuse private custody with an unencrypted Keeper while ordinary inventory remains usable.

    Parameters:
        tmp_path: Pytest-owned persistent identity, registry, section, and wallet directories.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with openHby(name='unencrypted-custody', temp=True, version=Vrsn_2_0) as hby:
        rgy = regery(hby, tmp_path)
        wallet = Wallet(hby, rgy, db=WalletBaser(name=hby.name, headDirPath=str(tmp_path)))
        wallet.custody = RegistryCustody(hby, rgy, db=wallet.db)
        try:
            with pytest.raises(AuthError, match='encrypted Keeper'):
                wallet.custody.createCustody('unprovisioned', 'not-an-identifier')
        finally:
            wallet.close()
            rgy.close()
