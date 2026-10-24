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


def test_encrypted_custody_export_import_and_future_derivation_after_reopen(tmp_path, capsys):
    """Reopen encrypted custody, reproduce future openings, enforce protected export/import, and recover AEID mismatch only by explicit rewrap.

    Parameters:
        tmp_path: Pytest-owned persistent identity, registry, section, and wallet directories.
        capsys: Pytest output capture used to prove exported salt is absent from logs.

    Returns:
        None. Assertions check the stated evidence boundary."""
    issuerKey, holderKey = Signer(transferable=False), Signer(transferable=False)
    export = tmp_path / 'private-custody.json'
    issuerInfo = holderInfo = None
    with (encrypted('custody-issuer', tmp_path, issuerKey) as issuer,
          encrypted('custody-holder', tmp_path, holderKey) as holder):
        ihab, hhab = issuer.makeHab(name='issuer'), holder.makeHab(name='holder')
        receive(issuer, hhab.replay(gvrsn=Vrsn_2_0))
        receive(holder, ihab.replay(gvrsn=Vrsn_2_0))
        irgy, hrgy = regery(issuer, tmp_path), regery(holder, tmp_path)
        iwallet = Wallet(issuer, irgy, db=WalletBaser(name=issuer.name, headDirPath=str(tmp_path)))
        hwallet = Wallet(holder, hrgy, db=WalletBaser(name=holder.name, headDirPath=str(tmp_path)))
        iwallet.custody = RegistryCustody(issuer, irgy, db=iwallet.db)
        hwallet.custody = RegistryCustody(holder, hrgy, db=hwallet.db)
        try:
            registry = Registrar(rgy=irgy).makeRegistry(name='credential', prefix=ihab.pre)
            rip = irgy.store.event(registry.regk)
            anchored(ihab, registry, rip)
            issuerInfo = iwallet.custody.createCustody(registry.regk, hhab.pre)
            assert iwallet.custody.createCustody(registry.regk, hhab.pre) == issuerInfo
            acdc = acdcmap(israid=ihab.pre, regid=registry.regk, iseaid=hhab.pre,
                           attribute={'d': '', 'name': 'Entitlement'})
            opening = iwallet.custody.derive(registry.regk, 1, acdc.said, 'issued')
            update = blindate(regid=registry.regk, prior=rip.said, blid=opening.said)
            registry.processEvent(update)
            anchored(ihab, registry, update)
            assert iwallet.recordIssued(acdc, update.said, blinder=opening).credential == acdc.said
            assert iwallet.custody.exportCustody(registry.regk, export) == export
            assert export.stat().st_mode & 0o777 == 0o600
            salt = json.loads(export.read_text())['salt']
            retained = iwallet.db.custody.get((registry.regk,))
            assert retained.aeid == issuer.mgr.aeid and salt not in retained.cipher
            assert salt.encode() not in Path(iwallet.db.path, 'data.mdb').read_bytes()
            # Receiver accepts normal signed KEL and foreign native events, never copied accepted rows.
            receive(holder, ihab.replay(gvrsn=Vrsn_2_0))
            receiver = Rever(db=holder.db, reger=hrgy.baser)
            assert receiver.processEvent(rip)
            assert receiver.processEvent(update)
            holderInfo = hwallet.custody.importCustody(export, regid=registry.regk,
                                               controller=ihab.pre, discloser=hhab.pre)
            assert holderInfo == issuerInfo
            assert hwallet.custody.derive(registry.regk, 1, acdc.said, 'issued').qb64 == opening.qb64
            future = iwallet.custody.derive(registry.regk, 17, acdc.said, 'revoked').qb64
            assert hwallet.custody.derive(registry.regk, 17, acdc.said, 'revoked').qb64 == future
            issuerReplacement = Signer(transferable=False)
            issuer.mgr.updateAeid(issuerReplacement.verfer.qb64, issuerReplacement.qb64)
            assert iwallet.custody.importCustody(export, regid=registry.regk, controller=ihab.pre,
                                         discloser=hhab.pre, rewrap=True) == issuerInfo
            assert iwallet.custody.derive(registry.regk, 17, acdc.said, 'revoked').qb64 == future
            assert all(salt.encode() not in Path(baser.path, 'data.mdb').read_bytes()
                       for baser in (irgy.baser, hrgy.baser))
            regid, controller, discloser, credential = registry.regk, ihab.pre, hhab.pre, acdc.said
        finally:
            iwallet.close()
            hwallet.close()
            irgy.close()
            hrgy.close()
    # Reopen actual encrypted Habery, RegBaser and wallet from disk with the same private key.
    with encrypted('custody-holder', tmp_path, holderKey) as holder:
        hrgy = regery(holder, tmp_path)
        wallet = Wallet(holder, hrgy, db=WalletBaser(name=holder.name, headDirPath=str(tmp_path)))
        wallet.custody = RegistryCustody(holder, hrgy, db=wallet.db)
        try:
            assert holder.habByPre(discloser)
            assert hrgy.store.head(regid).qb64 == update.said
            assert wallet.custody.derive(regid, 17, credential, 'revoked').qb64 == future
            assert wallet.custody.importCustody(export, regid=regid, controller=controller,
                                        discloser=discloser) == holderInfo
            with pytest.raises(ValidationError):
                wallet.custody.importCustody(export, regid=regid, controller=discloser, discloser=discloser)
            with pytest.raises(ValidationError):
                wallet.custody.importCustody(export, regid=regid, controller=controller, discloser=controller)
            export.chmod(0o644)
            with pytest.raises(ValidationError, match='mode0600'):
                wallet.custody.importCustody(export, regid=regid, controller=controller, discloser=discloser)
            export.chmod(0o600)
            link = tmp_path / 'link'
            link.symlink_to(export)
            with pytest.raises(OSError):
                wallet.custody.importCustody(link, regid=regid, controller=controller, discloser=discloser)
            with pytest.raises(FileExistsError):
                wallet.custody.exportCustody(regid, export)
            # Manager does not rewrap application records; identity mismatch is explicit and closed.
            replacement = Signer(transferable=False)
            holder.mgr.updateAeid(replacement.verfer.qb64, replacement.qb64)
            with pytest.raises(AuthError, match='AEID changed'):
                wallet.custody.derive(regid, 18, credential, 'revoked')
            with pytest.raises(AuthError, match='AEID changed'):
                wallet.custody.importCustody(export, regid=regid, controller=controller, discloser=discloser)
            assert wallet.custody.importCustody(export, regid=regid, controller=controller,
                                         discloser=discloser, rewrap=True) == holderInfo
            assert wallet.custody.derive(regid, 17, credential, 'revoked').qb64 == future
            assert wallet.db.custody.get((regid,)).aeid == replacement.verfer.qb64
            wallet.db.close()
            wallet.db.reopen()
            assert wallet.custody.derive(regid, 17, credential, 'revoked').qb64 == future
        finally:
            wallet.close()
            hrgy.close()
    captured = capsys.readouterr()
    assert salt not in captured.out + captured.err


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




@pytest.mark.parametrize('kind', [Kinds.cbor, Kinds.mgpk])
@pytest.mark.parametrize('history', ['public', 'mixed', 'blinded'])
def test_accepted_issuance_preserves_binary_credentials_after_reopen(tmp_path, kind, history):
    """Retain exact non-JSON credential bytes and accepted public/blinded issuer history across wallet reopen.

    Parameters:
        tmp_path: Pytest-owned persistent identity, registry, section, and wallet directories.
        kind: Binary/non-JSON credential serialization encoding.
        history: Public or blinded accepted issuer-update history.

    Returns:
        None. Assertions check the stated evidence boundary."""
    key = Signer(transferable=False)
    name = f'binary-{kind}-{history}'
    with encrypted(name, tmp_path, key) as issuer:
        hab = issuer.makeHab(name='issuer')
        rgy = regery(issuer, tmp_path)
        wallet = Wallet(issuer, rgy, db=WalletBaser(name=name, headDirPath=str(tmp_path)))
        try:
            registry = Registrar(rgy=rgy).makeRegistry(name='binary', prefix=hab.pre)
            rip = rgy.store.event(registry.regk)
            anchored(hab, registry, rip)
            acdc = acdcmap(israid=hab.pre, regid=registry.regk, kind=kind,
                           attribute={'d': '', 'entitlement': 'read'})
            prior, ordinal = rip.said, 1
            if history in ('mixed', 'blinded'):
                if history == 'blinded':
                    wallet.custody = RegistryCustody(issuer, rgy, db=wallet.db)
                    wallet.custody.createCustody(registry.regk, hab.pre)
                    opening = wallet.custody.derive(registry.regk, 1, acdc.said, 'issued')
                else:
                    opening = Blinder.blind(acdc=acdc.said, state='issued')
                blind = blindate(regid=registry.regk, prior=prior, blid=opening.said)
                registry.processEvent(blind)
                anchored(hab, registry, blind)
                prior, ordinal = blind.said, 2
            if history == 'blinded':
                head = blind
            else:
                head = update(regid=registry.regk, prior=prior, acdc=acdc.said, state='issued', sn=ordinal)
                registry.processEvent(head)
                anchored(hab, registry, head)
                assert wallet.db.custody.get((registry.regk,)) is None
            record = wallet.recordIssued(acdc, head.said,
                blinder=opening if history == 'blinded' else None)
            assert record.encoding == 'base64'
            assert wallet.issuedCredential(acdc.said).raw == acdc.raw
            raw, said, regid, head = acdc.raw, acdc.said, registry.regk, head.said
        finally:
            wallet.close()
            rgy.close()
    with encrypted(name, tmp_path, key) as issuer:
        rgy = regery(issuer, tmp_path)
        wallet = Wallet(issuer, rgy, db=WalletBaser(name=name, headDirPath=str(tmp_path)))
        try:
            assert rgy.store.head(regid).qb64 == head
            assert wallet.issuedCredential(said).raw == raw
            assert wallet.issuedCredential(said).kind == kind
            assert wallet.recordIssued(wallet.issuedCredential(said), head) == record
        finally:
            wallet.close()
            rgy.close()


def test_bound_issuance_retains_exact_historical_coordinates_after_reopen(tmp_path):
    """Retain explicit historical bound coordinates and validate them after the Issuee key state advances and stores reopen.

    Parameters:
        tmp_path: Pytest-owned persistent identity, registry, section, and wallet directories.

    Returns:
        None. Assertions check the stated evidence boundary."""
    key = Signer(transferable=False)
    with encrypted('bound-wallet', tmp_path, key) as hby:
        issuer, issuee = hby.makeHab(name='issuer'), hby.makeHab(name='issuee')
        rgy = regery(hby, tmp_path)
        wallet = Wallet(hby, rgy, db=WalletBaser(name=hby.name, headDirPath=str(tmp_path)))
        try:
            registry = Registrar(rgy=rgy).makeRegistry(name='bound', prefix=issuer.pre)
            rip = rgy.store.event(registry.regk)
            anchored(issuer, registry, rip)
            wallet.custody = RegistryCustody(hby, rgy, db=wallet.db)
            wallet.custody.createCustody(registry.regk, issuer.pre)
            acdc = acdcmap(israid=issuer.pre, iseaid=issuee.pre, regid=registry.regk,
                           attribute=dict(d='', status='authorized'))
            selected = issuee.kever.serder
            opening = wallet.custody.derive(registry.regk, 1, acdc.said, 'issued',
                                    **wallet.boundEvent(acdc, selected.said))
            update = blindate(regid=registry.regk, prior=rip.said, blid=opening.said)
            registry.processEvent(update)
            anchored(issuer, registry, update)
            record = wallet.recordIssued(acdc, update.said, blinder=opening)
            assert record.bound == dict(bn=selected.sn, bd=selected.said)
            issuee.rotate()
            assert issuee.kever.serder.said != selected.said
        finally:
            wallet.close()
            rgy.close()
    with encrypted('bound-wallet', tmp_path, key) as hby:
        rgy = regery(hby, tmp_path)
        wallet = Wallet(hby, rgy, db=WalletBaser(name=hby.name, headDirPath=str(tmp_path)))
        try:
            assert wallet.recordIssued(acdc, update.said) == record
            wallet.custody = RegistryCustody(hby, rgy, db=wallet.db)
            wrong = wallet.custody.derive(registry.regk, 1, acdc.said, 'issued',
                **wallet.boundEvent(acdc, hby.habByName('issuee').kever.serder.said))
            with pytest.raises(ValidationError):
                wallet.recordIssued(acdc, update.said, blinder=wrong)
        finally:
            wallet.close()
            rgy.close()
