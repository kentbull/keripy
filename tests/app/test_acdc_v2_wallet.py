"""Encrypted local custody, deterministic future openings and real IPEX inventory."""
from dataclasses import asdict
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0, Kinds
from keri.acdc import Regery, Registrar, acdcmap, blindate, grant, admit, loadHandlers
from keri.acdc.regbasing import RegBaser
from keri.acdc.regeventing import Rever
from keri.app.credentialing import Wallet, WalletBaser
from keri.app.registry_custody import RegistryCustody
from keri.app.configing import Configer
from keri.app.habbing import openHby
from keri.core import Encrypter, Kevery, Parser, Signer, Number, Diger, Compactor, Noncer, Blinder, messagize
from keri.kering import AuthError, ConfigurationError, ValidationError, MissingSchemaError
from keri.peer.exchanging import Exchanger, loadParsedNestedSubstreams


class Notices:
    def __init__(self):
        """Create an in-memory notification recorder for accepted ACDC v2 IPEX exchanges.

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
    """Open the persistent ACDC v2 registry environment beside one test identity.

    Args:
        hby (Habery): Caller-owned KEL evidence environment.
        root (Path): Pytest-owned persistent registry directory.

    Returns:
        Regery: Caller-owned ACDC v2 registry manager; tests explicitly close it."""
    return Regery(hby=hby, name=hby.name,
        baser=RegBaser(name=hby.name, temp=False, headDirPath=str(root)))


def receive(hby, raw, *, rgy=None, exc=None):
    """Ingest real remote KEL/EXN/TEL bytes through ordinary protocol processors.

    Args:
        hby (Habery): Destination identity/evidence environment.
        raw (bytes): Exact signed remote replay or ACDC v2 evidence stream.
        rgy (Regery | None): ACDC v2 registry TEL owner, when the stream contains registry events.
        exc (Exchanger | None): Shared exchange processor for IPEX route validation.

    Returns:
        None. Retries destination KEL escrows; accepted state is asserted separately."""
    remote = Kevery(db=hby.db, lax=False, local=False)
    Parser(version=Vrsn_2_0, local=False).parse(ims=bytearray(raw), kvy=remote, exc=exc,
        rgy=Rever(db=hby.db, reger=rgy.baser) if rgy else None)
    remote.processEscrows()


def anchored(hab, registry, event):
    """Seal one ACDC v2 registry event in a real controller interaction and require acceptance.

    Args:
        hab (Hab): Registry controller creating the KEL seal.
        registry (Registry): Concrete issuer-side registry engine.
        event (SerderACDC): Candidate TEL event already staged by that engine.

    Returns:
        None. Assertion fails if the real KEL anchor cannot advance registry state."""
    hab.interact(data=[dict(i=registry.regk, s=event.sad['n'], d=event.said)])
    assert registry.anchorMsg(event.said)


def _custody_issuance_case(tmp_path):
    """Create encrypted custody and authentic issuer/holder KEL/TEL state without handoff."""
    issuerKey, holderKey = Signer(transferable=False), Signer(transferable=False)
    with (encrypted('custody-issuer', tmp_path, issuerKey) as issuer,
          encrypted('custody-holder', tmp_path, holderKey) as holder):
        ihab, hhab = issuer.makeHab(name='issuer'), holder.makeHab(name='holder')
        receive(issuer, hhab.replay(gvrsn=Vrsn_2_0))
        receive(holder, ihab.replay(gvrsn=Vrsn_2_0))
        irgy, hrgy = regery(issuer, tmp_path), regery(holder, tmp_path)
        iwallet = Wallet(issuer, irgy, db=WalletBaser(name=issuer.name, headDirPath=str(tmp_path)))
        hwallet = Wallet(holder, hrgy, db=WalletBaser(name=holder.name, headDirPath=str(tmp_path)))
        iwallet.custody = RegistryCustody(issuer, irgy)
        hwallet.custody = RegistryCustody(holder, hrgy)
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
            salt = iwallet.custody._load(registry.regk).salt
            retained = iwallet.hby.ks.custody.get((registry.regk,))
            assert retained.aeid == issuer.mgr.aeid and salt not in retained.cipher
            assert salt.encode() not in Path(iwallet.db.path, 'data.mdb').read_bytes()
            # Receiver accepts normal signed KEL and foreign ACDC v2 registry events, never copied accepted rows.
            receive(holder, ihab.replay(gvrsn=Vrsn_2_0))
            receiver = Rever(db=holder.db, reger=hrgy.baser)
            assert receiver.processEvent(rip)
            assert receiver.processEvent(update)
            future = iwallet.custody.derive(registry.regk, 17, acdc.said, 'revoked').qb64
            assert all(salt.encode() not in Path(baser.path, 'data.mdb').read_bytes()
                       for baser in (irgy.baser, hrgy.baser))
            regid, controller, discloser, credential = registry.regk, ihab.pre, hhab.pre, acdc.said
        finally:
            iwallet.close()
            hwallet.close()
            irgy.close()
            hrgy.close()
    return SimpleNamespace(issuerKey=issuerKey, holderKey=holderKey, issuerInfo=issuerInfo,
                           regid=regid, controller=controller, discloser=discloser,
                           credential=credential, update=update, opening=opening,
                           future=future, salt=salt)


def test_encrypted_custody_future_derivation_after_reopen(tmp_path, capsys):
    """Encrypted derivation, real receiver history and Keeper rotation need no file handoff."""
    case = _custody_issuance_case(tmp_path)
    with (encrypted('custody-issuer', tmp_path, case.issuerKey) as issuer,
          encrypted('custody-holder', tmp_path, case.holderKey) as holder):
        irgy, hrgy = regery(issuer, tmp_path), regery(holder, tmp_path)
        iwallet = Wallet(issuer, irgy, db=WalletBaser(name=issuer.name, headDirPath=str(tmp_path)))
        hwallet = Wallet(holder, hrgy, db=WalletBaser(name=holder.name, headDirPath=str(tmp_path)))
        iwallet.custody = RegistryCustody(issuer, irgy)
        hwallet.custody = RegistryCustody(holder, hrgy)
        try:
            assert holder.habByPre(case.discloser)
            assert hrgy.store.head(case.regid).qb64 == case.update.said
            assert iwallet.custody.derive(case.regid, 1, case.credential, 'issued').qb64 == case.opening.qb64
            assert iwallet.custody.derive(case.regid, 17, case.credential, 'revoked').qb64 == case.future
            with pytest.raises(ConfigurationError, match='custody is not provisioned'):
                hwallet.custody.derive(case.regid, 17, case.credential, 'revoked')
            replacement = Signer(transferable=False)
            issuer.mgr.updateAeid(replacement.verfer.qb64, replacement.qb64)
            assert iwallet.custody.derive(case.regid, 17, case.credential, 'revoked').qb64 == case.future
        finally:
            iwallet.close()
            hwallet.close()
            irgy.close()
            hrgy.close()
    captured = capsys.readouterr()
    assert case.salt not in captured.out + captured.err


def test_encrypted_custody_handoff_and_keeper_binding_after_reopen(tmp_path, capsys):
    """Preserve encrypted transfer and derivation across reopen; changed Keepers fail closed."""
    case = _custody_issuance_case(tmp_path)
    issuerKey, holderKey, issuerInfo = case.issuerKey, case.holderKey, case.issuerInfo
    opening, update = case.opening, case.update
    with (encrypted('custody-issuer', tmp_path, issuerKey) as issuer,
          encrypted('custody-holder', tmp_path, holderKey) as holder):
        ihab, hhab = issuer.habByPre(case.controller), holder.habByPre(case.discloser)
        irgy, hrgy = regery(issuer, tmp_path), regery(holder, tmp_path)
        iwallet = Wallet(issuer, irgy, db=WalletBaser(name=issuer.name, headDirPath=str(tmp_path)))
        hwallet = Wallet(holder, hrgy, db=WalletBaser(name=holder.name, headDirPath=str(tmp_path)))
        iwallet.custody = RegistryCustody(issuer, irgy)
        hwallet.custody = RegistryCustody(holder, hrgy)
        try:
            verfer = hhab.kever.verfers[0]
            cipher = iwallet.custody.sealRoot(case.regid, Encrypter(verkey=verfer.qb64))
            root = hwallet.custody.openRoot(cipher, verfer)
            salt = root.qb64
            prepared = hwallet.custody.prepareRoot(issuerInfo, root)
            with hwallet.custody.db.env.begin(write=True) as txn:
                hwallet.custody.retainPrepared(prepared, txn)
            assert hwallet.custody.derive(case.regid, 1, case.credential, 'issued').qb64 == opening.qb64
            future = iwallet.custody.derive(case.regid, 17, case.credential, 'revoked').qb64
            assert hwallet.custody.derive(case.regid, 17, case.credential, 'revoked').qb64 == future
            assert all(salt.encode() not in Path(baser.path, 'data.mdb').read_bytes()
                       for baser in (irgy.baser, hrgy.baser))
            regid, controller, discloser, credential = case.regid, ihab.pre, hhab.pre, case.credential
        finally:
            iwallet.close()
            hwallet.close()
            irgy.close()
            hrgy.close()
    # Reopen actual encrypted Habery, RegBaser and wallet from disk with the same private key.
    with encrypted('custody-holder', tmp_path, holderKey) as holder:
        hrgy = regery(holder, tmp_path)
        wallet = Wallet(holder, hrgy, db=WalletBaser(name=holder.name, headDirPath=str(tmp_path)))
        wallet.custody = RegistryCustody(holder, hrgy)
        try:
            assert holder.habByPre(discloser)
            assert hrgy.store.head(regid).qb64 == update.said
            assert wallet.custody.derive(regid, 17, credential, 'revoked').qb64 == future
            replacement = Signer(transferable=False)
            holder.mgr.updateAeid(replacement.verfer.qb64, replacement.qb64)
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
        bytearray: ACDC v2 credential node stream with a real transferable signature group."""
    return messagize(acdc, tsgs=[(hab.kever.prefixer, Number(sn=hab.kever.lastEst.s),
        Diger(qb64=hab.kever.lastEst.d), hab.sign(ser=acdc.raw))], framed=False, gvrsn=Vrsn_2_0)


def test_real_partial_and_full_grants_retain_separate_explicit_admissions(tmp_path):
    """Keep two actual signed partial/full Grants as separate explicit admissions without expanding the earlier retained view.

    Parameters:
        tmp_path: Pytest-owned persistent identity, registry, section, and wallet directories.

    Returns:
        None. Assertions check the stated evidence boundary."""
    senderKey, holderKey = Signer(transferable=False), Signer(transferable=False)
    with (encrypted('inventory-issuer', tmp_path, senderKey) as issuer,
          encrypted('inventory-holder', tmp_path, holderKey) as holder):
        ihab, hhab = issuer.makeHab(name='issuer'), holder.makeHab(name='holder')
        receive(holder, ihab.replay(gvrsn=Vrsn_2_0))
        receive(issuer, hhab.replay(gvrsn=Vrsn_2_0))
        hrgy = regery(holder, tmp_path)
        notices = Notices()
        exc = Exchanger(hby=holder, handlers=[])
        loadHandlers(holder, exc, notices, rgy=hrgy)
        wallet = Wallet(holder, hrgy, exc=exc,
                        db=WalletBaser(name=holder.name, headDirPath=str(tmp_path)))
        try:
            full = acdcmap(israid=ihab.pre, uuid=Noncer().qb64, iseaid=hhab.pre,
                attribute={'d': '', 'u': Noncer().qb64,
                    'status': {'d': '', 'u': Noncer().qb64, 'value': 'authorized'},
                    'private': {'d': '', 'u': Noncer().qb64, 'value': 'hidden-first'}})
            compact = Compactor(mad=dict(full.sad['a']), makify=True, kind=Kinds.json)
            compact.compact(paths=['a/status/'], root='a')
            partial = acdcmap(israid=full.israid, uuid=full.sad['u'], schema=full.sad['s'],
                              attribute=dict(compact.partials[('a/status/',)].mad))
            assert partial.said == full.said
            assert isinstance(partial.sad['a']['private'], str)
            pairs = []
            for stage, credential in enumerate((partial, full), start=1):
                gexn, gatc = grant(ihab, hhab.pre, f'disclosure stage {stage}',
                    origin=signed(credential, ihab))
                receive(holder, gexn.raw + gatc, rgy=hrgy, exc=exc)
                assert exc.complete(gexn.said)
                assert wallet.inventory()['held'] == [record for record in wallet.admissions(full.said)]
                aexn, aatc = admit(hhab, 'I consent to retain this disclosure', gexn)
                receive(holder, aexn.raw + aatc, rgy=hrgy, exc=exc)
                assert exc.complete(aexn.said)
                with pytest.raises(ValidationError, match='consent'):
                    wallet.recordAdmission(gexn.said, aexn.said)
                record = wallet.recordAdmission(gexn.said, aexn.said, consent=True)
                assert wallet.recordAdmission(gexn.said, aexn.said, consent=True) == record
                pairs.append((gexn.said, aexn.said))
            assert pairs[0][0] != pairs[1][0]
            assert len(wallet.admissions(full.said)) == 2
            assert {record.grant for record in wallet.inventory()['held']} == {pair[0] for pair in pairs}
            assert isinstance(wallet.heldCredential(pairs[0][0])['credential'].sad['a']['private'], str)
            assert wallet.heldCredential(pairs[1][0])['credential'].sad['a']['private']['value'] == 'hidden-first'
            # Missing/synthetic protocol IDs and bare notifications never create inventory.
            notices.add({'r': '/exn/ipex/grant', 'd': 'synthetic'})
            with pytest.raises(ValidationError):
                wallet.recordAdmission('synthetic', pairs[0][1], consent=True)
        finally:
            wallet.close()
            hrgy.close()
    with encrypted('inventory-holder', tmp_path, holderKey) as holder:
        hrgy = regery(holder, tmp_path)
        exc = Exchanger(hby=holder, handlers=[])
        loadHandlers(holder, exc, Notices(), rgy=hrgy)
        wallet = Wallet(holder, hrgy, exc=exc,
                        db=WalletBaser(name=holder.name, headDirPath=str(tmp_path)))
        try:
            assert len(wallet.admissions(full.said)) == 2
            assert {record.admit for record in wallet.inventory()['held']} == {pair[1] for pair in pairs}
            assert wallet.recordAdmission(*pairs[0], consent=True).grant == pairs[0][0]
            assert isinstance(wallet.heldCredential(pairs[0][0])['credential'].sad['a']['private'], str)
            assert wallet.heldCredential(pairs[1][0])['credential'].sad['a']['private']['value'] == 'hidden-first'
        finally:
            wallet.close()
            hrgy.close()


def test_unencrypted_keeper_cannot_create_private_custody(tmp_path):
    """Refuse private custody with an unencrypted Keeper while ordinary inventory remains usable.

    Parameters:
        tmp_path: Pytest-owned persistent identity, registry, section, and wallet directories.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with openHby(name='unencrypted-custody', temp=True, version=Vrsn_2_0) as hby:
        rgy = regery(hby, tmp_path)
        wallet = Wallet(hby, rgy, db=WalletBaser(name=hby.name, headDirPath=str(tmp_path)))
        wallet.custody = RegistryCustody(hby, rgy)
        try:
            with pytest.raises(AuthError, match='encrypted Keeper'):
                wallet.custody.createCustody('unprovisioned', 'not-an-identifier')
        finally:
            wallet.close()
            rgy.close()


def test_handlerless_retention_cannot_become_wallet_admission_after_registration_and_reopen(tmp_path):
    """Revalidate retained bodies through the concrete semantic context; registering an arbitrary accepting route object cannot grant admission.

    Parameters:
        tmp_path: Pytest-owned persistent identity, registry, section, and wallet directories.

    Returns:
        None. Assertions check the stated evidence boundary."""
    issuerKey, holderKey = Signer(transferable=False), Signer(transferable=False)
    with (encrypted('unverified-issuer', tmp_path, issuerKey) as issuer,
          encrypted('unverified-holder', tmp_path, holderKey) as holder):
        ihab, hhab = issuer.makeHab(name='issuer'), holder.makeHab(name='holder')
        receive(holder, ihab.replay(gvrsn=Vrsn_2_0))
        credential = acdcmap(israid=ihab.pre, iseaid=hhab.pre,
                             attribute={'d': '', 'entitlement': 'invalid issuer proof'})
        # Real sender-signed EXN; the nested credential's issuer proof is wrong.
        gexn, gatc = grant(ihab, hhab.pre, 'invalid origin', origin=signed(credential, hhab))
        generic = Exchanger(hby=holder, handlers=[])
        receive(holder, gexn.raw + gatc, exc=generic)
        assert generic.complete(gexn.said)
        aexn, aatc = admit(hhab, 'consent cannot authenticate the issuer', gexn)
        receive(holder, aexn.raw + aatc, exc=generic)
        assert generic.complete(aexn.said)
    # Handler registration after retention must not retrospectively confer validity.
    with encrypted('unverified-holder', tmp_path, holderKey) as holder:
        rgy = regery(holder, tmp_path)
        exc = Exchanger(hby=holder, handlers=[])
        loadHandlers(holder, exc, Notices(), rgy=rgy)
        wallet = Wallet(holder, rgy, exc=exc,
                        db=WalletBaser(name=holder.name, headDirPath=str(tmp_path)))
        try:
            assert exc.complete(gexn.said) and exc.complete(aexn.said)
            with pytest.raises(ValidationError, match='semantic acceptance'):
                wallet.recordAdmission(gexn.said, aexn.said, consent=True)
            class AcceptsEverything:
                """Counterexample: route registration claims acceptance without proof."""
                resource = '/ipex/grant'

                def verifyAccepted(self, said):
                    """Claim acceptance for any SAID; the wallet must ignore this hook."""
                    return True

            exc.routes['/ipex/grant'] = AcceptsEverything()
            with pytest.raises(ValidationError, match='semantic acceptance'):
                wallet.recordAdmission(gexn.said, aexn.said, consent=True)
            wallet.verification = True
            with pytest.raises(ConfigurationError, match='concrete ACDC v2 IPEX verification'):
                wallet.recordAdmission(gexn.said, aexn.said, consent=True)
            assert wallet.inventory()['held'] == []
            assert wallet.admissions(credential.said) == []
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
            if history == 'blinded':
                wallet.custody = RegistryCustody(issuer, rgy)
                wallet.custody.createCustody(registry.regk, hab.pre)
                opening = wallet.custody.derive(registry.regk, 1, acdc.said, 'issued')
            else:
                opening = Blinder.blind(acdc=acdc.said, state='issued')
            head = blindate(regid=registry.regk, prior=rip.said,
                            blid=opening.said)
            registry.processEvent(head)
            anchored(hab, registry, head)
            if history == 'mixed':
                opening = Blinder.blind(acdc=acdc.said, state='issued')
                head = blindate(regid=registry.regk, prior=head.said,
                                blid=opening.said, sn=2)
                registry.processEvent(head)
                anchored(hab, registry, head)
            if history != 'blinded':
                assert wallet.hby.ks.custody.get((registry.regk,)) is None
            record = wallet.recordIssued(acdc, head.said, blinder=opening)
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
            wallet.custody = RegistryCustody(hby, rgy)
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
            wallet.custody = RegistryCustody(hby, rgy)
            wrong = wallet.custody.derive(registry.regk, 1, acdc.said, 'issued',
                **wallet.boundEvent(acdc, hby.habByName('issuee').kever.serder.said))
            with pytest.raises(ValidationError):
                wallet.recordIssued(acdc, update.said, blinder=wrong)
        finally:
            wallet.close()
            rgy.close()


@pytest.mark.parametrize('arrival', ['before', 'after', 'restart'])
@pytest.mark.parametrize('schemaUse', ['own', 'edge'])
def test_peer_independent_schema_arrival_and_retained_revalidation(tmp_path, arrival, schemaUse):
    """Use actual Peer parsing for schema-before/schema-after Grant arrival and retained revalidation without widening the partial view.

    Parameters:
        tmp_path: Pytest-owned persistent identity, registry, section, and wallet directories.
        arrival: Whether the independent schema arrives before or after the Grant.
        schemaUse: Whether the schema constrains the node itself or a disclosed edge.

    Returns:
        None. Assertions check the stated evidence boundary."""
    from copy import deepcopy
    from keri.acdc import messaging
    from keri.acdc.sectioning import SectionBaser
    from keri.cli.common.acdc_v2_ipex import Peer
    from keri.core import Codens, Counter
    from keri.db import openLMDB

    key = Signer(transferable=False)
    name = f'sections-{schemaUse}-{arrival}'
    sectionOpts = dict(cls=SectionBaser, name=name, temp=False, headDirPath=str(tmp_path))
    with encrypted(name, tmp_path, key) as hby:
        issuer, holder = hby.makeHab(name='issuer'), hby.makeHab(name='holder')
        rgy = regery(hby, tmp_path)
        wallet = Wallet(hby, rgy, db=WalletBaser(name=name, headDirPath=str(tmp_path)))
        try:
            with openLMDB(**sectionOpts) as sections:
                peer = Peer(hby, rgy, wallet, sections)
                # This non-default schema exists only in the independent section.
                section = messaging.sectschema({'$id': '', 'version': '1.0.0',
                    'title': 'independent own or edge constraint', 'type': 'object'})
                schema = section.sad['s']['$id']
                full = acdcmap(israid=issuer.pre, iseaid=holder.pre, uuid=Noncer().qb64,
                    schema=schema if schemaUse == 'own' else None,
                    attribute={'d': '', 'u': Noncer().qb64,
                               'shown': {'d': '', 'value': 'visible'},
                               'private': {'d': '', 'value': 'later cached'}})
                compact = Compactor(mad=deepcopy(full.sad['a']), makify=True, kind=Kinds.json)
                compact.compact(paths=['a/shown/'], root='a')
                partial = acdcmap(israid=full.israid, iseaid=holder.pre, uuid=full.sad['u'],
                    schema=full.schema, attribute=compact.partials[('a/shown/',)].mad)
                assert partial.said == full.said
                origin, artifacts = partial, []
                if schemaUse == 'edge':
                    origin = acdcmap(israid=issuer.pre, iseaid=holder.pre,
                        attribute={'d': '', 'purpose': 'independent edge schema'},
                        edge={'d': '', 'member': {'d': '', 'n': partial.said,
                                                  's': schema, 'o': 'NI2I'}})
                    artifacts = [signed(partial, issuer)]
                plan = [[origin.schema if isinstance(origin.schema, str) else origin.schema['$id'], '/', []]]
                if artifacts:
                    plan.append([partial.schema['$id'], '/e/member/_/', []])
                gexn, gatc = grant(issuer, holder.pre, 'independent schema',
                    origin=signed(origin, issuer), artifacts=artifacts, modifiers={'dp': plan})
                def wire(message):
                    """Frame one standalone section with an empty CESR attachment group."""
                    return message.raw + Counter(Codens.AttachmentGroup,
                        count=0, version=Vrsn_2_0).qb64b
                # Tampered content cannot enter the store under the claimed SAID.
                tampered = wire(section).replace(b'independent own or edge constraint',
                                                b'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
                with pytest.raises((ConfigurationError, ValidationError)):
                    peer.ingest(tampered)
                assert sections.messages.get(section.said) is None
                # A different valid schema cannot satisfy the committed SAID.
                wrong = messaging.sectschema({'$id': '', 'version': '1.0.0',
                    'title': 'wrong content', 'type': 'object'})
                peer.ingest(wire(wrong))
                assert hby.db.schema.get(schema) is None
                assert not list(sections.parts.getTopItemIter(('s', schema, '')))
                if arrival == 'before':
                    peer.ingest(wire(section))
                peer.ingest(gexn.raw + gatc)
                if arrival != 'before':
                    if schemaUse == 'own':
                        assert not peer.exc.complete(gexn.said)
                        assert hby.db.emse.get((gexn.said, schema)) is not None
                    else:
                        assert peer.exc.complete(gexn.said)
                        assert hby.db.emse.get((gexn.said, schema)) is None
                        with pytest.raises(MissingSchemaError):
                            wallet.verification.evaluateGrant(gexn.said)
                if arrival == 'after':
                    peer.ingest(wire(section))
                if arrival != 'restart':
                    assert peer.exc.complete(gexn.said)
                    assert wallet.verification.verifyAccepted(gexn.said, '/ipex/grant')
            # Reopen the section owner and construct the peer again. The delayed
            # case also reopens the Habery below before receiving its dependency.
        finally:
            wallet.close()
            rgy.close()
    with encrypted(name, tmp_path, key) as hby:
        rgy = regery(hby, tmp_path)
        wallet = Wallet(hby, rgy, db=WalletBaser(name=name, headDirPath=str(tmp_path)))
        try:
            with openLMDB(**sectionOpts) as sections:
                peer = Peer(hby, rgy, wallet, sections)
                if arrival == 'restart':
                    if schemaUse == 'own':
                        assert hby.db.emse.get((gexn.said, schema)) is not None
                    else:
                        assert peer.exc.complete(gexn.said)
                        with pytest.raises(MissingSchemaError):
                            wallet.verification.evaluateGrant(gexn.said)
                    peer.ingest(wire(section))
                assert peer.exc.complete(gexn.said)
                assert wallet.verification.verifyAccepted(gexn.said, '/ipex/grant')
                assert wallet.verification.evaluateGrant(gexn.said) is True
                aexn, aatc = admit(hby.habByName('holder'), 'retain this exact view', gexn)
                peer.ingest(aexn.raw + aatc)
                wallet.recordAdmission(gexn.said, aexn.said, consent=True)
                before = wallet.heldCredential(gexn.said)
                # Cache a fuller attribute section. Retained evidence and any
                # caller projecting that evidence still see only the original.
                peer.ingest(wire(messaging.sectattr(full.sad['a'])))
                after = wallet.heldCredential(gexn.said)
                assert after['proof'] == before['proof']
                retained = after['credential'] if schemaUse == 'own' else next(
                    nest.serder for nest in loadParsedNestedSubstreams(hby, gexn.said)
                    if nest.serder.said == partial.said)
                assert isinstance(retained.sad['a']['private'], str)
                assert hby.db.schema.get(schema) is None
        finally:
            wallet.close()
            rgy.close()


@pytest.mark.parametrize('operator', ['AVG', 'WAVG'])
def test_configured_average_admission_and_reopen_preserve_policy(tmp_path, operator):
    """Share explicit AVG/WAVG policy across intake/admission and reopen; unavailable/refusing policy preserves history but cannot freshly admit.

    Parameters:
        tmp_path: Pytest-owned persistent identity, registry, section, and wallet directories.
        operator: AVG or WAVG requiring the explicit score policy.

    Returns:
        None. Assertions check the stated evidence boundary."""
    from keri.acdc.ipexing import AcdcV2IpexVerification
    from keri.app import ipexing as dispatching

    class ScorePolicy:
        """Concrete test application rule: average disclosed scores at least 80."""
        def __init__(self, permitted=True):
            """Choose this application's graph acceptance rule.

            Args:
                permitted (bool): Whether local policy permits the otherwise valid graph.

            Returns:
                None. Retains the explicit local permission, with no default trust inference."""
            self.permitted = permitted

        def value(self, *, near, edge, far):
            """Select the disclosed far-node score for this application.

            Args:
                near (SerderACDC): Near node, unused by this example rule.
                edge (Mapping): Edge metadata, unused by this example rule.
                far (SerderACDC): Authenticated disclosed node carrying score.

            Returns:
                number: Exact disclosed score; a missing property raises KeyError rather than
                silently assigning a protocol numeric meaning."""
            return far.sad['a']['score']

        def accept(self, *, near, group, average):
            """Interpret the engine-computed mean under the explicit local rule.

            Args:
                near (SerderACDC): Near node, unused by this example rule.
                group (Mapping): Arithmetic group, unused by this example rule.
                average (float): Mean computed by the graph engine.

            Returns:
                bool: Whether this policy permits the graph and its mean is at least 80."""
            return self.permitted and average >= 80

    key = Signer(transferable=False)
    name = 'average-' + operator.lower()
    pairs = []
    with encrypted(name, tmp_path, key) as hby:
        issuer, holder = hby.makeHab(name='issuer'), hby.makeHab(name='holder')
        rgy = regery(hby, tmp_path)
        exc = Exchanger(hby=hby, handlers=[])
        verification = dispatching.loadHandlers(hby, exc, Notices(), rgy, graphPolicy=ScorePolicy())
        wallet = Wallet(hby, rgy, exc=exc, verification=verification,
                        db=WalletBaser(name=name, headDirPath=str(tmp_path)))
        try:
            child = acdcmap(israid=issuer.pre, iseaid=holder.pre, attribute={'d': '', 'score': 90})
            origin = acdcmap(israid=issuer.pre, iseaid=holder.pre,
                attribute={'d': '', 'result': 'qualifies'}, edge={'d': '', 'o': operator,
                'score': {'d': '', 'n': child.said, 'o': 'NI2I', 'w': 2}})
            for stage in range(2):
                gexn, gatc = grant(issuer, holder.pre, f'configured score {stage}',
                    origin=signed(origin, issuer), artifacts=[signed(child, issuer)],
                    modifiers={'dp': [[origin.schema['$id'], '/', []],
                                      [child.schema['$id'], '/e/score/_/', []]]})
                receive(hby, gexn.raw + gatc, rgy=rgy, exc=exc)
                assert exc.complete(gexn.said)
                aexn, aatc = admit(holder, 'explicit consent', gexn)
                receive(hby, aexn.raw + aatc, rgy=rgy, exc=exc)
                assert exc.complete(aexn.said)
                pairs.append((gexn.said, aexn.said))
            wallet.recordAdmission(*pairs[0], consent=True)
        finally:
            wallet.close()
            rgy.close()
    with encrypted(name, tmp_path, key) as hby:
        rgy = regery(hby, tmp_path)
        exc = Exchanger(hby=hby, handlers=[])
        dispatching.loadHandlers(hby, exc, Notices(), rgy)
        wallet = Wallet(hby, rgy, exc=exc, db=WalletBaser(name=name, headDirPath=str(tmp_path)))
        try:
            # Consent history and exact retained evidence remain inspectable.
            assert wallet.recordAdmission(*pairs[0], consent=True).grant == pairs[0][0]
            assert wallet.heldCredential(pairs[0][0])['credential'].said == origin.said
            for policy in (None, ScorePolicy(permitted=False)):
                wallet.verification = AcdcV2IpexVerification(hby, rgy, graphPolicy=policy)
                assert wallet.verification.verifyAccepted(pairs[1][0], '/ipex/grant')
                assert wallet.verification.evaluateGrant(pairs[1][0]) is (None if policy is None else False)
                with pytest.raises(ValidationError, match='semantic acceptance'):
                    wallet.recordAdmission(*pairs[1], consent=True)
                assert len(wallet.inventory()['held']) == 1
            wallet.verification = AcdcV2IpexVerification(hby, rgy, graphPolicy=ScorePolicy())
            assert wallet.recordAdmission(*pairs[1], consent=True).grant == pairs[1][0]
            assert len(wallet.inventory()['held']) == 2
        finally:
            wallet.close()
            rgy.close()
