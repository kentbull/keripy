"""Optional registry capabilities never gate ordinary retained credential use."""
from contextlib import ExitStack
from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0
from keri.acdc import Registrar, acdcmap, admit, blindate, grant, loadHandlers
from keri.app import openHby
from keri.app.configing import Configer
from keri.app.credentialing import Wallet
from keri.app.registry_custody import RegistryCustody
from keri.core import Blinder, Signer
from keri.kering import AuthError, ConfigurationError, ValidationError
from keri.peer import Exchanger
from tests.app.test_acdc_v2_wallet import (Notices, anchored, encrypted,
                                           receive, regery, signed)


@pytest.mark.parametrize('publicTail', [False, True])
def test_explicit_custody_provisioning_allows_public_prefix_but_never_recreates_after_bup(tmp_path, publicTail):
    """Allow explicit custody provisioning after public history, then forbid salt recreation after any accepted blinded update.

    Parameters:
        tmp_path: Pytest-owned persistent registry/wallet directories.
        publicTail: Whether an accepted public update follows the blinded history before custody loss.

    Returns:
        None. Assertions check the stated evidence boundary."""
    key = Signer(transferable=False)
    with encrypted('custody-history', tmp_path, key) as hby:
        issuer = hby.makeHab(name='issuer')
        rgy = regery(hby, tmp_path)
        wallet = Wallet(hby, rgy)
        try:
            registry = Registrar(rgy=rgy).makeRegistry(name='mixed', prefix=issuer.pre)
            rip = rgy.store.event(registry.regk)
            anchored(issuer, registry, rip)
            credential = acdcmap(israid=issuer.pre, regid=registry.regk,
                                 attribute={'d': '', 'role': 'public then blinded'})
            publicOpening = Blinder.blind(acdc=credential.said, state='issued')
            public = blindate(registry.regk, rip.said, publicOpening.said)
            registry.processEvent(public)
            anchored(issuer, registry, public)
            wallet.rgy.store.retainOpening(public, publicOpening)
            assert wallet.custody is None
            assert not list(wallet.hby.ks.custody.getTopItemIter())
            wallet.custody = RegistryCustody(hby, rgy)
            info = wallet.custody.createCustody(registry.regk, issuer.pre)
            assert info.registry == registry.regk
            opening = wallet.custody.derive(registry.regk, 2, credential.said, 'issued')
            blinded = blindate(registry.regk, public.said, opening.said, sn=2)
            registry.processEvent(blinded)
            anchored(issuer, registry, blinded)
            if publicTail:
                tailOpening = wallet.custody.derive(
                    registry.regk, 3, credential.said, 'revoked')
                tail = blindate(registry.regk, blinded.said, tailOpening.said, sn=3)
                registry.processEvent(tail)
                anchored(issuer, registry, tail)
            # Simulate private record loss, preserving all authentic public history.
            assert wallet.hby.ks.custody.rem((registry.regk,))
            with pytest.raises(ConfigurationError, match='salt cannot be recreated'):
                wallet.custody.createCustody(registry.regk, issuer.pre)
            assert wallet.hby.ks.custody.get((registry.regk,)) is None
        finally:
            wallet.close()
            rgy.close()


def test_fresh_blinded_issuance_requires_supplied_common_verifier_opening(tmp_path):
    """Require supplied common-verifier proof for fresh blinded inventory while allowing an exact existing-history retry without deriving secrets.

    Parameters:
        tmp_path: Pytest-owned persistent registry/wallet directories.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with openHby(name='supplied-opening', version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name='issuer')
        rgy = regery(hby, tmp_path)
        wallet = Wallet(hby, rgy)
        try:
            registry = Registrar(rgy=rgy).makeRegistry(name='explicit', prefix=issuer.pre)
            rip = rgy.store.event(registry.regk)
            anchored(issuer, registry, rip)
            credential = acdcmap(israid=issuer.pre, regid=registry.regk,
                                 attribute={'d': '', 'role': 'supplied opening'})
            proof = Blinder.blind(acdc=credential.said, state='issued')
            event = blindate(registry.regk, rip.said, proof.said)
            registry.processEvent(event)
            anchored(issuer, registry, event)
            assert wallet.custody is None
            with pytest.raises(ConfigurationError, match='explicit event opening'):
                wallet.recordIssued(credential, event.said)
            with pytest.raises(ValidationError):
                wallet.recordIssued(credential, event.said,
                                    blinder=Blinder.blind(acdc=credential.said, state='revoked'))
            record = wallet.recordIssued(credential, event.said, blinder=proof)
            assert wallet.recordIssued(credential, event.said) == record
            assert not list(wallet.hby.ks.custody.getTopItemIter())
        finally:
            wallet.close()
            rgy.close()


@pytest.mark.parametrize('custodyState', ['absent', 'unencrypted', 'corrupt', 'old-aeid'])
def test_holder_retained_admission_and_onward_presentation_ignore_custody_after_reopen(tmp_path, custodyState):
    """Missing, unusable, and old-AEID custody cannot disable valid held evidence.

    Args:
        tmp_path: Separate durable stores for real issuer, holder, and verifier.
        custodyState: Capability failure to isolate from ordinary holder operations.

    Returns:
        None. Assertions use authenticated EXNs, actual consent, durable reopen,
        fresh holder signing, and independent onward IPEX semantic acceptance.
    """
    keys = {role: Signer(transferable=False) for role in ('issuer', 'holder', 'verifier')}
    name = 'holder-capability-' + custodyState

    def holderContext():
        """Reopen the same supported identity without migrating Keeper encryption.

        Returns:
            contextmanager: Existing encrypted or deliberately unencrypted Habery selected
            by the outer test case. Custody corruption/rotation never changes this choice."""
        if custodyState == 'unencrypted':
            return openHby(name=name, temp=False, headDirPath=str(tmp_path),
                cf=Configer(name=name, temp=True), version=Vrsn_2_0)
        return encrypted(name, tmp_path, keys['holder'])

    with ExitStack() as stack:
        issuer = stack.enter_context(encrypted('issuer-' + custodyState, tmp_path, keys['issuer']))
        holder = stack.enter_context(holderContext())
        ihab, hhab = issuer.makeHab(name='issuer'), holder.makeHab(name='holder')
        issuerKel = bytes(ihab.replay(gvrsn=Vrsn_2_0))
        receive(holder, issuerKel)
        rgy = regery(holder, tmp_path)
        stack.callback(rgy.close)
        exc = Exchanger(holder, handlers=[])
        loadHandlers(holder, exc, Notices(), rgy=rgy)
        wallet = Wallet(holder, rgy, exc=exc)
        stack.callback(wallet.close)
        assert wallet.custody is None
        if custodyState == 'unencrypted':
            assert not holder.mgr.aeid
        credential = acdcmap(israid=ihab.pre, iseaid=hhab.pre,
                             attribute={'d': '', 'role': 'retained independently'})
        original, atc = grant(ihab, hhab.pre, 'ordinary receipt', origin=signed(credential, ihab))
        receive(holder, original.raw + atc, rgy=rgy, exc=exc)
        response, ratc = admit(hhab, 'explicit holder consent', original)
        receive(holder, response.raw + ratc, rgy=rgy, exc=exc)
        wallet.verification.validateAdmission(original.said, response.said, consent=True)
        retained = wallet.verification.heldCredential(original.said)['proof']
        regid = None
        if custodyState in ('corrupt', 'old-aeid'):
            registry = Registrar(rgy=rgy).makeRegistry(name='private capability', prefix=hhab.pre)
            anchored(hhab, registry, rgy.store.event(registry.regk))
            regid = registry.regk
            wallet.custody = RegistryCustody(holder, rgy)
            wallet.custody.createCustody(regid, hhab.pre)
            if custodyState == 'corrupt':
                row = wallet.hby.ks.custody.get((regid,))
                row.cipher = 'corrupt ciphertext'
                wallet.hby.ks.custody.pin((regid,), row)
            else:
                row = holder.ks.custody.get((regid,))
                row.aeid = Signer(transferable=False).verfer.qb64
                holder.ks.custody.pin((regid,), row)
            with pytest.raises(AuthError):
                wallet.custody.derive(regid, 1, credential.said, 'issued')
        assert wallet.verification.heldCredential(original.said)['proof'] == retained
    with ExitStack() as stack:
        holder = stack.enter_context(holderContext())
        verifier = stack.enter_context(encrypted('verifier-' + custodyState, tmp_path, keys['verifier']))
        vhab = verifier.makeHab(name='verifier')
        hrgy, vrgy = regery(holder, tmp_path), regery(verifier, tmp_path)
        stack.callback(hrgy.close)
        stack.callback(vrgy.close)
        hexc, vexc = Exchanger(holder, handlers=[]), Exchanger(verifier, handlers=[])
        loadHandlers(holder, hexc, Notices(), rgy=hrgy)
        loadHandlers(verifier, vexc, Notices(), rgy=vrgy)
        wallet = Wallet(holder, hrgy, exc=hexc)
        stack.callback(wallet.close)
        assert wallet.custody is None
        inventory = wallet.inventory()
        assert set(inventory) == {'issued', 'held'}
        assert inventory['held'][0].grant == original.said
        if custodyState == 'unencrypted':
            assert not holder.mgr.aeid
        assert wallet.verification.heldCredential(original.said)['proof'] == retained
        if regid is not None:
            capability = RegistryCustody(holder, hrgy)
            with pytest.raises(AuthError):
                capability.derive(regid, 1, credential.said, 'issued')
        hhab = holder.habByName('holder')
        onward, patc = grant(hhab, vhab.pre, 'held proof after reopen', origin=retained)
        receive(verifier, issuerKel)
        receive(verifier, hhab.replay(gvrsn=Vrsn_2_0))
        receive(verifier, onward.raw + patc, rgy=vrgy, exc=vexc)
        assert vexc.complete(onward.said)
        assert wallet.verification.heldCredential(original.said)['proof'] == retained
