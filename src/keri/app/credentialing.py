"""Explicit native credential inventory over ordinary LMDB application records.

Private derivation custody is an optional registry_custody collaborator. Ordinary
issued/admitted inventory and retained disclosure retrieval never load its salt.

Protocol acceptance remains in KERIpy's registry and IPEX processors. The small
issued/admitted reference model is adapted from KERI Foundation Locksmith
3a5ad9ebcf98b4ec03baf1bbb91d928d49c168e4 (Apache-2.0 LICENSE; its package metadata
incorrectly declares MIT). No Locksmith runtime or GUI dependency is used.
"""
from dataclasses import dataclass, field
from base64 import b64encode, b64decode

from keri.acdc import regeventing
from keri.acdc.ipexing import NativeVerification
from keri.core import Blinder, BoundState, Number, SerderACDC
from keri.db import dbing, koming, subing
from keri.help import helping
from keri.kering import ConfigurationError, ValidationError
from keri.peer import exchanging
from .registry_custody import EncryptedCustody
from .credential_disclosing import boundEvent


@dataclass
class IssuedCredential:
    """Durable issued-history reference plus exact original credential bytes.

        credential/registry/controller/update bind accepted issuance. raw is base64
        under encoding='base64'; bound retains original issuee KEL coordinates for
        explicitly supplied bound openings, never a salt or current-standing claim."""
    credential: str
    registry: str
    controller: str
    update: str
    raw: str
    encoding: str
    bound: dict = field(default_factory=dict)


@dataclass
class AdmittedCredential:
    """Explicit local consent to one exact grant/admit disclosure pair.

        credential and holder identify its origin/recipient; grant and admit retain
        exchange provenance. admitted is local consent time, not issuer publication."""
    credential: str
    grant: str
    admit: str
    holder: str
    admitted: str


class WalletBaser(dbing.LMDBer):
    """Application records; no secret or consent state belongs in public RegBaser."""
    TailDirPath = 'keri/wallet'
    AltTailDirPath = '.keri/wallet'

    def reopen(self, **kwa):
        """Open existing inventory indexes and the unchanged optional custody table.

            Args:
                **kwa: Ordinary LMDBer path/reopen settings.

            Returns:
                bool: Whether the application environment is open.

            The custody Komer is storage schema only: opening it does not enumerate or
            decrypt secrets. Consent and its rebuildable credential index share a store."""
        super().reopen(**kwa)
        self.custody = koming.Komer(db=self, subkey='custody.', klas=EncryptedCustody)
        self.issued = koming.Komer(db=self, subkey='issued.', klas=IssuedCredential)
        self.admitted = koming.Komer(db=self, subkey='admitted.', klas=AdmittedCredential)
        # The index is rebuildable from admitted records, but is committed with them.
        self.credentials = subing.Suber(db=self, subkey='credential-grants.')
        return self.opened


class Wallet:
    """Local issued/admitted references and immutable retained disclosure retrieval.

    Optional RegistryCustody is an explicit collaborator for callers that derive
    openings. Inventory itself never invokes it or reads encrypted salt records.
    """
    def __init__(self, hby, rgy, *, exc=None, db=None, verification=None, custody=None):
        """Compose local inventory and native verification without loading secrets.

        Args:
            hby (Habery): Authenticated local identity and retained exchange owner.
            rgy (Regery): Native registry evidence owner.
            exc (Exchanger | None): Router used to check retained completion.
            db (WalletBaser | None): Existing inventory/custody store, or create one.
            verification (NativeVerification | None): Explicit context returned by
                native/app IPEX loadHandlers. None uses ordinary default policy;
                configured applications must pass their actual shared context.
            custody (RegistryCustody | None): Explicit optional private capability.
                None is normal for ordinary holders and public-only issuers.

        Returns:
            None
        """
        self.hby, self.rgy, self.exc = hby, rgy, exc
        self.custody = custody
        self.verification = (verification if verification is not None
                             else NativeVerification(hby, rgy))
        self.db = db if db is not None else WalletBaser(
            name=hby.name, base=hby.base, temp=hby.temp)

    def boundEvent(self, acdc, said):
        """Resolve a selected accepted, witnessed issuee KEL event for derivation.

            Args:
                acdc (SerderACDC): Credential defining the issuee whose KEL is referenced.
                said (str): Exact selected issuee event digest, not today's implicit head.

            Returns:
                dict: Explicit bound=True, sequence number, and digest for opening creation.

            Raises:
                ValidationError: Event is missing, unaccepted, or not fully witnessed.

            This public evidence lookup loads no custody and does not derive an opening."""
        return boundEvent(self.hby, acdc, said)









    def close(self):
        """Close this wallet's application environment after dependent work stops.

            Returns:
                None. Habery/Regery remain caller-owned. Optional RegistryCustody shares
                this store and must not access it after closing; no secret is exported."""
        self.db.close()
