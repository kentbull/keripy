"""Test-only composition of existing native credential evidence owners.

This fixture retains no application records or protocol behavior. Production
commands compose the required stores directly. The original view design was
adapted from Locksmith 3a5ad9ebcf98b4ec03baf1bbb91d928d49c168e4 (Apache-2.0).
"""
from keri.acdc.registraring import Registrar
from keri.acdc.ipexing import AcdcV2IpexVerification
from keri.vdr.eventing import Reger
from keri.app.credential_disclosing import boundEvent


class NativeOwners:
    """Issued records and authenticated retained IPEX disclosure retrieval.

    Optional RegistryCustody is an explicit collaborator for callers that derive
    openings. Inventory itself never invokes it or reads encrypted salt records.
    """
    def __init__(self, hby, rgy, *, exc=None, reger=None, verification=None, custody=None):
        """Compose local inventory and ACDC v2 IPEX verification without loading secrets.

        Args:
            hby (Habery): Authenticated local identity and retained exchange owner.
            rgy (Regery): ACDC v2 registry evidence owner.
            exc (Exchanger | None): Router used to check retained completion.
            reger (Reger | None): Borrow an existing credential owner, or open one
                that this facade closes. Native and legacy bytes use its normal tables.
            verification (AcdcV2IpexVerification | None): Explicit context returned by
                app.ipexing.loadHandlers for ACDC v2. None uses ordinary default policy;
                configured applications must pass their actual shared context.
            custody (RegistryCustody | None): Explicit optional private capability.
                None is normal for ordinary holders and public-only issuers.

        Returns:
            None
        """
        self.hby, self.rgy, self.exc = hby, rgy, exc
        self.custody = custody
        self.verification = (verification if verification is not None
                             else AcdcV2IpexVerification(hby, rgy))
        self.reger = reger if reger is not None else Reger(
            name=hby.name, base=hby.base, temp=hby.db.temp, headDirPath=hby.db.headDirPath)
        self.ownsReger = reger is None

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

    def inventory(self):
        """Combine issued Reger records and historical signed IPEX admission views.

        Returns:
            dict: Issued records and held views, without a second consent index
                or a claim about current credential standing.
        """
        return {'issued': Registrar(self.rgy).issuedRecords(self.reger),
                'held': self.verification.admissions()}

    def close(self):
        """Close this wallet's application environment after dependent work stops.

            Returns:
                None. Habery/Regery and a borrowed Reger remain caller-owned.
                An internally opened Reger closes here. RegistryCustody uses
                the independently owned Keeper; no secret is exported."""
        if self.ownsReger:
            self.reger.close()
