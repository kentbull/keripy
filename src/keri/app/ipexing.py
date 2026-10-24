"""Application composition of the existing legacy and native IPEX processors."""
from keri.acdc import ipexing as native
from keri.vc import protocoling as legacy


class IpexHandler:
    """Select protocol semantics from the EXN body, independently of CESR genus."""
    acceptsSscs = True
    acceptsEvidence = True

    def __init__(self, resource, hby, notifier, rgy, *, graphPolicy=None, sections=None, verification=None):
        """Compose v1/v2 handlers for one route with explicit native context.

        Args:
            resource (str): IPEX route dispatched by EXN protocol version.
            hby (Habery): Shared KEL/EXN evidence owner.
            notifier: Accepted-message notification receiver.
            rgy (Regery): Native registry evidence owner.
            graphPolicy: Optional explicit native graph policy.
            sections (SectionBaser | None): Parser-owned native schema evidence.
            verification (NativeVerification | None): Shared native context.

        Returns:
            None

        Raises:
            ConfigurationError: Shared native context has different owners.
        """
        self.resource = resource
        self.native = native.IpexHandler(resource, hby, notifier, rgy=rgy,
                                         graphPolicy=graphPolicy, sections=sections, verification=verification)
        self.legacy = legacy.IpexHandler(resource, hby, notifier)
        self.acceptsMissingEvidence = resource == '/ipex/grant'

    def verify(self, serder, attachments=None, **kwa):
        """Dispatch semantic verification from the serialized EXN protocol version.

            Args:
                serder: Parsed EXN whose validated version selects v1 or native behavior.
                attachments: Legacy attachment collection, forwarded to its processor.
                **kwa: Native nests, sender source couples, and authenticated evidence.

            Returns:
                bool: Selected protocol processor's semantic verdict.

            Native nests/source couples cannot give v1 traffic v2 meaning. Missing native
            dependencies propagate through the selected processor's escrow exceptions."""
        if serder.pvrsn.major == 1:
            # A v1 EXN cannot acquire v2 meaning from a genus-2 envelope.
            if kwa.get('nests') or kwa.get('sscs'):
                return False
            return self.legacy.verify(serder, attachments=attachments)
        return self.native.verify(serder, attachments=attachments,
            **{key: kwa[key] for key in ('nests', 'sscs', 'evidence') if key in kwa})

    def verifyEvidence(self, serder, **kwa):
        """Apply the selected protocol's supplemental-evidence policy.

            Args:
                serder: Parsed EXN selecting legacy or native semantics.
                **kwa: Verified signatures, source seals, and missing/invalid evidence flags.

            Returns:
                tuple | None: Accepted native evidence groups or rejection. Legacy accepts
                    no supplemental native evidence and returns three empty lists."""
        if serder.pvrsn.major == 1:
            if any(kwa.get(key) for key in ('tsgs', 'cigars', 'sourceSeals', 'invalid', 'missing')):
                return None
            return [], [], []
        return self.native.verifyEvidence(serder, **kwa)

    def handle(self, serder, attachments=None, **kwa):
        """Notify the selected processor after Exchanger has accepted semantics.

            Args:
                serder: Accepted legacy/native EXN.
                attachments: Legacy attachment data forwarded to the concrete handler.
                **kwa: Additional dispatch metadata not used for notifications.

            Returns:
                None. The protocol-specific notifier may write application notices;
                notification itself does not create wallet consent."""
        handler = self.legacy if serder.pvrsn.major == 1 else self.native
        handler.handle(serder, attachments=attachments)


def loadHandlers(hby, exc, notifier, rgy, *, graphPolicy=None, sections=None):
    """Register version dispatchers and return their shared NativeVerification.

    Args:
        hby (Habery): Shared KEL/EXN evidence owner.
        exc (Exchanger): Router receiving every IPEX route.
        notifier: Accepted-message notification receiver.
        rgy (Regery): Native registry evidence owner.
        graphPolicy: Optional explicit native graph policy.
        sections (SectionBaser | None): Independent schema store used by parsing.

    Returns:
        NativeVerification: Concrete context for configured wallet admission.
    """
    verification = native.NativeVerification(hby, rgy, graphPolicy=graphPolicy, sections=sections)
    for verb in native.Ipex:
        exc.addHandler(IpexHandler(f'/ipex/{verb}', hby, notifier, rgy,
                                  verification=verification))
    return verification
