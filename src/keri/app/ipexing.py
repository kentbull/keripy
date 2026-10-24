"""Application composition of the existing legacy and ACDC v2 IPEX processors."""
from keri.acdc import ipexing as acdc_v2_ipexing
from keri.vc import protocoling as legacy


class IpexHandler:
    """Select protocol semantics from the EXN body, independently of CESR genus."""
    acceptsSscs = True
    acceptsEvidence = True

    def __init__(self, resource, hby, notifier, rgy, *, graphPolicy=None, sections=None, verification=None):
        """Compose v1/v2 handlers for one route with explicit ACDC v2 IPEX context.

        Args:
            resource (str): IPEX route dispatched by EXN protocol version.
            hby (Habery): Shared KEL/EXN evidence owner.
            notifier: Accepted-message notification receiver.
            rgy (Regery): ACDC v2 registry evidence owner.
            graphPolicy: Optional explicit ACDC v2 graph policy.
            sections (SectionBaser | None): Parser-owned ACDC v2 schema evidence.
            verification (AcdcV2IpexVerification | None): Shared ACDC v2 IPEX context.

        Returns:
            None

        Raises:
            ConfigurationError: Shared ACDC v2 IPEX context has different owners.
        """
        self.resource = resource
        self.acdcV2 = acdc_v2_ipexing.IpexHandler(resource, hby, notifier, rgy=rgy,
                                         graphPolicy=graphPolicy, sections=sections, verification=verification)
        self.legacy = legacy.IpexHandler(resource, hby, notifier)
        self.acceptsMissingEvidence = resource == '/ipex/grant'

    def verify(self, serder, attachments=None, **kwa):
        """Dispatch semantic verification from the serialized EXN protocol version.

            Args:
                serder: Parsed EXN whose validated version selects v1 or ACDC v2 IPEX behavior.
                attachments: Legacy attachment collection, forwarded to its processor.
                **kwa: ACDC v2 IPEX nests, sender source couples, and authenticated evidence.

            Returns:
                bool: Selected protocol processor's semantic verdict.

            ACDC v2 IPEX nests/source couples cannot give v1 traffic v2 meaning. Missing ACDC v2 IPEX
            dependencies propagate through the selected processor's escrow exceptions."""
        if serder.pvrsn.major == 1:
            # A v1 EXN cannot acquire v2 meaning from a genus-2 envelope.
            if kwa.get('nests') or kwa.get('sscs'):
                return False
            return self.legacy.verify(serder, attachments=attachments)
        return self.acdcV2.verify(serder, attachments=attachments,
            **{key: kwa[key] for key in ('nests', 'sscs', 'evidence') if key in kwa})

    def verifyEvidence(self, serder, **kwa):
        """Apply the selected protocol's supplemental-evidence policy.

            Args:
                serder: Parsed EXN selecting legacy or ACDC v2 IPEX semantics.
                **kwa: Verified signatures, source seals, and missing/invalid evidence flags.

            Returns:
                tuple | None: Accepted ACDC v2 IPEX evidence groups or rejection. Legacy accepts
                    no supplemental ACDC v2 IPEX evidence and returns three empty lists."""
        if serder.pvrsn.major == 1:
            if any(kwa.get(key) for key in ('tsgs', 'cigars', 'sourceSeals', 'invalid', 'missing')):
                return None
            return [], [], []
        return self.acdcV2.verifyEvidence(serder, **kwa)

    def handle(self, serder, attachments=None, **kwa):
        """Notify the selected processor after Exchanger has accepted semantics.

            Args:
                serder: Accepted v1 or ACDC v2 IPEX EXN.
                attachments: Legacy attachment data forwarded to the concrete handler.
                **kwa: Additional dispatch metadata not used for notifications.

            Returns:
                None. The protocol-specific notifier may write application notices;
                notification itself does not create wallet consent."""
        handler = self.legacy if serder.pvrsn.major == 1 else self.acdcV2
        handler.handle(serder, attachments=attachments)


def loadHandlers(hby, exc, notifier, rgy, *, graphPolicy=None, sections=None):
    """Register version dispatchers and return their shared AcdcV2IpexVerification.

    Args:
        hby (Habery): Shared KEL/EXN evidence owner.
        exc (Exchanger): Router receiving every IPEX route.
        notifier: Accepted-message notification receiver.
        rgy (Regery): ACDC v2 registry evidence owner.
        graphPolicy: Optional explicit ACDC v2 graph policy.
        sections (SectionBaser | None): Independent schema store used by parsing.

    Returns:
        AcdcV2IpexVerification: Concrete context for configured wallet admission.
    """
    verification = acdc_v2_ipexing.AcdcV2IpexVerification(hby, rgy, graphPolicy=graphPolicy, sections=sections)
    for verb in acdc_v2_ipexing.Ipex:
        exc.addHandler(IpexHandler(f'/ipex/{verb}', hby, notifier, rgy,
                                  verification=verification))
    return verification
