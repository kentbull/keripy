"""Application composition of the existing legacy and native IPEX processors."""
from keri.acdc import ipexing as native
from keri.vc import protocoling as legacy


class IpexHandler:
    """Select protocol semantics from the EXN body, independently of CESR genus."""
    acceptsSscs = True
    acceptsEvidence = True

    def __init__(self, resource, hby, notifier, rgy, *, graphPolicy=None):
        self.resource = resource
        self.native = native.IpexHandler(resource, hby, notifier, rgy=rgy,
                                         graphPolicy=graphPolicy)
        self.legacy = legacy.IpexHandler(resource, hby, notifier)
        self.acceptsMissingEvidence = resource == '/ipex/grant'

    def verify(self, serder, attachments=None, **kwa):
        if serder.pvrsn.major == 1:
            # A v1 EXN cannot acquire v2 meaning from a genus-2 envelope.
            if kwa.get('nests') or kwa.get('sscs'):
                return False
            return self.legacy.verify(serder, attachments=attachments)
        return self.native.verify(serder, attachments=attachments,
            **{key: kwa[key] for key in ('nests', 'sscs', 'evidence') if key in kwa})

    def verifyEvidence(self, serder, **kwa):
        if serder.pvrsn.major == 1:
            if any(kwa.get(key) for key in ('tsgs', 'cigars', 'sourceSeals', 'invalid', 'missing')):
                return None
            return [], [], []
        return self.native.verifyEvidence(serder, **kwa)

    def handle(self, serder, attachments=None, **kwa):
        handler = self.legacy if serder.pvrsn.major == 1 else self.native
        handler.handle(serder, attachments=attachments)


def loadHandlers(hby, exc, notifier, rgy, *, graphPolicy=None):
    for verb in native.Ipex:
        exc.addHandler(IpexHandler(f'/ipex/{verb}', hby, notifier, rgy,
                                  graphPolicy=graphPolicy))
