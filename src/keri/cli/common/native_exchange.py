"""Native IPEX command composition using retained wallet views and core proofs."""
from contextlib import ExitStack
from dataclasses import asdict, replace
import json
import math
from pathlib import Path
from urllib.parse import urlsplit

import falcon
from hio.base import doing
from hio.core import http

from keri import Vrsn_2_0, Kinds
from keri.acdc import ipexing
from keri.acdc.regeventing import issuerRegistry, _blindCandidates
from keri.acdc.sectioning import SectionBaser, Sectioner
from keri.app import GroupHab, Notifier
from keri.app.native_grouping import NativeGroup
from keri.app.credential_disclosing import registryProof
from keri.app.httping import CESR_CONTENT_TYPE
from keri.app.indirecting import createHttpServer
from keri.app.evidencing import EvidenceContext, signedQuery, KEL_DEPENDENCIES
from keri.core import Compactor, Diger, Number, Parser, SerderACDC, messagize
from keri.kering import ConfigurationError, MissingChainError, MissingSchemaError
from keri.peer import exchanging
from keri.db import openLMDB
from keri.cli.common import native, cesr_sending


class Notices:
    """Adapt core notification calls when retained evidence drives CLI results.

    This adapter owns no notification database. Receiving a notification is not
    wallet consent, protocol acceptance, or transport acknowledgement."""
    def add(self, attrs):
        """Ignore transient attrs; CLI decisions read the verified retained EXNs.

        Return None and create no notification store or acceptance side effect."""
        pass


class Peer:
    """Share core proof processors between command intake and explicit admission.

    The caller owns identity, registry, wallet, and independent section stores.
    The peer composes verification and escrow processing; it grants no automatic
    wallet consent and does not weaken the native KRAM requirement."""
    def __init__(self, hby, rgy, wallet, sections, *, graphPolicy=None):
        """Share section evidence and native policy across intake and admission.

        Args:
            hby (Habery): Authenticated local identity and KEL/EXN evidence.
            rgy (Regery): Native registry evidence owner.
            wallet (Wallet): Inventory owner configured to use this peer's context.
            sections (SectionBaser): Independently received section store; caller
                owns closing it, including across CLI invocations/reopen.
            graphPolicy: Optional explicit graph validity/averaging policy.

        Returns:
            None
        """
        self.hby, self.rgy, self.wallet = hby, rgy, wallet
        self.evidence = EvidenceContext(hby, reger=rgy.baser)
        self.exc = exchanging.Exchanger(hby, handlers=[])
        self.scy = Sectioner(db=hby.db, sections=sections)
        wallet.verification = ipexing.loadHandlers(hby, self.exc, Notices(), rgy,
                                                  graphPolicy=graphPolicy, sections=sections)
        wallet.exc = self.exc
        self.parser = Parser(kvy=self.evidence.kvy, rgy=self.evidence.rever,
                             exc=self.exc, scy=self.scy, version=Vrsn_2_0, local=False)

    def ingest(self, raw):
        """Process complete native frames from raw bytes and report EXN acceptance.

        Copy raw before incremental framing so the caller's bytes are unchanged.
        Dispatch through the normal KEL, registry, section, and exchange processors;
        only concrete retained dependency errors remain for escrow retry. Return a
        list of exchange SAIDs with their current core accepted flags. Incomplete
        framing raises ConfigurationError; other proof failures propagate. Neither
        intake nor acceptance records wallet consent or claims delivery."""
        ims = bytearray(raw)
        grants = []
        while ims:
            size = len(ims)
            dom = self.parser.parseOne(ims=ims, processive=False)
            if dom is None or dom.serder is None or len(ims) >= size:
                raise ConfigurationError('incomplete native IPEX stream')
            if dom.serder.ilk == 'exn':
                grants.append(dom.serder.said)
            try:
                self.parser.msgProcess(asdict(dom), kvy=self.evidence.kvy,
                    rgy=self.evidence.rever, exc=self.exc, scy=self.scy,
                    tvy=None, vry=None, rvy=None)
            except KEL_DEPENDENCIES + (MissingChainError, MissingSchemaError):
                # The concrete core processor retained this exact dependency;
                # unrelated proof or framing failures must still propagate.
                pass
        self.process()
        return [{'exchange': said, 'accepted': self.exc.complete(said)} for said in grants]

    def process(self):
        """Retry the shared KEL, registry, and exchange dependency escrows.

        Return None; core processors determine which retained evidence can advance.
        Scheduling this method does not manufacture observer freshness or admission."""
        self.evidence.kvy.processEscrows()
        self.evidence.rever.processEscrows()
        self.exc.processEscrow()






class Intake:
    """Expose raw CESR intake for a shared native peer without wallet consent."""
    def __init__(self, peer):
        """Retain the peer whose core processors own this endpoint's evidence.

        No separate parser, identity, or store is created by the HTTP adapter."""
        self.peer = peer

    def on_post(self, req, rep):
        """Dispatch the request's bounded CESR bytes and return intake status 202.

        req and rep are Falcon request/response objects. Require application/cesr
        or raise HTTPUnsupportedMediaType; framing/proof errors propagate through
        the framework. The JSON lists core exchange acceptance, not wallet consent
        or recipient delivery, and this adapter records no admission itself."""
        if (req.content_type or '').split(';')[0] != CESR_CONTENT_TYPE:
            raise falcon.HTTPUnsupportedMediaType()
        rep.media = self.peer.ingest(req.bounded_stream.read())
        rep.status = falcon.HTTP_202

    # StreamPoster uses PUT at the recipient endpoint root. Both methods enter
    # the same native verifier and neither implies wallet admission.
    on_put = on_post
