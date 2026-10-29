# -*- encoding: utf-8 -*-
"""
KERI
keri.app.grouping module

module for enveloping and forwarding KERI message
"""

from hio.base import doing
from hio.help import ogler

from ..kering import KeriError, ValidationError, Version, Versionage, Vrsn_1_0, Vrsn_2_0, Kinds, Ilks
from ..core import (Cipher, MtrDex, Number, Diger, Saider,
                    Prefixer, Kevery, Router,
                    Revery, Parser, SerderKERI,
                    Serder, NumDex, SealSource, messagize, exchange)
from ..peer import Exchanger, specialExchange, cloneMessage
from ..peer.exchanging import serializeParsedSubstream, loadParsedNestedSubstreams, verify

from .delegating import Anchorer
from .agenting import Receiptor, WitnessInquisitor

logger = ogler.getLogger()


class Counselor(doing.DoDoer):
    """
    Multisig event handling coordinator for group multisig events including delegation events.
    Handles escrows for partially signed multisig events, delegation events, and witness receipts.

    Doers:
        - swain (Anchorer): handles delegation anchoring
        - witq (WitnessInquisitor): queries witnesses for receipts
        - witDoer (Receiptor): sends witness receipts
        - escrowDo: processes escrows of group multisig identifiers waiting to be completed.
    """

    def __init__(self, hby, swain=None, proxy=None, version=None, kind=None, **kwa):
        """
        Initialize Counselor.

        Parameters:
            hby (Habery): database environment for local Habs
            swain (Anchorer): optional Anchorer for delegation anchoring
            proxy (Hab): optional proxy Hab to use for delegation anchoring if not using local Hab
            version (Versionage | None): optional explicit protocol version for
                delegation queries and the default Anchorer.
            kind (str | None): optional explicit serialization kind for
                delegation queries and the default Anchorer.
        """

        self.hby = hby
        self.version = version
        self.kind = kind if kind is not None else Kinds.json
        self.swain = swain if swain is not None else Anchorer(hby=self.hby,
                                                              version=self.version,
                                                              kind=self.kind)
        self.proxy = proxy
        self.witDoer = Receiptor(hby=self.hby)
        self.witq = WitnessInquisitor(hby=hby)

        doers = [self.swain, self.witq, self.witDoer, doing.doify(self.escrowDo)]

        super(Counselor, self).__init__(doers=doers, **kwa)

    def start(self, ghab, prefixer, number, diger):
        """ Begin processing of escrowed group multisig identifier

        Escrow identifier for multisigs, witness receipts and delegation anchor

        Parameters:
            ghab (Hab): group Habitat
            prefixer (Prefixer): prefixer of group identifier
            number (Number): number of event of group identifier
            diger (Diger): diger of event of group identifier

        Returns:
            bool: True if the escrow record was added

        """
        # used just for the log message
        evt = ghab.msgOwnEvent(sn=number.sn, allowPartiallySigned=True, framed=True,
                               gvrsn=self.version if self.version is not None else Version)
        serder = SerderKERI(raw=evt)  # used just for the log message
        logger.info("Waiting for other signatures on %s for %s:%s...",
                    serder.ilk, prefixer.qb64, number.sn)
        return self.hby.db.gpse.add(keys=(prefixer.qb64,), val=(number, diger))

    def complete(self, prefixer, number, diger=None):
        """ Check for completed multsig protocol for the specific event

        Parameters:
            prefixer (Prefixer): qb64 identifier prefix of event to check
            number (Number): sequence number of event to check
            diger (Diger): optional digest of event to verify

        Returns:
            bool: True when the multisig protocol has completed for the event
            """
        cdiger = self.hby.db.cgms.get(keys=(prefixer.qb64, number.qb64))
        if not cdiger:
            return False
        else:
            if diger and (cdiger.qb64 != diger.qb64):
                raise ValidationError(f"invalid multisig protocol escrowed event {cdiger.qb64}-{diger.qb64}")

        return True

    def escrowDo(self, tymth, tock=1.0, **kwa):
        """ Process escrows of group multisig identifiers waiting to be completed.

        Steps involve:
           1. Sending local event with sig to other participants
           2. Waiting for signature threshold to be met.
           3. If elected and delegated identifier, send complete event to delegator
           4. If delegated, wait for delegator's anchored seal
           5. If elected, send event to witnesses and collect receipts.
           6. Otherwise, wait for fully receipted event

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value.  Default to 1.0 to slow down processing

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            self.processEscrows()
            yield 0.5

    def processEscrows(self):
        """Process group multisig event escrows."""
        self.processPartialSignedEscrow()
        self.processDelegateEscrow()
        self.processPartialWitnessEscrow()

    def processPartialSignedEscrow(self):
        """
        Process escrow of partially signed multisig group KEL events.  Message
        processing will send this local controllers signature to all other participants
        then this escrow waits for signatures from all other participants

        """
        for (pre,), (number, diger) in self.hby.db.gpse.getTopItemIter():  # group partially signed escrow
            sdig = self.hby.db.kels.getLast(keys=pre, on=number.sn)
            if sdig:
                sdig = sdig.encode("utf-8")
                self.hby.db.gpse.rem(keys=(pre,))
                ghab = self.hby.habs[pre]
                kever = ghab.kever
                keys = [verfer.qb64 for verfer in kever.verfers]
                sigers = self.hby.db.sigs.get(keys=(pre, sdig))
                if not sigers:  # otherwise its a list of sigs
                    continue

                windex = min([siger.index for siger in sigers])

                # True if Elected to perform delegation and witnessing
                witered = ghab.mhab.kever.verfers[0].qb64 == keys[windex]

                if kever.delegated and kever.ilk in (Ilks.dip, Ilks.drt):
                    # We are a delegated identifier, must wait for delegator approval for dip and drt
                    if witered:  # We are elected to perform delegation and witnessing messaging
                        logger.info("AID %s...%s: We are the witnesser, sending %s to delegator", pre[:4], pre[-4:], pre)
                        self.swain.delegation(pre=pre, sn=number.sn)
                    else:
                        anchor = dict(i=pre, s=number.snh, d=diger.qb64)
                        kwa = dict(version=self.version, gvrsn=self.version, kind=self.kind) if self.version is not None else {}
                        if self.proxy:
                            self.witq.query(hab=self.proxy, pre=kever.delpre, anchor=anchor,
                                            **kwa)
                        else:
                            self.witq.query(src=ghab.mhab.pre, pre=kever.delpre, anchor=anchor,
                                            **kwa)

                    logger.info("AID %s...%s: Waiting for delegation approval...", pre[:4], pre[-4:])
                    self.hby.db.gdee.add(keys=(pre,), val=(number, diger))
                else:  # Non-delegation, move on to witnessing
                    if witered:  # We are elected witnesser, send off event to witnesses
                        logger.info(
                            "AID %s...%s: We are the fully signed witnesser %s, sending to witnesses",
                            pre[:4], pre[-4:], number.sn)
                        self.witDoer.msgs.append(dict(pre=pre, sn=number.sn))

                    # Move to escrow waiting for witness receipts
                    logger.info("AID %s...%s: Waiting for fully signed witness receipts for %s",
                                pre[:4], pre[-4:], number.sn)
                    self.hby.db.gpwe.add(keys=(pre,), val=(number, diger))

    def processDelegateEscrow(self):
        """
        Process escrow of delegate group multisig identifiers that are
        waiting for delegator approval of a recent establishment event.

        """
        for (pre,), (number, diger) in self.hby.db.gdee.getTopItemIter():  # group delegatee escrow
            anchor = dict(i=pre, s=number.numh, d=diger.qb64)
            ghab = self.hby.habs[pre]
            kever = ghab.kevers[pre]

            keys = [verfer.qb64 for verfer in kever.verfers]
            witer = ghab.mhab.kever.verfers[0].qb64 == keys[0]  # We are elected to perform delegation and witnessing

            if witer:  # We are elected witnesser, We've already done out part in Boatswain, we are done.
                if self.swain.complete(prefixer=kever.prefixer, number=Number(num=kever.sn, code=NumDex.Huge)):
                    self.hby.db.gdee.rem(keys=(pre,))
                    logger.info("AID %s...%s: Delegation approval for %s received.", pre[:4], pre[-4:], pre)

                    self.hby.db.cgms.put(keys=(pre, number.qb64), val=diger)

            else:  # Not witnesser, we need to look for the anchor and then wait for receipts
                if serder := self.hby.db.fetchLastSealingEventByEventSeal(kever.delpre,
                                                                          seal=anchor):
                    sner = Number(num=serder.sn, code=NumDex.Huge)
                    adiger = Diger(qb64b=serder.saidb)
                    self.hby.db.aess.pin(keys=(pre, diger.qb64b),
                                         val=(sner, adiger))  # authorizer event seal (delegator/issuer)
                    self.hby.db.gdee.rem(keys=(pre,))
                    logger.info("AID %s...%s: Delegation approval for %s received.", pre[:4], pre[-4:], pre)

                    # Move to escrow waiting for witness receipts
                    logger.info("AID %s...%s: Waiting for witness receipts for %s", pre[:4], pre[-4:], pre)
                    self.hby.db.gdee.rem(keys=(pre,))
                    self.hby.db.gpwe.add(keys=(pre,), val=(number, diger))

    def processPartialWitnessEscrow(self):
        """
        Process escrow of group multisig events that do not have a full complement of receipts
        from witnesses yet.  When receipting is complete, remove from escrow and cue up a message
        that the event is complete.

        """
        for (pre,), (number, diger) in self.hby.db.gpwe.getTopItemIter():  # group partial witness escrow
            kever = self.hby.kevers[pre]

            # Load all the witness receipts we have so far
            wigers = self.hby.db.wigs.get(keys=(pre, diger.qb64))
            ghab = self.hby.habs[pre]
            keys = [verfer.qb64 for verfer in kever.verfers]
            witer = ghab.mhab.kever.verfers[0].qb64 == keys[0]
            if len(wigers) == len(kever.wits):  # We have all of them, this event is finished
                if witer and len(kever.wits) > 0:
                    witnessed = False
                    for cue in self.witDoer.cues:
                        if cue["pre"] == ghab.pre and cue["sn"] == number.sn:
                            witnessed = True
                    if not witnessed:
                        continue
                logger.info("AID %s...%s: Witness receipts complete, %s confirmed.", pre[:4], pre[-4:], pre)
                self.hby.db.gpwe.rem(keys=(pre,))
                self.hby.db.cgms.put(keys=(pre, number.qb64), val=diger)
            elif not witer:
                self.witDoer.gets.append(dict(pre=pre, sn=number.sn))


class MultisigNotificationHandler:
    """
    Handler for multisig coordination EXN messages

    """

    def __init__(self, resource, mux):
        """ Create an exn handler for multisig messages

        Parameters:
            resource:
            mux:
        """
        self.resource = resource
        self.mux = mux

    def verify(self, serder, attachments=None, nests=None):
        """Validate a multisig EXN before the exchanger saves it."""
        try:
            return (serder.route == self.resource
                    and self.mux.validate(serder=serder, nests=nests) is not None)
        except (ValidationError, ValueError, KeyError, TypeError, AttributeError):
            return False

    def handle(self, serder, attachments=None, nests=None):
        """  Do route specific processing of multisig exn messages

        Parameters:
            serder (Serder): Serder of the exn multisig message
            attachments (list): list of tuples of pather, CESR SAD path attachments to the exn event
            nests (list | None): parsed V2 nested substreams for routes that
                use the single-child V2 multisig envelope

        """
        logger.info("Notification for %s event SAID=%s", self.resource, serder.said)
        logger.debug("EXN Body=\n%s\n", serder.pretty())
        self.mux.add(serder=serder, nests=nests)


def loadHandlers(exc, mux):
    """Load handlers for the peer-to-peer distributed group multisig protocol

    Parameters:
        exc (Exchanger): Peer-to-peer message router
        mux (Multiplexor): Multisig communication coordinator

    Returns:
        None. Registers the existing multisig routes, including ACDC v2 registry
        proposals, on the caller-owned Exchanger; registration grants no approval."""
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/icp", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/rot", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/ixn", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/vcp", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/iss", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/rev", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/exn", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/rpy", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/rip", mux=mux))
    exc.addHandler(MultisigNotificationHandler(resource="/multisig/bup", mux=mux))


def multisigInceptExn(hab, smids, rmids, icp, delegator=None, version=None, gvrsn=None, kind=None):
    """

    Parameters:
        hab (Hab): habitat of local multisig member AID
        smids (list): list of qb64 AIDs of members with signing authority
        rmids (list): list of qb64 AIDs of members with rotation authority
        icp (bytes): serialized inception event with CESR streamed attachments
        delegator (str): qb64 AID of Delegator is group multisig is a delegated AID
        version(Versionage | None): optional explicit wrapper/framing version
        gvrsn(Versionage | None): optional explicit wrapped child attachment genus version
        kind (str | None): optional explicit serialization kind

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """
    rmids = rmids if rmids is not None else smids
    serder = SerderKERI(raw=icp)
    data = dict(
        gid=serder.pre,
        smids=smids,
        rmids=rmids,
    )

    embeds = dict(icp=icp)

    if delegator is not None:
        data |= dict(delegator=delegator)

    version = version if version is not None else Version
    kind = kind if kind is not None else Kinds.json
    child = Serder(raw=icp)
    childGvrsn = (gvrsn if gvrsn is not None
                  else child.gvrsn if child.gvrsn else child.pvrsn)

    if version.major == Vrsn_1_0.major:
        if child.gvrsn is None and childGvrsn != child.pvrsn:
            data["cgvrsn"] = [childGvrsn.major, childGvrsn.minor]
        exn, end = specialExchange(sender=hab.pre,
                                   route="/multisig/icp",
                                   modifiers=dict(),
                                   attributes=data,
                                   embeds=embeds,
                                   version=version,
                                   kind=kind)
        ims = hab.endorse(serder=exn, last=False, framed=True, gvrsn=version)
        del ims[:exn.size]
        ims.extend(end)

        return exn, ims

    # Sign the wrapped child by SAID directly in the outer payload
    data = dict(data)

    # Add the child SAID under the route-specific attribute name
    data["icp"] = child.said

    # Parse the child event without processing it to recover body and attachments
    parsed = Parser(version=childGvrsn).parse(ims=bytearray(icp),
                                              framed=True,
                                              processive=False)
    if not parsed:
        raise ValueError(f"Unable to parse multisig payload stream with attachment genus {childGvrsn.major}.{childGvrsn.minor}")
    if len(parsed) != 1:
        raise ValueError("Expected one multisig payload stream")

    # Re-encode the child as one nested V2 substream
    nests = serializeParsedSubstream(parsed[0], gvrsn=childGvrsn)

    # Build the outer body multisig exn
    exn = exchange(sender=hab.pre,
                   route="/multisig/icp",
                   modifiers=dict(),
                   attributes=data,
                   version=version,
                   gvrsn=version,
                   kind=kind)

    # Endorse the outer body exn and attach the one nested child stream
    ims = hab.endorse(serder=exn,
                      last=False,
                      framed=False,
                      gvrsn=version,
                      nests=[nests])

    exn = SerderKERI(raw=ims)

    return exn, bytearray(ims[exn.size:])


def multisigRotateExn(ghab, smids, rmids, rot, version=None, gvrsn=None, kind=None):
    """

    Parameters:
        ghab (GroupHab): habitat of group multisig AID
        smids (list): list of qb64 AIDs of members with signing authority
        rmids (list): list of qb64 AIDs of members with rotation authority
        rot (bytes): serialized rotation event with CESR streamed attachments
        version(Versionage | None): optional explicit wrapper/framing version
        gvrsn(Versionage | None): optional explicit wrapped child attachment genus version
        kind (str | None): optional explicit serialization kind

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """
    embeds = dict(
        rot=rot,
    )

    data = dict(gid=ghab.pre,
                smids=smids,
                rmids=rmids)
    version = version if version is not None else Version
    kind = kind if kind is not None else Kinds.json
    child = Serder(raw=rot)
    childGvrsn = (gvrsn if gvrsn is not None
                  else child.gvrsn if child.gvrsn else child.pvrsn)
    if version.major == Vrsn_1_0.major:
        if child.gvrsn is None and childGvrsn != child.pvrsn:
            data["cgvrsn"] = [childGvrsn.major, childGvrsn.minor]
        exn, end = specialExchange(sender=ghab.mhab.pre,
                                   route="/multisig/rot", modifiers=dict(),
                                   attributes=data,
                                   embeds=embeds,
                                   version=version,
                                   kind=kind)
        ims = ghab.mhab.endorse(serder=exn, last=False, framed=True, gvrsn=version)
        atc = bytearray(ims[exn.size:])
        atc.extend(end)

        return exn, atc

    # Sign the wrapped child by SAID directly in the outer payload
    data = dict(data)
    data["rot"] = child.said
    parsed = Parser(version=childGvrsn).parse(ims=bytearray(rot),
                                              framed=True,
                                              processive=False)
    if not parsed:
        raise ValueError(f"Unable to parse multisig payload stream with attachment genus {childGvrsn.major}.{childGvrsn.minor}")
    if len(parsed) != 1:
        raise ValueError("Expected one multisig payload stream")

    # Re-encode the child as one nested V2 substream
    nests = serializeParsedSubstream(parsed[0], gvrsn=childGvrsn)

    # Build the outer multisig exn
    exn = exchange(sender=ghab.mhab.pre,
                   route="/multisig/rot",
                   modifiers=dict(),
                   attributes=data,
                   version=version,
                   gvrsn=version,
                   kind=kind)

    # Endorse the outer exn and attach the one nested child stream
    ims = ghab.mhab.endorse(serder=exn,
                            last=False,
                            framed=False,
                            gvrsn=version,
                            nests=[nests])

    exn = SerderKERI(raw=ims)

    return exn, bytearray(ims[exn.size:])


def multisigInteractExn(ghab, aids, ixn, version=None, gvrsn=None, kind=None):
    """ Create a peer to peer message to propose a multisig group interaction event

    Parameters:
        ghab (GroupHab): group Hab to endorse the message
        aids (list): qb64 identifier prefixes to include in the interaction event
        ixn (bytes): serialized interaction event with CESR streamed attachments
        version(Versionage | None): optional explicit wrapper/framing version
        gvrsn(Versionage | None): optional explicit wrapped child attachment genus version
        kind (str | None): optional explicit serialization kind

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments
    """

    embeds = dict(
        ixn=ixn,
    )

    data = dict(gid=ghab.pre,
                smids=aids)

    version = version if version is not None else Version
    kind = kind if kind is not None else Kinds.json
    child = Serder(raw=ixn)
    childGvrsn = (gvrsn if gvrsn is not None
                  else child.gvrsn if child.gvrsn else child.pvrsn)
    if version.major == Vrsn_1_0.major:
        if child.gvrsn is None and childGvrsn != child.pvrsn:
            data["cgvrsn"] = [childGvrsn.major, childGvrsn.minor]
        exn, end = specialExchange(sender=ghab.mhab.pre,
                                   route="/multisig/ixn",
                                   modifiers=dict(),
                                   attributes=data,
                                   embeds=embeds,
                                   version=version,
                                   kind=kind)
        ims = ghab.mhab.endorse(serder=exn, last=False, framed=True, gvrsn=version)
        atc = bytearray(ims[exn.size:])
        atc.extend(end)

        return exn, atc

    # Sign the wrapped child by SAID directly in the outer payload
    data = dict(data)
    data["ixn"] = child.said
    parsed = Parser(version=childGvrsn).parse(ims=bytearray(ixn),
                                              framed=True,
                                              processive=False)
    if not parsed:
        raise ValueError(f"Unable to parse multisig payload stream with attachment genus {childGvrsn.major}.{childGvrsn.minor}")
    if len(parsed) != 1:
        raise ValueError("Expected one multisig payload stream")

    nests = serializeParsedSubstream(parsed[0], gvrsn=childGvrsn)

    exn = exchange(sender=ghab.mhab.pre,
                   route="/multisig/ixn",
                   modifiers=dict(),
                   attributes=data,
                   version=version,
                   gvrsn=version,
                   kind=kind)

    ims = ghab.mhab.endorse(serder=exn,
                            last=False,
                            framed=False,
                            gvrsn=version,
                            nests=[nests])

    exn = SerderKERI(raw=ims)

    return exn, bytearray(ims[exn.size:])


def multisigRegistryInceptExn(ghab, usage, vcp, anc, version=None, kind=None):
    """ Create a peer to peer message to propose a credential registry inception from a multisig group identifier

    Either rot or ixn are required but not both

    Parameters:
        ghab (GroupHab): identifier Hab for endorsing the message to send
        usage (str): human readable reason for creating the credential registry
        vcp (bytes): serialized Credentials registry inception event
        anc (bytes): CESR stream of serialized and signed event anchoring registry inception event
        version(Versionage | None): optional explicit outer framing version
        kind (str | None): optional explicit serialization kind

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """

    embeds = dict(
        vcp=vcp,
        anc=anc
    )
    gvrsn = version if version is not None else Version
    kind = kind if kind is not None else Kinds.json

    exn, end = specialExchange(sender=ghab.mhab.pre,
                               route="/multisig/vcp",
                               attributes={'gid': ghab.pre, 'usage': usage},
                               embeds=embeds,
                               version=Vrsn_1_0,
                               kind=kind)
    evt = ghab.mhab.endorse(serder=exn, last=False, framed=True, gvrsn=gvrsn)
    atc = bytearray(evt[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigIssueExn(ghab, acdc, iss, anc, version=None, kind=None):
    """ Create a peer to peer message to propose a credential creation from a multisig group identifier

    Either rot or ixn are required but not both

    Parameters:
        ghab (GroupHab): identifier Hab for endorsing the message to send
        acdc (bytes): serialized Credential
        iss (bytes): CESR stream of serialized and TEL issuance event
        anc (bytes): CESR stream of serialized and signed anchoring event anchoring creation
        version(Versionage | None): optional explicit outer framing version
        kind (str | None): optional explicit serialization kind

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """

    embeds = dict(
        acdc=acdc,
        iss=iss,
        anc=anc
    )
    gvrsn = version if version is not None else Version
    kind = kind if kind is not None else Kinds.json

    exn, end = specialExchange(sender=ghab.mhab.pre,
                               route="/multisig/iss",
                               attributes={'gid': ghab.pre},
                               embeds=embeds,
                               version=Vrsn_1_0,
                               kind=kind)
    evt = ghab.mhab.endorse(serder=exn, last=False, framed=True, gvrsn=gvrsn)
    atc = bytearray(evt[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigRevokeExn(ghab, said, rev, anc, version=None, kind=None):
    """ Create a peer to peer message to propose a credential revocation from a multisig group identifier

    Either rot or ixn are required but not both

    Parameters:
        ghab (GroupHab): identifier Hab for endorsing the message to send
        said (str): qb64 SAID of credential being revoked
        rev (bytes): CESR stream of serialized and TEL revocation event
        anc (bytes): CESR stream of serialized and signed anchoring event anchoring revocation
        version(Versionage | None): optional explicit outer framing version
        kind (str | None): optional explicit serialization kind

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """

    embeds = dict(
        rev=rev,
        anc=anc
    )
    gvrsn = version if version is not None else Version
    kind = kind if kind is not None else Kinds.json

    exn, end = specialExchange(sender=ghab.mhab.pre,
                               route="/multisig/rev",
                               attributes={'gid': ghab.pre, 'said': said},
                               embeds=embeds,
                               version=Vrsn_1_0,
                               kind=kind)
    evt = ghab.mhab.endorse(serder=exn, last=False, framed=True, gvrsn=gvrsn)
    atc = bytearray(evt[exn.size:])
    atc.extend(end)

    return exn, atc


def multisigRpyExn(ghab, rpy, version=None, gvrsn=None, kind=None):
    """ Create a peer to peer message to propose a credential revocation from a multisig group identifier

    Either rot or ixn are required but not both

    Parameters:
        ghab (GroupHab): identifier Hab for endorsing the message to send
        rpy (bytes): CESR stream of serialized and reply event
        version(Versionage | None): optional explicit wrapper/framing version
        gvrsn(Versionage | None): optional explicit wrapped child attachment genus version
        kind (str | None): optional explicit serialization kind

    Returns:
        tuple: (Serder, bytes): Serder of exn message and CESR attachments

    """

    embeds = dict(
        rpy=rpy
    )

    data = {'gid': ghab.pre}
    version = version if version is not None else Version
    kind = kind if kind is not None else Kinds.json
    child = Serder(raw=rpy)
    childGvrsn = (gvrsn if gvrsn is not None
                  else child.gvrsn if child.gvrsn else child.pvrsn)
    if version.major == Vrsn_1_0.major:
        if child.gvrsn is None and childGvrsn != child.pvrsn:
            data["cgvrsn"] = [childGvrsn.major, childGvrsn.minor]
        exn, end = specialExchange(sender=ghab.mhab.pre,
                                   route="/multisig/rpy",
                                   attributes=data,
                                   embeds=embeds,
                                   version=version,
                                   kind=kind)
        evt = ghab.mhab.endorse(serder=exn, last=False, framed=True, gvrsn=version)
        atc = bytearray(evt[exn.size:])
        atc.extend(end)

        return exn, atc

    data = dict(data)
    data["rpy"] = child.said
    parsed = Parser(version=childGvrsn).parse(ims=bytearray(rpy),
                                              framed=True,
                                              processive=False)
    if not parsed:
        raise ValueError(f"Unable to parse multisig payload stream with attachment genus {childGvrsn.major}.{childGvrsn.minor}")
    if len(parsed) != 1:
        raise ValueError("Expected one multisig payload stream")

    nests = serializeParsedSubstream(parsed[0], gvrsn=childGvrsn)

    exn = exchange(sender=ghab.mhab.pre,
                   route="/multisig/rpy",
                   modifiers=dict(),
                   attributes=data,
                   version=version,
                   gvrsn=version,
                   kind=kind)

    ims = ghab.mhab.endorse(serder=exn,
                            last=False,
                            framed=False,
                            gvrsn=version,
                            nests=[nests])

    exn = SerderKERI(raw=ims)

    return exn, bytearray(ims[exn.size:])


def _replyGroup(hby, ghab):
    """Require an accepted local GroupHab with its normal signing member."""
    from .habbing import GroupHab

    if (not isinstance(ghab, GroupHab) or hby.habs.get(ghab.pre) is not ghab
            or not ghab.accepted or ghab.mhab is None
            or ghab.mhab.pre not in ghab.smids):
        raise ValidationError('reply approval requires an accepted local signing group')


def _replyChild(ghab, child, validate):
    """Check exact reply attribution and signature-only attachments before policy."""
    serder = child.serder
    if (not callable(validate) or not isinstance(serder, SerderKERI)
            or serder.ilk != Ilks.rpy or not serder.verify()
            or (serder.pvrsn == Vrsn_2_0 and serder.pre != ghab.pre)
            or any(value for key, value in vars(child).items()
                   if key not in ('serder', 'tsgs', 'cigars', 'local'))):
        raise ValidationError('reply approval requires one group reply with signature attachments')
    # Policy must raise on refusal. Merely returning False must never mean consent.
    if validate(serder) is False:
        raise ValidationError('reply approval domain policy declined the body')


def replyProposal(hby, exc, mux, said, *, ghab, validate):
    """Inspect one authenticated retained v2 reply proposal without approving it.

    Parameters: hby/exc/mux are caller-owned processors; said identifies a
        retained /multisig/rpy wrapper; ghab is the local GroupHab; validate is a required domain-policy
        callable that raises on rejection, run before user approval/display.
    Returns: exact retained parsed reply child, including signature attachments.
    Raises: ValidationError for missing authentication, mismatched group/member,
        invalid local group, malformed child or domain-policy refusal. Policy errors
        propagate. This read path grants no local approval or reply authority.
    """
    _replyGroup(hby, ghab)
    wrapper = hby.db.exns.get(keys=said)
    if (wrapper is None or wrapper.route != '/multisig/rpy'
            or wrapper.pvrsn != Vrsn_2_0 or not exc.complete(said)
            or wrapper.sad['a'].get('gid') != ghab.pre
            or wrapper.pre not in ghab.smids):
        raise ValidationError('reply proposal requires an authenticated current group member wrapper')
    verify(hby, wrapper)
    children = loadParsedNestedSubstreams(hby, said)
    mux.validate(wrapper, nests=children)
    if len(children) != 1:
        raise ValidationError('reply proposal requires exactly one retained child')
    child = children[0]
    _replyChild(ghab, child, validate)
    _replyGroup(hby, ghab)
    return child


def endorseReply(hby, ghab, child, *, validate):
    """Add explicit local approval to an exact policy-validated group reply.

    Parameters: hby is caller-owned Habery; ghab is its accepted GroupHab;
        child is the exact parsed reply;
        validate is required domain policy, rerun immediately before signing.
    Returns: (signed child stream, member wrapper, detached wrapper attachments).
        The caller processes the local wrapper through its existing Exchanger/
        Multiplexor to record approval and replay retained contributions.
    Raises: ValidationError for invalid local group, child or policy refusal.
        Policy and signing errors propagate. No routes or processors are created.
        The callback owns domain consent; this helper adds no application-secret
        custody prerequisite beyond the group's existing signing operation.
    """
    _replyGroup(hby, ghab)
    _replyChild(ghab, child, validate)
    _replyGroup(hby, ghab)
    local = Parser(version=Vrsn_2_0).parse(
        ims=bytearray(ghab.endorse(child.serder, gvrsn=Vrsn_2_0)), processive=False)[0]
    # Reparse a copy so retries cannot mutate the retained proposal object.
    signed = Parser(version=Vrsn_2_0).parse(
        ims=bytearray(serializeParsedSubstream(child)), processive=False)[0]
    signed.tsgs.extend(local.tsgs)
    signed.cigars.extend(local.cigars)
    stream = messagize(signed.serder, tsgs=signed.tsgs or None,
                       cigars=signed.cigars or None, gvrsn=Vrsn_2_0)
    wrapper, attachments = multisigRpyExn(ghab, stream, version=Vrsn_2_0,
                                         gvrsn=Vrsn_2_0, kind=Kinds.json)
    return stream, wrapper, attachments


def multisigExn(ghab, exn, version=None, kind=None):
    """Wrap one proposed exchange for explicit group-member approval.

    Args:
        ghab (GroupHab): Group whose local member signs the wrapper.
        exn (bytes): Exact signed child exchange stream, including its attachments.
        version (Versionage | None): Genus/profile selector; v2 uses a CESR-framed nest,
        otherwise the legacy embedded-exchange form is retained.
        kind (str | None): Wrapper body encoding, default JSON.

    Returns:
        tuple[Serder, bytearray]: Member-signed wrapper body and detached attachments.

    Raises:
        ValueError: V2 input does not parse as exactly one EXN.

    The wrapper commits to the child's SAID; reception is a proposal, never local
    consent to issue a credential or send the child exchange."""
    if version is not None and version.major == Vrsn_2_0.major:
        parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(exn), processive=False)
        if len(parsed) != 1 or parsed[0].serder.ilk != Ilks.exn:
            raise ValueError('v2 multisig exchange requires exactly one EXN')
        child = parsed[0].serder
        wrapper = exchange(sender=ghab.mhab.pre, route='/multisig/exn',
            attributes=dict(gid=ghab.pre, exn=child.said), version=Vrsn_2_0,
            gvrsn=Vrsn_2_0, kind=kind if kind is not None else Kinds.json)
        msg = ghab.mhab.endorse(wrapper, last=False, framed=False, gvrsn=Vrsn_2_0,
                               nests=[serializeParsedSubstream(parsed[0])])
        return wrapper, bytearray(msg[wrapper.size:])

    embeds = dict(
        exn=exn
    )
    gvrsn = version if version is not None else Version
    kind = kind if kind is not None else Kinds.json

    wexn, end = specialExchange(sender=ghab.mhab.pre,
                                route="/multisig/exn",
                                attributes={'gid': ghab.pre},
                                embeds=embeds,
                                version=Vrsn_1_0,
                                kind=kind)
    evt = ghab.mhab.endorse(serder=wexn, last=False, framed=True, gvrsn=gvrsn)
    atc = bytearray(evt[wexn.size:])
    atc.extend(end)

    return wexn, atc


def validateRegistryAnchor(event, anchor, controller):
    """Require this profile's single sequence/digest TEL seal before consent.

    Args: event is the exact native TEL body; anchor is the proposed KEL body;
        controller is the group AID expected to sign it.
    Returns: None. Raises ValidationError for another controller, event type,
        version, seal form, or additional seals. This local proposal restriction
        does not narrow the seal forms accepted by the underlying TEL verifier.
    """
    if (anchor.pvrsn != Vrsn_2_0 or anchor.pre != controller
            or anchor.ilk not in (Ilks.ixn, Ilks.rot, Ilks.drt)
            or anchor.sad.get('a') != [dict(s=event.sad['n'], d=event.said)]):
        raise ValidationError('group proposal does not exclusively anchor the requested TEL with one s,d seal')


def multisigRipExn(ghab, rip, anc, *, salts=None):
    """Wrap an exact ACDC v2 registry inception and its proposed group KEL anchor.

    The local member endorses the proposal. GroupHab and Counselor still own
    group signing and completion; the wrapper itself grants no approval.

    Args:
        ghab (GroupHab): Group whose local member endorses the wrapper.
        rip (bytes): One exact registry inception stream with attachments.
        anc (bytes): One proposed controlling KEL event with attachments.
        salts (dict | None): Optional member AID to encrypted salt mapping.

    Returns:
        tuple: Member-signed wrapper and detached attachments, in TEL/KEL order.

    Raises:
        ValueError: A child is not one event or the TEL is not a v2 inception.
    """
    return _multisigRegistryExn(ghab, rip, anc, ilk=Ilks.rip, salts=salts)


def multisigBupExn(ghab, bup, anc, *, salts=None):
    """Wrap an exact ACDC v2 blindable update and its proposed group KEL anchor.

    Supplied attachments may disclose an explicitly public event opening. This
    builder neither derives openings nor accesses registry custody secrets.

    Args:
        ghab (GroupHab): Group whose local member endorses the wrapper.
        bup (bytes): One exact blinded update stream with supplied attachments.
        anc (bytes): One proposed controlling KEL event with attachments.
        salts (dict | None): Optional member AID to encrypted salt mapping.

    Returns:
        tuple: Member-signed wrapper and detached attachments, in TEL/KEL order.

    Raises:
        ValueError: A child is not one event or the TEL is not a v2 blinded update.
    """
    return _multisigRegistryExn(ghab, bup, anc, ilk=Ilks.bup, salts=salts)


def validateRegistrySalts(salts, members):
    """Validate optional encrypted salt copies addressed to local group members.

    salts is a map of member AIDs to exact CESR X25519 salt ciphers. members is
    the existing GroupHab signing-member list, not a separate roster. None means
    no salt sharing. This local R&D EXN payload encoding neither discloses an
    event opening nor proves that ciphertexts contain identical plaintexts.
    Signature verification and recipient decryption remain their owners' work.
    """
    if salts is None:
        return
    if not isinstance(salts, dict) or not salts or set(salts) - set(members):
        raise ValidationError('registry salt copies require current group member recipients')
    try:
        for member, value in salts.items():
            if Prefixer(qb64=member).qb64 != member:
                raise ValueError
            cipher = Cipher(qb64=value)
            if cipher.code != MtrDex.X25519_Cipher_Salt or cipher.qb64 != value:
                raise ValueError
    except (KeriError, ValueError, TypeError):
        raise ValidationError('registry salt copy is not an exact encrypted salt') from None


def _multisigRegistryExn(ghab, tel, anc, *, ilk, salts=None):
    """Endorse two exact child streams under the route for the required TEL ilk.

    Multiplexor validates their commitments, controller, and anchor relationship
    before storing the proposal. The builder rejects a TEL for the wrong route.

    ghab, tel and anc supply the member signer and exact child streams; ilk
    selects the required TEL type. Return the wrapper and detached attachments.
    This factors the former fork multisigRegistryExn construction, introduced
    in 93fef663f53ee49187747caf207bc9173c9b6fc1, into per-event contracts.
    """
    children = []
    for stream in (tel, anc):
        parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(stream), processive=False)
        if len(parsed) != 1:
            raise ValueError('ACDC v2 registry proposal requires one TEL and one KEL event')
        children.append(parsed[0])
    event = children[0].serder
    if event.ilk != ilk or event.pvrsn != Vrsn_2_0:
        raise ValueError(f'ACDC v2 multisig {ilk} proposal requires a {ilk} event')
    validateRegistryAnchor(event, children[1].serder, ghab.pre)
    validateRegistrySalts(salts, ghab.smids)
    attributes = dict(gid=ghab.pre, tel=event.said, anc=children[1].serder.said)
    if salts is not None:
        attributes['salts'] = salts
    wrapper = exchange(sender=ghab.mhab.pre, route=f'/multisig/{ilk}',
        attributes=attributes, version=Vrsn_2_0,
        gvrsn=Vrsn_2_0, kind=Kinds.json)
    msg = ghab.mhab.endorse(wrapper, last=False, framed=False, gvrsn=Vrsn_2_0,
                           nests=[serializeParsedSubstream(child) for child in children])
    return wrapper, bytearray(msg[wrapper.size:])


def getEscrowedEvent(db, pre, sn):
    vals = db.pses.getLast(keys=pre, on=sn)
    dig = vals if vals else None
    if dig is None:
        dig = db.kels.getLast(keys=pre, on=sn)
    dig = dig.encode("utf-8")
    serder = db.evts.get(keys=(pre, dig))
    sigers = db.sigs.get(keys=(pre, dig))
    duple = db.aess.get(keys=(pre, dig))

    seal = None
    if duple is not None:
        number, diger = duple
        seal = SealSource(s=number.snh, d=diger.qb64)

    return messagize(serder, sigers=sigers, bonds=seal, framed=True,
                     gvrsn=Version)


class Multiplexor:
    """ Multiplexor (mux) is responsible for coordinating peer-to-peer messages between group multisig participants

    When new messages arrive the Mux associates the SAID of the wrapped child payload with the exn message SAID
    and sender. This lets the controller of the participant know who has sent matching proposals. If the local
    participant has already approved the wrapped payload, the wrapped child stream is replayed through the local
    parser so signatures can merge.

    Attributes:
        hby (habbing.Habery): database environment for local Habs
        rtr (Router): routes reply 'rpy' messages
        rvy (Revery): factory that processes reply 'rpy' messages
        exc (Exchanger): processor and router for peer-to-peer msgs
        kvy (Kevery): factory for local processing of local event msgs
        psr (Parser):  parses local messages for .kvy .rvy
        notifier (notifying.Notifier): stores notices for human consumption

        Parameters:
            hby (habbing.Habery): database environment for local Habs
            notifier (notifying.Notifier): stores notices for human consumption


    """

    def __init__(self, hby, notifier, *, exc=None, rgy=None, kvy=None, rvy=None):
        """Create Multiplexor for local database and Habs

        Parameters:
            hby (habbing.Habery): database environment for local Habs
            notifier (notifying.Notifier): stores notices for human consumption

        Additional parameters:
            exc (Exchanger | None): Shared concrete exchange processor for approved child
            replay; None creates the existing empty-handler Exchanger.
            rgy (Rever | None): ACDC v2 registry processor for approved TEL child replay.
            kvy (Kevery | None), rvy (Revery | None): Matching caller-owned pair
                for approved child replay. Supply both or neither. An injected
                pair keeps its existing reply routes, cues and KRAM policy;
                the caller owns registration and escrow scheduling.

        Returns:
            None. Habery, notifier, and injected processors remain caller-owned; this
            object creates no autonomous approval or scheduling lifecycle.

        Raises:
            ValidationError: An injected pair is incomplete or belongs to a
                different database/reply owner.
        """
        if (kvy is None) != (rvy is None):
            raise ValidationError('group replay requires both borrowed KEL and reply processors')
        if kvy is not None and (kvy.db is not hby.db or rvy.db is not hby.db or kvy.rvy is not rvy):
            raise ValidationError('group replay processors must share the selected Habery and reply owner')
        self.hby = hby
        self.rtr = rvy.rtr if rvy is not None else Router()
        self.rvy = rvy if rvy is not None else Revery(db=self.hby.db, rtr=self.rtr)
        self.exc = exc if exc is not None else Exchanger(hby=self.hby, handlers=[])
        self.rgy = rgy
        self.kvy = kvy if kvy is not None else Kevery(db=self.hby.db, lax=False, local=False, rvy=self.rvy)
        if kvy is None:
            self.kvy.registerReplyRoutes(router=self.rtr)

        self.notifier = notifier

    def _replayApproved(self, said):
        """Replay a retained child proposal after the caller establishes local approval.

        Args:
            said (str): Accepted multisig wrapper whose exact retained children to replay.

        Returns:
            None. Dispatches v2 nested child streams through the injected KEL/EXN/TEL processors,
            or legacy embedded children through the existing replay path.

        Parsing may escrow dependencies rather than complete a group operation. This
        method does not create approval or conclude quorum completion; caller/store
        failures propagate and parser validation uses its ordinary error handling."""

        # Check for nested substreams saved under that EXN SAID
        stored = self.hby.db.enst.get(keys=(said,))
        if stored:
            ims = bytearray()
            for nest in stored:
                ims.extend(bytearray(nest.encode("utf-8") if isinstance(nest, str) else nest))

            # Replay them through normal local event processing
            parser = Parser(framed=True, kvy=self.kvy, rvy=self.rvy,
                            exc=self.exc, rgy=self.rgy, version=Vrsn_2_0)
            parser.parse(ims=ims, local=True)
            return

        # If no nests, fall back to v1 cloneMessage
        exn, paths = cloneMessage(self.hby, said=said)
        payload = exn.ked["a"]
        for key, val in exn.ked['e'].items():
            if not isinstance(val, dict):
                continue

            cserder = Serder(sad=val)
            ims = bytearray(cserder.raw)
            if key in paths:
                atc = bytearray(paths[key])
                ims.extend(atc)

                # If v1 body had v2 attachments, parse replay with the recorded attachment version
                version = (Versionage(*payload["cgvrsn"])
                           if "cgvrsn" in payload and cserder.gvrsn is None
                           else cserder.gvrsn if cserder.gvrsn else cserder.pvrsn)
            else:
                version = cserder.gvrsn if cserder.gvrsn else cserder.pvrsn

            # Replay the child event locally
            parser = Parser(framed=True, kvy=self.kvy, rvy=self.rvy,
                            exc=self.exc, version=version)
            parser.parse(ims=ims, local=True)

    def validate(self, serder, nests=None):
        """Check a multisig wrapper's shape, child commitments, and local membership.

        Args:
            serder (Serder): Sender-authenticated multisig proposal wrapper.
            nests (Iterable | None): Exact parsed children for ACDC v2 wrappers.

        Returns:
            tuple | None: (proposal key, sender, route, wrapper SAID) for a supported
            proposal; None for a legacy wrapper without an embedded digest.

        Raises:
            ValidationError: Unsupported route, wrong child type/count/SAID, registry
            controller mismatch, or missing exact TEL seal in the proposed key event.
            ValueError: Local participant/group membership or sender membership fails.

        This performs no writes and grants no local consent. ACDC v2 registry proposals
        use their anchoring key-event SAID as the aggregation key; exchange proposals use
        the signed child SAID, so distinct bodies cannot share approval accidentally."""
        ked = serder.ked
        embed = ked.get('e')
        nests = nests if nests is not None else []
        payload = ked['a']
        sender = ked['i']
        route = ked['r']
        ovrsn = serder.pvrsn
        exnSaid = serder.said

        if route in ('/multisig/rip', '/multisig/bup') and ovrsn != Vrsn_2_0:
            raise ValidationError('ACDC v2 registry proposal requires a v2 wrapper')

        if ovrsn.major == Vrsn_1_0.major:
            if embed is None or "d" not in embed:
                return

            # Preserve the legacy V1 aggregation key for both single- and multi-child wrappers
            esaid = embed["d"]
        elif route in ('/multisig/rip', '/multisig/bup'):
            if len(nests) != 2 or not isinstance(payload, dict):
                raise ValidationError('ACDC v2 registry proposal requires TEL and KEL children')
            children = [nest['serder'] if isinstance(nest, dict) else nest.serder for nest in nests]
            tel, anchor = children
            if (tel.ilk != route.rsplit('/', 1)[-1]
                    or tel.pvrsn.major != 2 or anchor.ilk not in (Ilks.ixn, Ilks.rot, Ilks.drt)
                    or anchor.pre != payload.get('gid')
                    or not tel.verify() or not anchor.verify()
                    or tel.said != payload.get('tel') or anchor.said != payload.get('anc')):
                raise ValidationError('invalid ACDC v2 registry proposal bodies')
            if tel.ilk == Ilks.rip and tel.sad['i'] != anchor.pre:
                raise ValidationError('ACDC v2 registry inception has a different controller')
            validateRegistryAnchor(tel, anchor, payload.get('gid'))
            group = self.hby.habByPre(payload.get('gid'))
            validateRegistrySalts(payload.get('salts'), group.smids if group else [])
            esaid = anchor.said
        else:
            if len(nests) != 1:
                raise ValidationError(f"invalid multisig nested substreams count={len(nests)}, expected 1")

            # Allow only supported routes through v2 path
            supported = ("/multisig/icp", "/multisig/rot", "/multisig/ixn", "/multisig/rpy", "/multisig/exn")
            if route not in supported:
                raise ValidationError(f"unsupported V2 multisig route {route}")

            field = route.rsplit("/", 1)[-1]

            # Retrieve the child SAID from the route-specific field in `a`
            signed = payload.get(field) if isinstance(payload, dict) else None
            if signed is None:
                raise ValidationError(f"invalid multisig payload missing signed {field} child SAID for route {route}")

            # Retrieve child event serder directly from nested substream
            nserder = nests[0]["serder"] if isinstance(nests[0], dict) else nests[0].serder

            # Validate child ilks
            allowed = {
                "/multisig/icp": (Ilks.icp, Ilks.dip),
                "/multisig/rot": (Ilks.rot,),
                "/multisig/ixn": (Ilks.ixn,),
                "/multisig/rpy": (Ilks.rpy,),
                "/multisig/exn": (Ilks.exn,),
            }
            if nserder.ilk not in allowed[route]:
                raise ValidationError(f"invalid multisig nested substream ilk {nserder.ilk} for route {route}")
            if route == '/multisig/exn' and (nserder.pvrsn.major != 2
                    or nserder.pre != payload.get('gid') or not nserder.route.startswith('/ipex/')):
                raise ValidationError('ACDC v2 group exchange must be IPEX from this group')

            # Make sure the child event is saidive before validating the signed child SAID
            saids = nserder.Fields[nserder.proto][nserder.pvrsn][nserder.ilk].saids
            if not saids:
                raise ValidationError(f"invalid multisig nested substream ilk {nserder.ilk} is not saidive")
            
            # Validate the nested child digest against the route-specific signed child SAID
            if not nserder.verify() or not nserder.compare(signed):
                raise ValidationError(f"invalid multisig nested substream digest for route {route}")

            # Use the signed child SAID as the V2 proposal identity
            esaid = signed

        # Route specific logic to ensure this is a valid exn for a local participant.
        match route.split("/"):
            case ["", "multisig", "icp"]:
                mids = list(payload["smids"])
                if "rmids" in payload:
                    mids.extend(payload["rmids"])
                member = any([True for mid in mids if mid in self.hby.habs])
                if not member:
                    raise ValueError(f"invalid request to join group, not member in mids={mids}")

            case ["", "multisig", "rot"]:
                gid = payload["gid"]

                # Check if we know this group identifier locally
                if gid not in self.hby.habs:
                    mids = list(payload["smids"])
                    mids.extend(payload["rmids"])
                    member = any([True for mid in mids if mid in self.hby.habs])
                    if not member:
                        raise ValueError(f"invalid request to join group, not member in mids={mids}")

            case ["", "multisig", *_]:
                gid = payload["gid"]
                if gid not in self.hby.habs:
                    raise ValueError(f"invalid request to participate in group, not member of gid={gid}")
                if ovrsn.major == 2 and route in ('/multisig/rip', '/multisig/bup', '/multisig/exn'):
                    if sender not in self.hby.db.signingMembers(pre=gid):
                        raise ValueError('v2 multisig proposal sender is not a signing member')

            case _:
                raise ValueError(f"invalid route {route} for multiplexed exn={ked}")

        return esaid, sender, route, exnSaid

    def add(self, serder, nests=None):
        """Process a /multisig exn by associating it with its wrapped event payload.

        Adds the exn message contained in `serder` to the set of messages received
        for a given wrapped event payload. Ensures this is a /multisig message with
        the correct properties and then stores the SAID of the exn message and the
        prefix of the sender associated with the wrapped event payload. Also sends
        the controller of the local participant a notice.

        This method will extract and parse the wrapped events if the local
        participant has already approved them so any additional signatures can be
        processed.

        Parameters:
            serder (SerderKERI): peer-to-peer exn "/multisig" message to coordinate
                from other participants
            nests (list | None): parsed nested substreams for single-child V2
                exchanges

        Returns:

        """
        result = self.validate(serder=serder, nests=nests)
        if result is None:
            return

        esaid, sender, route, exnSaid = result

        # Retrieve all EXN SAIDs for this child event
        digers = list(self.hby.db.meids.get(keys=(esaid,)))

        # Check if it is the first time we see this child event
        firstSeen = len(digers) == 0

        # Retrieve all AIDs that already submitted this child event
        submitters = self.hby.db.maids.get(keys=(esaid,))
        if sender not in self.hby.habs:  # We are not sending this one, need to parse if already approved

            # Only a locally controlled submitter counts as approval.
            approved = any([True for sub in submitters if sub.qb64 in self.hby.habs])

            if approved:
                self._replayApproved(exnSaid)
            else:
                if firstSeen:
                    self.notifier.add(attrs=dict(r=route, d=exnSaid))
                else:
                    self.notifier.add(attrs=dict(r=route, d=exnSaid, e=esaid))
        elif not firstSeen and any([True for sub in submitters if sub.qb64 not in self.hby.habs]):
            # If a remote copy arrived before we registered our local approval, replay it now.
            for diger in digers:
                self._replayApproved(diger.qb64)

        self.hby.db.meids.add(keys=(esaid,), val=Saider(qb64=exnSaid))
        self.hby.db.maids.add(keys=(esaid,), val=Prefixer(qb64=sender))

    def get(self, esaid):
        digers = self.hby.db.meids.get(keys=(esaid,))

        exns = []
        for diger in digers:
            exn, paths = cloneMessage(hby=self.hby, said=diger.qb64)
            nests = self.hby.db.enst.get(keys=(diger.qb64,))
            exns.append(dict(
                exn=exn.ked,
                paths={k: path.decode("utf-8") for k, path in paths.items()},
                nests=nests if nests else None,
            ))

        return exns
