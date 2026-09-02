# -*- encoding: utf-8 -*-
"""
KERI
keri.app.agenting module

"""
import json
import random
from urllib.parse import urlencode, urlparse, urljoin

from hio.base import doing
from hio import hioing
from hio.core import http
from hio.core.tcp import clienting
from hio.help import decking, Hict

from socket import gaierror

from . import httping, forwarding
from .. import help
from .. import kering
from .. import core
from ..core import eventing, parsing, coring, serdering, indexing
from ..db import dbing
from ..kering import Roles

logger = help.ogler.getLogger()


def _messengerTransportError(client, protocol, target, pending):
    """Return the retained transport exception or a directional close error.

    Parameters:
        client: HIO TCP or HTTP client exposing directional terminal state.
        protocol (str): transport label included in a synthesized error.
        target (str): remote identifier included in a synthesized error.
        pending (int): bytes still owned locally at terminal close.
    """
    if client.error is not None:
        return client.error

    directions = []
    if client.cutoff:
        directions.append("receive")
    if client.txCutoff:
        directions.append("transmit")

    direction = " and ".join(directions) if directions else "connection"
    return kering.ClosedError(
        f"{protocol} {direction} cutoff for {target} with {pending} pending bytes"
    )


class Receiptor(doing.DoDoer):
    """DoDoer for synchronous witness receipting and receipt queries over HTTP.

    Drains `msgs` for witness receipt submissions and `gets` for receipt
    queries, pushing processed request dicts to `cues`.
    """

    def __init__(self, hby, msgs=None, gets=None, cues=None):
        """Initialize with shared queues and an HTTP client.

        Parameters:
            hby (Habery): Habitat environment for identifier lookups.
            msgs (Deck): receipt requests with `pre`, optional `sn`, optional `auths`.
            gets (Deck): receipt query requests with `pre`, optional `sn`.
            cues (Deck): completed request cues.
        """

        self.msgs = msgs if msgs is not None else decking.Deck()
        self.gets = gets if gets is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.hby = hby
        self.clienter = httping.Clienter()

        doers = [self.clienter,
                 doing.doify(self.witDo, tock=hby.tocks["receiptor"]),
                 doing.doify(self.gitDo, tock=hby.tocks["receiptor"])]

        super(Receiptor, self).__init__(doers=doers)

    def receipt(self, pre, sn=None, auths=None, tock=0.0):
        """Yield while witnessing an event and returning witness receipt couples.

        Sends the event to all witnesses, optionally catches new witnesses up,
        then propagates the collected non-transferable receipts to each witness.

        Parameters:
            pre (str): qb64 identifier to receipt for.
            sn (int | None): sequence number, defaults to latest.
            auths (dict | None): optional map of wit AID to 2FA auth header value.

        Returns:
            iterable: witness identifiers that returned receipts.
        """
        auths = auths if auths is not None else dict()
        if pre not in self.hby.prefixes:
            raise kering.MissingEntryError(f"{pre} not a valid AID")

        hab = self.hby.habs[pre]
        sn = sn if sn is not None else hab.kever.sner.num
        wits = hab.kever.wits

        if len(wits) == 0:
            return

        msg = hab.makeOwnEvent(sn=sn)
        ser = serdering.SerderKERI(raw=msg)

        # If we are a rotation event, may need to catch new witnesses up to current key state
        if ser.ked['t'] in (coring.Ilks.rot, coring.Ilks.drt,):
            adds = ser.ked["ba"]
            for wit in adds:
                yield from self.catchup(ser.pre, wit, tock=tock)

        clients = dict()
        doers = []
        for wit in wits:
            try:
                client, clientDoer = httpClient(hab, wit)
                clients[wit] = client
                doers.append(clientDoer)
                self.extend([clientDoer])
            except (kering.MissingEntryError, gaierror) as e:
                logger.error(f"unable to create http client for witness {wit}: {e}")

        rcts = dict()
        for wit, client in clients.items():
            headers = dict()
            if wit in auths:
                headers["Authorization"] = auths[wit]

            httping.streamCESRRequests(client=client, dest=wit, ims=bytearray(msg), path="receipts", headers=headers)
            while not client.responses:
                yield tock

            rep = client.respond()
            if rep.status == 200:
                rct = bytearray(rep.body)
                hab.psr.parseOne(bytearray(rct))
                rserder = serdering.SerderKERI(raw=rct)
                del rct[:rserder.size]

                # pull off the count code
                core.Counter(qb64b=rct, strip=True, gvrsn=kering.Vrsn_1_0)
                rcts[wit] = rct
            else:
                print(f"invalid response {rep.status} from witnesses {wit}")

        for wit in rcts:
            ewits = [w for w in rcts if w != wit]
            wigs = [sig for w, sig in rcts.items() if w != wit]

            msg = bytearray()
            if ser.ked['t'] in (coring.Ilks.icp, coring.Ilks.dip):  # introduce new witnesses
                msg.extend(schemes(self.hby.db, eids=ewits))
            elif ser.ked['t'] in (coring.Ilks.rot, coring.Ilks.drt) and \
                    ("ba" in ser.ked and wit in ser.ked["ba"]):  # Newly added witness, introduce to all
                msg.extend(schemes(self.hby.db, eids=ewits))

            rserder = eventing.receipt(pre=hab.pre,
                                       sn=sn,
                                       said=ser.said)
            msg.extend(rserder.raw)
            msg.extend(core.Counter(core.Codens.NonTransReceiptCouples,
                                    count=len(wigs), gvrsn=kering.Vrsn_1_0).qb64b)
            for wig in wigs:
                msg.extend(wig)

            client = clients[wit]

            sent = httping.streamCESRRequests(client=client, dest=wit, ims=bytearray(msg))
            while len(client.responses) < sent:
                yield tock

        self.remove(doers)

        return rcts.keys()

    def get(self, pre, sn=None, tock=0.0):
        """Yield while querying a witness for receipts of an event identified by pre and sn.

        Picks one witness and issues GET /receipts?pre=&sn=. Parses any
        returned receipts into the local parser.

        Returns:
            bool: True if the witness returned HTTP 200.
        """
        if pre not in self.hby.prefixes:
            raise kering.MissingEntryError(f"{pre} not a valid AID")

        hab = self.hby.habs[pre]
        sn = sn if sn is not None else hab.kever.sner.num
        wits = hab.kever.wits

        if len(wits) == 0:
            return

        wit = random.choice(hab.kever.wits)
        urls = hab.fetchUrls(eid=wit, scheme=kering.Schemes.http) or hab.fetchUrls(eid=wit, scheme=kering.Schemes.https)
        if not urls:
            raise kering.MissingEntryError(f"unable to query witness {wit}, no http endpoint")

        base = urls[kering.Schemes.http] if kering.Schemes.http in urls else urls[kering.Schemes.https]
        url = urljoin(base, f"/receipts?pre={pre}&sn={sn}")

        headers = Hict([(httping.CESR_DESTINATION_HEADER, wit)])
        client = self.clienter.request("GET", url, headers=headers)
        while not client.responses:
            yield tock

        rep = client.respond()
        if rep.status == 200:
            rct = bytearray(rep.body)
            hab.psr.parseOne(bytearray(rct))

        self.clienter.remove(client)
        return rep.status == 200

    def ksn(self, pre, wit, src, tock=0.0):
        """Yield while querying a witness for the key state of an identifier.

        Parameters:
            pre (str): qb64 identifier whose key state is requested.
            wit (str): qb64 witness identifier to query.
            src (str): qb64 local identifier issuing the query.

        Returns:
            bool: True if the witness returned HTTP 200.
        """
        if src not in self.hby.prefixes:
            raise kering.MissingEntryError(f"{pre} not a valid AID")

        hab = self.hby.habs[src]
        kever = hab.kevers[pre]

        if wit not in kever.wits:
            return

        urls = hab.fetchUrls(eid=wit, scheme=kering.Schemes.http) or \
            hab.fetchUrls(eid=wit, scheme=kering.Schemes.https)
        if not urls:
            raise kering.MissingEntryError(f"unable to query witness {wit}, no http endpoint")

        base = urls[kering.Schemes.http] if kering.Schemes.http in urls else urls[kering.Schemes.https]
        url = urljoin(base, f"/ksn?pre={pre}&src={src}")
        headers = Hict([(httping.CESR_DESTINATION_HEADER, wit)])

        client = self.clienter.request("GET", url, headers=headers)
        while not client.responses:
            yield tock

        rep = client.respond()
        if rep.status == 200:
            hab.psr.parseOne(bytearray(rep.body))

        self.clienter.remove(client)
        return rep.status == 200

    def logs(self, pre, wit, src, sn=None, fn=None, anchor=None, tock=0.0):
        """Yield while retrieving an identifier's event log from a witness.

        Parameters:
            pre (str): qb64 identifier whose event log is requested.
            wit (str): qb64 witness identifier to query.
            src (str): qb64 local identifier issuing the query.
            sn (int | None): optional minimum witnessed sequence number.
            fn (int | None): optional first ordinal for the cloned log.
            anchor (dict | None): optional event seal with `i`, `s`, and `d` fields.

        Returns:
            bool: True if the witness returned HTTP 200.
        """
        if src not in self.hby.prefixes:
            raise kering.MissingEntryError(f"{pre} not a valid AID")

        hab = self.hby.habs[src]
        kever = hab.kevers[pre]

        if wit not in kever.wits:
            return

        urls = hab.fetchUrls(eid=wit, scheme=kering.Schemes.http) or \
            hab.fetchUrls(eid=wit, scheme=kering.Schemes.https)
        if not urls:
            raise kering.MissingEntryError(f"unable to query witness {wit}, no http endpoint")

        params = {"pre": pre}
        if sn is not None:
            params["s"] = f"{sn:X}"
        if fn is not None:
            params["fn"] = f"{fn:X}"
        if anchor is not None:
            params["a"] = json.dumps(anchor, separators=(",", ":"))

        base = urls[kering.Schemes.http] if kering.Schemes.http in urls else urls[kering.Schemes.https]
        url = urljoin(base, f"/log?{urlencode(params)}")
        headers = Hict([(httping.CESR_DESTINATION_HEADER, wit)])

        client = self.clienter.request("GET", url, headers=headers)
        while not client.responses:
            yield tock

        rep = client.respond()
        if rep.status == 200:
            hab.psr.parse(bytearray(rep.body))
        else:
            logger.info(f"Failed to retrieve log from {wit}: {rep.status} {rep.body}")

        self.clienter.remove(client)
        return rep.status == 200

    def catchup(self, pre, wit, tock=0.0):
        """
        Yield while replaying the full KEL for `pre` to the witness.
        When adding a new Witness, use this method to catch the witness up to the current state of the KEL

        Parameters:
            pre (str): qualified base64 AID of the KEL to send
            wit (str): qualified base64 AID of the witness to send the KEL to
        """
        if pre not in self.hby.prefixes:
            raise kering.MissingEntryError(f"{pre} not a valid AID")

        hab = self.hby.habs[pre]

        client, clientDoer = httpClient(hab, wit)
        self.extend([clientDoer])

        for fmsg in hab.db.clonePreIter(pre=pre):
            httping.streamCESRRequests(client=client, dest=wit, ims=bytearray(fmsg))
            while not client.responses:
                yield tock

        self.remove([clientDoer])

    def witDo(self, tymth=None, tock=0.0, **kwa):
        """Doer loop that drains `msgs` and runs witness receipt flow."""
        self.wind(tymth)
        _ = (yield tock)

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                pre = msg["pre"]
                sn = msg["sn"] if "sn" in msg else None
                auths = msg["auths"] if "auths" in msg else None

                yield from self.receipt(pre, sn, auths, tock=tock)
                self.cues.push(msg)

            yield tock

    def gitDo(self, tymth=None, tock=0.0, **kwa):
        """Doer loop that drains `gets` and runs witness receipt queries."""
        self.wind(tymth)
        _ = (yield tock)

        while True:
            while self.gets:
                msg = self.gets.popleft()
                pre = msg["pre"]
                sn = msg["sn"] if "sn" in msg else None

                yield from self.get(pre, sn, tock=tock)

            yield tock


class WitnessReceiptor(doing.DoDoer):
    """Witness receipt doer that sends events and propagates receipts.

    Uses messenger doers to asynchronously send the event to each witness,
    waits for receipts to arrive in `hab.db` (via mailbox processing), then
    propagates the full receipt set across the witness group.

    A completion cue means the original receipts exist locally and the
    receipt fan-out reached every messenger's local transport boundary. It
    does not assert that each remote witness processed the fan-out.

    Could be enhanced to have a `once` method that runs once and cleans up
    and an `all` method that runs and waits for more messages to receipt.
    """

    def __init__(self, hby, msgs=None, cues=None, force=False, auths=None, **kwa):
        """Initialize with queues and optional auth for witness endpoints.

        Parameters:
            hby (Habery): Habitat environment for identifier lookups.
            msgs (Deck): receipt requests with `pre` and optional `sn`.
            cues (Deck): completed request cues.
            force (bool): resend receipts even if already complete.
            auths (dict | None): optional map of wit AID to auth header value.
        """
        self.hby = hby
        self.force = force
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.auths = auths if auths is not None else dict()
        self.idleTock = hby.tocks["witnessReceiptorIdle"]

        super(WitnessReceiptor, self).__init__(
            doers=[doing.doify(self.receiptDo,
                               tock=hby.tocks["witnessReceiptor"])], **kwa)

    def receiptDo(self, tymth=None, tock=0.0, **kwa):
        """Doer loop that sends events to witnesses and propagates receipts.


        Asynchronously processes witness receipt requests from self.msgs queue.
        Sends any required delegation context, replays KEL for new witnesses,
        posts the event, waits for receipts to be stored in `hab.db`, then
        shares the full receipt set across witnesses. If `force` is false and
        all receipts already exist, it skips resubmission.
        Terminal messenger errors are logged and suppress the completion cue.
        """
        self.wind(tymth)
        _ = (yield tock)

        while True:
            while self.msgs:
                evt = self.msgs.popleft()
                pre = evt["pre"]

                if pre not in self.hby.habs:
                    continue

                hab = self.hby.habs[pre]

                sn = evt["sn"] if "sn" in evt else hab.kever.sner.num
                wits = hab.kever.wits

                if len(wits) == 0:
                    continue

                msg = hab.makeOwnEvent(sn=sn)
                ser = serdering.SerderKERI(raw=msg)

                dgkey = dbing.dgKey(ser.preb, ser.saidb)

                witers = []
                for wit in wits:
                    auth = self.auths[wit] if wit in self.auths else None
                    witer = messenger(hab, wit, auth=auth)
                    witers.append(witer)
                    self.extend([witer])

                # Check to see if we already have all the receipts we need for this event
                wigs = hab.db.getWigs(dgkey)
                completed = len(wigs) == len(wits)
                failed = False
                if len(wigs) != len(wits):  # We have all the receipts, skip
                    for idx, witer in enumerate(witers):
                        wit = wits[idx]

                        for dmsg in hab.db.cloneDelegation(hab.kever):
                            witer.msgs.append(bytearray(dmsg))

                        if ser.ked['t'] in (coring.Ilks.icp, coring.Ilks.dip) or \
                                "ba" in ser.ked and wit in ser.ked["ba"]:  # Newly added witness, must catch up
                            for fmsg in hab.db.clonePreIter(pre=pre):
                                witer.msgs.append(bytearray(fmsg))

                        witer.msgs.append(bytearray(msg))  # make a copy
                        _ = (yield tock)

                    while True:  # wait for all receipts to arrive
                        wigs = hab.db.getWigs(dgkey)
                        if len(wigs) == len(wits):
                            break

                        failure = next((witer for witer in witers
                                        if witer.error is not None), None)
                        if failure is not None:
                            logger.error(f"Witness delivery to {failure.wit} failed: "
                                         f"{failure.error}")
                            failed = True
                            break
                        _ = yield tock

                if failed:
                    self.remove(witers)
                    continue

                # If we started with all our receipts, exit unless told to force resubmit of all receipts
                if completed and not self.force:
                    self.remove(witers)
                    self.cues.push(evt)
                    continue

                # generate all rct msgs to send to all witnesses
                awigers = [indexing.Siger(qb64b=bytes(wig)) for wig in wigs]

                # make sure all witnesses have fully receipted KERL and know about each other
                for witer in witers:
                    ewits = []
                    wigers = []
                    for i, wit in enumerate(wits):
                        if wit == witer.wit:
                            continue
                        ewits.append(wit)
                        wigers.append(awigers[i])

                    if len(wigers) == 0:
                        continue

                    rctMsg = bytearray()

                    # Now that the witnesses have not met each other, send them each other's receipts
                    if ser.ked['t'] in (coring.Ilks.icp, coring.Ilks.dip):  # introduce new witnesses
                        rctMsg.extend(schemes(self.hby.db, eids=ewits))
                    elif ser.ked['t'] in (coring.Ilks.rot, coring.Ilks.drt) and \
                            ("ba" in ser.ked and witer.wit in ser.ked["ba"]):  # Newly added witness, introduce to all
                        rctMsg.extend(schemes(self.hby.db, eids=ewits))

                    rserder = eventing.receipt(pre=ser.pre,
                                               sn=sn,
                                               said=ser.said)
                    rctMsg.extend(eventing.messagize(serder=rserder, wigers=wigers))

                    witer.msgs.append(rctMsg)
                    _ = (yield tock)

                while True:
                    failure = next((witer for witer in witers
                                    if witer.error is not None), None)
                    if failure is not None:
                        logger.error(f"Witness delivery to {failure.wit} failed: "
                                     f"{failure.error}")
                        failed = True
                        break
                    if all(witer.idle for witer in witers):
                        break
                    yield self.idleTock

                self.remove(witers)

                if failed:
                    continue

                self.cues.push(evt)
                yield tock

            yield tock


class WitnessInquisitor(doing.DoDoer):
    """
    Sends messages to all current witnesses of given identifier (from hab) and waits
    for receipts from each of those witnesses and propagates those receipts to each
    of the other witnesses after receiving the complete set.

    Builds and sends qry/tel queries, pushing the raw sent message to `sent`.
    The response parsing happens elsewhere (e.g. mailbox or HTTP response handlers).

    Could be enhanced to have a `once` method that runs once and cleans up
    and an `all` method that runs and waits for more messages to receipt.
    """

    def __init__(self, hby, reger=None, msgs=None, klas=None, **kwa):
        """Initialize with a message queue and optional messenger class.

        Parameters:
            hby (Habery): Habitat environment for endpoint and kever lookup.
            reger (Reger | None): optional registry database handle.
            msgs (Deck): query requests built by `query`/`telquery`.
            klas (type | None): messenger class, defaults to `HTTPMessenger`.
        """
        self.hby = hby
        self.reger = reger
        self.klas = klas if klas is not None else HTTPMessenger
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.sent = decking.Deck()

        super(WitnessInquisitor, self).__init__(
            doers=[doing.doify(self.msgDo,
                               tock=hby.tocks["witnessInquisitor"])], **kwa)

    def msgDo(self, tymth=None, tock=0.0, **opts):
        """
        Doer loop that sends one query to one selected endpoint.

        For all msgs, select a random witness from Habitat's current set of witnesses
        send the msg and process all responses (KEL replays, RCTs, etc)
        Pushes the raw sent message to self.sent to signal local transport
        completion. Terminal delivery failure removes the messenger without
        reporting the message as sent.
        """
        self.wind(tymth)
        _ = (yield tock)

        while True:
            while not self.msgs:
                yield tock

            evt = self.msgs.popleft()
            pre = evt["pre"]
            target = evt["target"]
            src = evt["src"]
            r = evt["r"]
            q = evt["q"]
            wits = evt["wits"] if "wits" in evt else None

            if "hab" in evt:
                hab = evt["hab"]
            elif (hab := self.hby.habByPre(src)) is None:
                continue

            if not wits and pre not in self.hby.kevers:
                logger.error(f"must have KEL for identifier to query {pre}")
                continue

            if not wits:
                ends = hab.endsFor(pre=pre)
                if Roles.controller in ends:
                    end = ends[Roles.controller]
                elif Roles.agent in ends:
                    end = ends[Roles.agent]
                elif Roles.witness in ends:
                    end = ends[Roles.witness]
                else:
                    logger.error(f"unable query: can not find a valid role for {pre}")
                    continue

                if len(end.items()) == 0:
                    logger.error(f"must have endpoint to query for pre={pre}")
                    continue

                ctrl, locs = random.choice(list(end.items()))
                if len(locs.items()) == 0:
                    logger.error(f"must have location in endpoint to query for pre={pre}")
                    continue

                witer = messengerFrom(hab=hab, pre=ctrl, urls=locs)
            else:
                wit = random.choice(wits)
                witer = messenger(hab, wit)

            self.extend([witer])

            msg = hab.query(target, src=witer.wit, route=r, query=q)  # Query for remote pre Event

            kel = forwarding.introduce(hab, witer.wit)
            if kel:
                witer.msgs.append(bytearray(kel))

            witer.msgs.append(bytearray(msg))

            while not witer.sent and witer.error is None:
                yield tock

            if witer.error is not None:
                logger.error(f"Witness query delivery to {witer.wit} failed: "
                             f"{witer.error}")
                self.remove([witer])
                continue

            self.sent.append(witer.sent.popleft())

            yield tock

    def query(self, pre, r="logs", sn='0', fn='0', src=None, hab=None, anchor=None, wits=None, **kwa):
        """Create, sign, and queue a `qry` KEL query request against the attester for the prefix for later sending.

        Parameters:
            pre (str): qb64 identifier being queried.
            r (str): query route (e.g. "logs").
            sn (str): optional hex sequence number to query for.
            fn (str): optional hex start sequence number.
            src (str | None): qb64 source identifier (ignored if `hab` provided).
            hab (Hab | None): habitat used to sign and route the query.
            anchor (Seal | None): anchored seal to search for.
            wits (list | None): explicit witnesses to target; otherwise uses endpoints.
        """
        qry = dict(s=sn, fn=fn)
        if anchor is not None:
            qry["a"] = anchor

        msg = dict(src=src, pre=pre, target=pre, r=r, q=qry, wits=wits)
        if hab is not None:
            msg["hab"] = hab

        self.msgs.append(msg)

    def telquery(self, ri, src=None, i=None, r="tels", hab=None, pre=None, wits=None, **kwa):
        """Queue a TEL query request for later sending."""
        qry = dict(ri=ri)
        msg = dict(src=src, pre=pre, target=i, r=r, wits=wits, q=qry)
        if hab is not None:
            msg["hab"] = hab

        self.msgs.append(msg)


class WitnessPublisher(doing.DoDoer):
    """DoDoer that publishes messages to all witnesses for an identifier.

    ``messageInProgress`` remains true from dequeue until every child
    messenger reaches local completion or one records terminal failure.
    ``cues`` is only a consumable success-notification queue and does not
    participate in the publisher's ``idle`` calculation.

    Could be enhanced to have a `once` method that runs once and cleans up
    and an `all` method that runs and waits for more messages to receipt.
    """

    def __init__(self, hby, msgs=None, cues=None, **kwa):
        """Initialize with publish queue and completion cues.

        Parameters:
            hby (Habery): Habitat environment for identifier lookups.
            msgs (Deck): publish requests with `pre` and `msg`.
            cues (Deck): completed request cues.

        Attributes:
            messageInProgress (bool): whether one dequeued publication still
                owns child messenger work.
        """
        self.hby = hby
        self.messageInProgress = False
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        super(WitnessPublisher, self).__init__(
            doers=[doing.doify(self.sendDo,
                               tock=hby.tocks["witnessPublisher"])], **kwa)

    def sendDo(self, tymth=None, tock=0.0, **opts):
        """Doer loop that sends queued messages to each witness.

        Pushes the request to `cues` only when every messenger becomes idle.
        Terminal delivery failure removes all children without reporting
        success.
        """
        self.wind(tymth)
        _ = (yield tock)

        while True:
            while self.msgs:
                evt = self.msgs.popleft()
                self.messageInProgress = True
                try:
                    pre = evt["pre"]
                    msg = evt["msg"]

                    if pre not in self.hby.habs:
                        continue

                    hab = self.hby.habs[pre]
                    wits = hab.kever.wits

                    witers = []
                    for wit in wits:
                        witer = messenger(hab, wit)
                        witers.append(witer)
                        # Each transport owns its own mutable message copy.
                        witer.msgs.append(bytearray(msg))
                        self.extend([witer])

                        _ = (yield tock)

                    failed = False
                    for witer in witers:
                        while not witer.idle and witer.error is None:
                            _ = (yield tock)

                        if witer.error is not None:
                            logger.error(
                                f"Witness publication to {witer.wit} failed: "
                                f"{witer.error}")
                            failed = True

                    self.remove(witers)

                    if failed:
                        continue

                    self.messageInProgress = False
                    self.cues.push(evt)

                    yield tock
                finally:
                    self.messageInProgress = False

            yield tock

    def sent(self, said):
        """ Check if message with given SAID was sent

        Parameters:
            said (str): qb64 SAID of message to check for
        """

        for cue in self.cues:
            if cue["said"] == said:
                return True

        return False

    @property
    def idle(self):
        """Whether no queued or active publication remains.

        Completion cues are consumable notifications and therefore do not
        participate in lifecycle accounting.
        """
        return not self.msgs and not self.messageInProgress


class TCPMessenger(doing.DoDoer):
    """Serially send CESR messages to a witness and parse inbound receipts.

    Only one dequeued message is owned at a time.  It remains in progress until
    its bytes drain from HIO's local send buffer or the transport records a
    terminal transmit error. A receive-only cutoff does not prevent raw TCP
    from draining queued output. Local drain does not prove remote receipt or
    processing.

    ``sent`` is a consumable notification queue, not lifecycle accounting.
    ``idle`` is therefore derived from the input queue, active-message flag,
    and HIO transmit buffer. ``error`` retains the first terminal transport
    outcome and makes ``idle`` false so owners cannot mistake failure for
    successful completion.
    """

    def __init__(self, hab, wit, url, msgs=None, sent=None, doers=None, **kwa):
        """Initialize TCP messenger with queues and parser wiring.

        Parameters:
            hab (Hab): habitat for KEL parsing and db access.
            wit (str): qb64 witness identifier.
            url (str): tcp endpoint URL for the witness.
            msgs (Deck | None): outbound message queue.
            sent (Deck | None): consumable successful-drain notification queue.

        Attributes:
            messageInProgress (bool): whether one dequeued message still owns
                local transmit work.
            error (Exception | None): retained terminal transmit failure.
        """
        self.hab = hab
        self.wit = wit
        self.url = url
        self.messageInProgress = False
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.sent = sent if sent is not None else decking.Deck()
        self.client = None
        self.error = None
        self.parser = None
        doers = doers if doers is not None else []
        doers.extend([doing.doify(self.receiptDo)])

        self.kevery = eventing.Kevery(db=self.hab.db,
                                      **kwa)

        super(TCPMessenger, self).__init__(doers=doers)

    def receiptDo(self, tymth=None, tock=0.0, **kwa):
        """Send queued messages one at a time to local transport completion.

        A dequeued message remains in progress while HIO owns any of its bytes
        in ``txbs``. A transmit cutoff retains ``error`` and ends the sender.
        A receive-only cutoff is directional and does not prevent remaining
        bytes from draining. Successful drain publishes the original message
        to the consumable ``sent`` queue before the next message is admitted.

        Yields:
            The configured ``tock`` while idle or awaiting transport drain.
        """
        self.wind(tymth)
        _ = (yield tock)

        up = urlparse(self.url)
        if up.scheme != kering.Schemes.tcp:
            raise ValueError(f"invalid scheme {up.scheme} for TcpWitnesser")

        self.client = clienting.Client(host=up.hostname, port=up.port)
        self.parser = parsing.Parser(ims=self.client.rxbs,
                                     framed=True,
                                     kvy=self.kevery)

        clientDoer = clienting.ClientDoer(client=self.client)
        self.extend([clientDoer, doing.doify(self.msgDo)])

        while True:
            while not self.msgs:
                yield tock

            msg = self.msgs.popleft()
            self.messageInProgress = True
            try:
                try:
                    self.client.tx(msg)  # send to connected remote
                except hioing.HioError:
                    if not self.client.txCutoff:
                        raise
                    self.error = _messengerTransportError(
                        self.client, "TCP", self.wit, len(msg))
                    return False

                while self.client.txbs:
                    if self.client.txCutoff:
                        self.error = _messengerTransportError(
                            self.client, "TCP", self.wit,
                            len(self.client.txbs))
                        return False
                    yield tock

                self.messageInProgress = False
                self.sent.append(msg)
                yield tock
            finally:
                self.messageInProgress = False

    def msgDo(self, tymth=None, tock=0.0, **opts):
        """Doer loop that parses inbound TCP messages into the Kevery."""
        parser = self.parser.parsator(local=True)
        while True:
            try:
                next(parser)
            except StopIteration as ex:
                return ex.value
            yield tock

    @property
    def idle(self):
        """Whether every queued message reached successful local TCP drain."""
        return (self.error is None and
                not self.msgs and
                not self.messageInProgress and
                (self.client is None or not self.client.txbs))

    @property
    def cutoff(self):
        """Whether the TCP receive direction has closed."""
        return bool(self.client is not None and self.client.cutoff)

    @property
    def txCutoff(self):
        """Whether the TCP transmit direction has closed."""
        return bool(self.client is not None and self.client.txCutoff)


class TCPStreamMessenger(doing.DoDoer):
    """Send one CESR message over TCP and terminate at local completion.

    The one-shot outcome is retained independently of the consumable ``sent``
    queue. Success means the admitted bytes drained from HIO's local transmit
    buffer; transmit failure is retained in ``error``. Receive-only cutoff is
    directional and does not prevent raw TCP output drain. Neither terminal
    outcome means remote processing.
    """

    def __init__(self, hab, wit, url, msg=None, msgs=None, sent=None,
                 doers=None, **kwa):
        """Initialize the one-shot message and parser wiring.

        Parameters:
            hab (Hab): habitat for KEL parsing and db access.
            wit (str): qb64 witness identifier.
            url (str): tcp endpoint URL for the witness.
            msg (bytes | None): sole CESR message to admit immediately.
            msgs (Deck | None): outbound message queue.
            sent (Deck | None): consumable successful-drain notification queue.

        Attributes:
            messageInProgress (bool): whether the admitted message still owns
                local transmit work.
            error (Exception | None): retained terminal transmit failure.
            _terminal (bool): private one-shot outcome latch used to end all
                child doers after success or failure.
        """
        self.hab = hab
        self.wit = wit
        self.url = url
        self.messageInProgress = False
        self.msgs = msgs if msgs is not None else decking.Deck()
        if msg is not None:
            self.msgs.append(bytearray(msg))
        self.sent = sent if sent is not None else decking.Deck()
        self.client = None
        self.error = None
        self._terminal = False
        self.parser = None
        doers = doers if doers is not None else []
        doers.extend([doing.doify(self.receiptDo)])

        self.kevery = eventing.Kevery(db=self.hab.db,
                                      **kwa)

        super(TCPStreamMessenger, self).__init__(doers=doers)

    def receiptDo(self, tymth=None, tock=0.0, **kwa):
        """Send the admitted message until local drain or transmit failure.

        The message remains in progress while HIO owns bytes in ``txbs``.
        Receive-only cutoff does not stop output drain. The retained one-shot
        outcome then lets ``recur`` cleanly close all transport/parser children.
        """
        self.wind(tymth)
        _ = (yield tock)

        up = urlparse(self.url)
        if up.scheme != kering.Schemes.tcp:
            raise ValueError(f"invalid scheme {up.scheme} for TcpWitnesser")

        self.client = clienting.Client(host=up.hostname, port=up.port)
        self.parser = parsing.Parser(ims=self.client.rxbs,
                                     framed=True,
                                     kvy=self.kevery)

        clientDoer = clienting.ClientDoer(client=self.client)
        self.extend([clientDoer, doing.doify(self.msgDo)])

        while not self.msgs:
            yield tock

        msg = self.msgs.popleft()
        self.messageInProgress = True
        try:
            try:
                self.client.tx(msg)
            except hioing.HioError:
                if not self.client.txCutoff:
                    raise
                self.error = _messengerTransportError(
                    self.client, "TCP", self.wit, len(msg))
                self._terminal = True
                return False

            while self.client.txbs:
                if self.client.txCutoff:
                    self.error = _messengerTransportError(
                        self.client, "TCP", self.wit,
                        len(self.client.txbs))
                    self._terminal = True
                    return False
                yield tock

            self.sent.append(msg)
            self._terminal = True
            return True
        finally:
            self.messageInProgress = False

    def msgDo(self, tymth=None, tock=0.0, **opts):
        """Doer loop that parses inbound TCP messages into the Kevery."""
        parser = self.parser.parsator(local=True)
        while True:
            try:
                next(parser)
            except StopIteration as ex:
                return ex.value
            yield tock

    def recur(self, tyme, deeds=None):
        """Advance children and finish once the one-shot outcome is retained."""
        done = super(TCPStreamMessenger, self).recur(tyme, deeds)
        return done or self._terminal

    @property
    def idle(self):
        """Whether the admitted message reached successful local TCP drain."""
        return (self.error is None and
                not self.msgs and
                not self.messageInProgress and
                (self.client is None or not self.client.txbs))

    @property
    def cutoff(self):
        """Whether the TCP receive direction has closed."""
        return bool(self.client is not None and self.client.cutoff)

    @property
    def txCutoff(self):
        """Whether the TCP transmit direction has closed."""
        return bool(self.client is not None and self.client.txCutoff)


class HTTPMessenger(doing.DoDoer):
    """Send CESR messages to a witness over HTTP and capture responses.

    Lifecycle completion is derived from live ownership across ``msgs`` and
    HIO's request, waited-response, transmit-buffer, and response queues.
    ``sent`` remains a consumable response-notification queue, so consuming a
    response cannot make completed work appear incomplete. ``error`` retains a
    terminal transport outcome only while unfinished work exists.
    """

    def __init__(self, hab, wit, url, msgs=None, sent=None, doers=None, auth=None, **kwa):
        """Initialize HTTP messenger with queues and optional auth.

        Parameters:
            hab (Hab): habitat for KEL parsing and db access.
            wit (str): qb64 witness identifier.
            url (str): http/https endpoint URL for the witness.
            msgs (Deck | None): outbound message queue.
            sent (Deck | None): consumable completed-response queue.
            auth (str | None): optional 2FA auth codes for witnesses.

        Attributes:
            error (Exception | None): terminal transport failure retained only
                when HTTP work remains unfinished.
        """
        self.hab = hab
        self.wit = wit
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.sent = sent if sent is not None else decking.Deck()
        self.error = None
        self.parser = None
        self.auth = auth
        doers = doers if doers is not None else []

        up = urlparse(url)
        if up.scheme != kering.Schemes.http and up.scheme != kering.Schemes.https:
            raise ValueError(f"invalid scheme {up.scheme} for HTTPMessenger")

        self.client = http.clienting.Client(scheme=up.scheme, hostname=up.hostname, port=up.port)
        clientDoer = http.clienting.ClientDoer(client=self.client)

        # Queue work, service the transport, then read its current state.
        doers.extend([doing.doify(self.msgDo),
                      clientDoer,
                      doing.doify(self.responseDo)])

        super(HTTPMessenger, self).__init__(doers=doers, **kwa)

    def msgDo(self, tymth=None, tock=0.0, **kwa):
        """Doer loop that sends queued messages over HTTP."""
        self.wind(tymth)
        _ = (yield tock)

        while True:
            while not self.msgs:
                yield tock

            msg = self.msgs.popleft()
            headers = dict()
            if self.auth is not None:
                headers["Authorization"] = self.auth

            httping.streamCESRRequests(client=self.client, dest=self.wit,
                                       ims=msg, headers=headers)
            while self.client.requests:
                yield tock

            yield tock

    def responseDo(self, tymth=None, tock=0.0, **kwa):
        """Move completed responses to ``sent`` and retain terminal failure."""
        self.wind(tymth)
        _ = (yield tock)

        while True:
            while self.client.responses:
                rep = self.client.respond()
                self.sent.append(rep)
                yield

            pending = (bool(self.msgs) or
                       bool(self.client.requests) or
                       self.client.waited or
                       bool(self.client.connector.txbs) or
                       bool(self.client.responses))
            if (self.error is None and pending and
                    (self.client.error is not None or self.client.cutoff or
                     self.client.txCutoff)):
                self.error = _messengerTransportError(
                    self.client, "HTTP", self.wit,
                    len(self.client.connector.txbs))
            yield

    @property
    def idle(self):
        """Whether HIO and this messenger own no unfinished HTTP work."""
        return (self.error is None and
                not self.msgs and
                not self.client.requests and
                not self.client.waited and
                not self.client.connector.txbs and
                not self.client.responses)

    @property
    def cutoff(self):
        """Whether the HTTP connector's receive direction has closed."""
        return self.client.cutoff

    @property
    def txCutoff(self):
        """Whether the HTTP connector's transmit direction has closed."""
        return self.client.txCutoff


class HTTPStreamMessenger(doing.DoDoer):
    """Send a single CESR message via HTTP PUT and retain one outcome.

    ``rep`` holds the successful HTTP response. ``error`` holds terminal
    transport failure. The doer completes for either outcome after servicing
    HIO, so a response already produced at the boundary wins over later close.
    """

    def __init__(self, hab, wit, url, msg=b'', headers=None, **kwa):
        """Initialize a single-request HTTP messenger.

        Parameters:
            hab (Hab): habitat for KEL parsing and db access.
            wit (str): qb64 witness identifier.
            url (str): http/https endpoint URL for the witness.
            msg (bytes): CESR message body to send.
            headers (dict | None): extra HTTP headers.

        Attributes:
            rep (Response | None): retained successful HIO response.
            error (Exception | None): retained terminal transport failure.
        """
        self.hab = hab
        self.wit = wit
        self.rep = None
        self.error = None
        headers = headers if headers is not None else {}

        up = urlparse(url)
        if up.scheme != kering.Schemes.http and up.scheme != kering.Schemes.https:
            raise ValueError(f"invalid scheme {up.scheme} for HTTPMessenger")

        self.client = http.clienting.Client(scheme=up.scheme, hostname=up.hostname, port=up.port)
        clientDoer = http.clienting.ClientDoer(client=self.client)

        headers = Hict([
            ("Content-Type", "application/cesr"),
            ("Content-Length", len(msg)),
            (httping.CESR_DESTINATION_HEADER, self.wit),
        ] + list(headers.items()))

        self.client.request(
            method="PUT",
            path="/",
            headers=headers,
            body=bytes(msg)
        )

        doers = [clientDoer]

        super(HTTPStreamMessenger, self).__init__(doers=doers, **kwa)

    def recur(self, tyme, deeds=None):
        """Service the client, then retain its response or terminal error."""
        done = super(HTTPStreamMessenger, self).recur(tyme, deeds)

        if self.client.responses:
            self.rep = self.client.respond()
            return True

        if (self.error is None and
                (self.client.error is not None or self.client.cutoff or
                 self.client.txCutoff)):
            self.error = _messengerTransportError(
                self.client, "HTTP", self.wit,
                len(self.client.connector.txbs))
            return True

        return done

    @property
    def idle(self):
        """Whether the one-shot request completed with an HTTP response."""
        return self.error is None and self.rep is not None

    @property
    def cutoff(self):
        """Whether the HTTP connector's receive direction has closed."""
        return self.client.cutoff

    @property
    def txCutoff(self):
        """Whether the HTTP connector's transmit direction has closed."""
        return self.client.txCutoff


def mailbox(hab, cid):
    for (_, erole, eid), end in hab.db.ends.getItemIter(keys=(cid, kering.Roles.mailbox)):
        if end.allowed:
            return eid

    if cid not in hab.kevers:
        return None

    kever = hab.kevers[cid]
    if not kever.wits:
        return None

    mbx = random.choice(kever.wits)
    return mbx


def messenger(hab, pre, auth=None):
    """ Create a Messenger (tcp or http) based on available endpoints

    Parameters:
        hab (Habitat): Environment to use to look up witness URLs
        pre (str): qb64 identifier prefix of recipient to create a messanger for
        auth (str): optional auth code to send with any request for messenger

    Returns:
        Optional(TcpWitnesser, HTTPMessenger): witnesser for ensuring full reciepts
    """
    urls = hab.fetchUrls(eid=pre)
    return messengerFrom(hab, pre, urls, auth)


def messengerFrom(hab, pre, urls, auth=None):
    """ Create a Witnesser (tcp or http) based on provided endpoints

    Parameters:
        hab (Habitat): Environment to use to look up witness URLs
        pre (str): qb64 identifier prefix of recipient to create a messanger for
        urls (dict): map of schemes to urls of available endpoints
        auth (str): optional auth code to send with any request for messenger

    Returns:
        Optional(TcpWitnesser, HTTPMessenger): witnesser for ensuring full reciepts
    """
    if kering.Schemes.http in urls or kering.Schemes.https in urls:
        url = urls[kering.Schemes.http] if kering.Schemes.http in urls else urls[kering.Schemes.https]
        witer = HTTPMessenger(hab=hab, wit=pre, url=url, auth=auth)
    elif kering.Schemes.tcp in urls:
        url = urls[kering.Schemes.tcp]
        witer = TCPMessenger(hab=hab, wit=pre, url=url)
    else:
        raise kering.ConfigurationError(f"unable to find a valid endpoint for witness {pre}")

    return witer


def streamMessengerFrom(hab, pre, urls, msg, headers=None):
    """Create a stream messenger (HTTP or TCP) for a single outbound message.

    Parameters:
        hab (Habitat): Environment to use to look up witness URLs
        pre (str): qb64 identifier prefix of recipient to create a messanger for
        urls (dict): map of schemes to urls of available endpoints
        msg (bytes): sole message admitted by the one-shot messenger.
        headers (dict | None): optional headers for an HTTP request.

    Returns:
        TCPStreamMessenger | HTTPStreamMessenger: one-shot doer that retains
        either successful local completion or a terminal transport error.
    """
    if kering.Schemes.http in urls or kering.Schemes.https in urls:
        url = urls[kering.Schemes.http] if kering.Schemes.http in urls else urls[kering.Schemes.https]
        witer = HTTPStreamMessenger(hab=hab, wit=pre, url=url, msg=msg, headers=headers)
    elif kering.Schemes.tcp in urls:
        url = urls[kering.Schemes.tcp]
        witer = TCPStreamMessenger(hab=hab, wit=pre, url=url, msg=msg)
    else:
        raise kering.ConfigurationError(f"unable to find a valid endpoint for witness {pre}")

    return witer


def httpClient(hab, wit):
    """ Create and return a http.client and http.ClientDoer for the witness

    Parameters:
        hab (Habitat): Environment to use to look up witness URLs
        wit (str): qb64 identifier prefix of witness for which to create a client

    Returns:
        Client: Http client for connecting to remote identifier
        ClientDoer: Doer for client

    """
    urls = hab.fetchUrls(eid=wit, scheme=kering.Schemes.http) or hab.fetchUrls(eid=wit, scheme=kering.Schemes.https)
    if not urls:
        raise kering.MissingEntryError(f"unable to query witness {wit}, no http endpoint")

    url = urls[kering.Schemes.http] if kering.Schemes.http in urls else urls[kering.Schemes.https]
    up = urlparse(url)
    client = http.clienting.Client(scheme=up.scheme, hostname=up.hostname, port=up.port, path=up.path)
    clientDoer = http.clienting.ClientDoer(client=client)

    return client, clientDoer


def schemes(db, eids):
    msgs = bytearray()
    for eid in eids:
        for scheme in kering.Schemes:
            keys = (eid, scheme)
            said = db.lans.get(keys=keys)
            if said is not None:
                serder = db.rpys.get(keys=(said.qb64,))
                cigars = db.scgs.get(keys=(said.qb64,))

                if len(cigars) == 1:
                    (verfer, cigar) = cigars[0]
                    cigar.verfer = verfer
                else:
                    cigar = None
                msgs.extend(eventing.messagize(serder=serder,
                                               cigars=[cigar],
                                               pipelined=True))
    return msgs
