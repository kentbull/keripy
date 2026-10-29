"""Authenticated local registry-salt lifecycle over existing KERI owners.

This experimental application profile uses Revery for live reply authority,
the caller's Kevery/KRAM for live intake, and archival signature verification
for immutable transcript evidence after ordinary reply pruning. It creates no
database environment, scheduler or alternative group approval protocol.

Explicit prepare/approve calls are local actions; receiving an init or bind
never grants consent. PendingDH records preserve that local initial action and
its exact private key before any outbound statement. Group consent remains an
own-member /multisig/rpy wrapper, not a second approval journal. Public proof
frames are retained only for init/bind/confirm/assign, because late provisioning
must verify original bodies and historical thresholds after Revery pruning.

Custody currently supports one current Ed25519 key per intended individual
recipient. There is no implicit key-zero selection or recipient delegation.
Every intended roster and representative is checked before establishment or
provisioning. Root possession remains independent of group signing authority.
"""

from base64 import b64decode, b64encode
from dataclasses import asdict, dataclass, field
from time import time

import lmdb

from .. import Vrsn_2_0
from ..core import Dater, Diger, Salter, SerderKERI, messagize
from ..core.parsing import MsgParseDom
from ..core.routing import fetchTsgs
from ..peer.exchanging import loadParsedNestedSubstreams, serializeParsedSubstream
from ..help import helping
from ..kering import (AuthError, ConfigurationError, MissingEntryError,
                      Ilks, KeriError, UnverifiedReplyError, ValidationError)
from . import registry_salt_replies as replies, registry_salts
from .essring import envelope
from .group_members import acceptedRoster, currentRecipientKey
from .grouping import endorseReply, replyProposal
from .habbing import GroupHab
from .registry_custody import CustodyInfo
from .registry_salt_proofs import verifyArchivedReply
from .registry_salt_state import SaltDelivery, SaltOrigin, SaltReceiptIntent
from .replying import parseReply


ROUTES = (replies.INIT_ROUTE, replies.BIND_ROUTE, replies.CONFIRM_ROUTE,
          replies.ASSIGN_ROUTE, replies.PROVISION_ROUTE, replies.RECEIPT_ROUTE)


@dataclass(frozen=True)
class SaltOutbound:
    """Exact public statement and optional member proposal for caller-owned I/O."""
    body: SerderKERI
    stream: bytes = field(repr=False)
    proposal: SerderKERI | None = None
    attachments: bytes = field(default=b'', repr=False)


class RegistrySaltService:
    """Enforce salt-domain authority while borrowing authenticated runtime owners."""

    def __init__(self, hby, rgy, wallet, custody, state, parser, rvy, *, exc=None, mux=None):
        """Borrow matching owners; construction registers no routes and opens no store.

        Parameters: hby/rgy/wallet/custody/state are existing identity, accepted
            registry, inventory, custody and feature owners. parser and rvy are
            the caller's shared live pipeline with enabled KRAM. exc/mux are
            required only for group approval and must already be composed.
        Raises: ConfigurationError for mismatched owners or absent live policy.
        Returns: an unscheduled service; the caller explicitly calls register.
        """
        if (wallet.db is not custody.db or state.db is not custody.db
                or custody.hby is not hby or custody.rgy is not rgy
                or parser.rvy is not rvy or rvy.db is not hby.db
                or parser.kvy is None or parser.kvy.kramer is None
                or not parser.kvy.kramer.enabled):
            raise ConfigurationError('registry-salt service requires shared owners and enabled live KRAM')
        self.hby, self.rgy, self.wallet = hby, rgy, wallet
        self.custody, self.state = custody, state
        self.parser, self.rvy, self.exc, self.mux = parser, rvy, exc, mux

    def register(self):
        """Register the six exact domain routes on the borrowed Revery, once.

        Returns: None. Existing conflicting route ownership is an error; this
            does not install ESSR handlers or start a worker.
        Raises: ConfigurationError if another resource already owns a route.
        """
        for route in ROUTES:
            registered, _ = self.rvy.rtr._find(route)
            if registered is not None and registered.resource is not self:
                raise ConfigurationError('registry-salt reply route is already owned')
        for route in ROUTES:
            if self.rvy.rtr._find(route)[0] is None:
                self.rvy.rtr.addRoute(route, self, suffix='RegistrySalt')

    def trustRoster(self, party, smids):
        """Persist a caller-supplied trusted local ordered map after custody preflight.

        Parameters: party is the logical AID; smids are its explicit trusted
            member AIDs (use [party] for an individual). Never pass remote claims.
        Returns: the current AcceptedRoster; no entitlement is created.
        Raises: ValidationError for unsupported recipients or invalid history.
        """
        roster = acceptedRoster(self.hby, party, smids)
        for member in roster.members:
            currentRecipientKey(self.hby, roster, member)
        return self.state.retainRoster(roster)

    def _roster(self, party):
        """Require a saved trusted current accepted map, independent of recipient capability."""
        roster = self.state.roster(party)
        if roster is None:
            raise ConfigurationError('registry-salt requires an explicit trusted current roster')
        if acceptedRoster(self.hby, party, tuple(member.aid for member in roster.members)) != roster:
            raise ValidationError('registry-salt trusted roster is stale')
        return roster

    def _preflight(self, party):
        """Preflight every intended recipient before enrolling a new root entitlement."""
        roster = self._roster(party)
        for member in roster.members:
            currentRecipientKey(self.hby, roster, member)
        return roster

    def roster(self, party):
        """Return the trusted current accepted roster for explicit caller fanout."""
        return self._roster(party)

    def _member(self, party, aid):
        """Resolve an exact current individual member and supported encryption target."""
        roster = self._roster(party)
        member = next((item for item in roster.members if item.aid == aid), None)
        if member is None:
            raise ValidationError('registry-salt individual is not a current accepted member')
        event, key = currentRecipientKey(self.hby, roster, member)
        return roster, member, event, key

    @staticmethod
    def _coordinate(event):
        """Return a public canonical establishment coordinate for a known event."""
        return dict(s=f'{event.sn:x}', d=event.said)

    def _representative(self, body):
        """Require the signed DH representative to remain a supported current member."""
        data = body.sad['a']
        _, _, event, _ = self._member(body.pre, data['rep'])
        if data['est'] != self._coordinate(event):
            raise ValidationError('registry-salt representative establishment is no longer current')

    def _proof(self, said, route):
        """Load original signed proof and reverify historical canonical authority."""
        stream = self.state.proof(said)
        if stream is None:
            raise MissingEntryError('registry-salt authenticated transcript proof is unavailable')
        parsed = parseReply(self.parser, stream, {route})
        if parsed.serder.said != said:
            raise ValidationError('registry-salt proof archive references another body')
        return verifyArchivedReply(self.hby, self.parser, stream, route, parsed.serder.pre)

    @staticmethod
    def _said(body, field):
        """Read a required canonical public digest without leaking parser KeyErrors."""
        try:
            value = body.sad['a'][field]
            if not isinstance(value, str) or Diger(qb64=value).qb64 != value:
                raise ValueError
            return value
        except (KeriError, ValueError, TypeError, KeyError):
            raise ValidationError('registry-salt reply has a missing or invalid cross-reference') from None

    def _rip(self, registry, issuer):
        """Require the exact accepted registry inception, not a retained candidate."""
        rip = self.rgy.store.seqEvent(registry, 0)
        if rip is None or rip.said != registry or rip.sad['i'] != issuer or not rip.verify():
            raise MissingEntryError('registry-salt accepted issuer registry inception is unavailable')
        return rip

    def _transcript(self, initSaid, bindSaid):
        """Resolve an authenticated exact init/bind pair and accepted registry."""
        init = self._proof(initSaid, replies.INIT_ROUTE)
        bind = self._proof(bindSaid, replies.BIND_ROUTE)
        rip = self._rip(bind.sad['a']['registry'], init.sad['a']['issuer'])
        replies.validateBind(init, bind, rip)
        return init, bind, rip

    def _confirmed(self, said):
        """Verify the original immutable transcript without requiring departed representatives."""
        confirm = self._proof(said, replies.CONFIRM_ROUTE)
        init, bind, rip = self._transcript(confirm.sad['a']['init'], confirm.sad['a']['bind'])
        replies.validateConfirm(init, bind, confirm, rip)
        return init, bind, confirm, rip

    def _local(self, aid):
        """Require an individually controlled local signing habitat."""
        hab = self.hby.habByPre(aid)
        if hab is None or isinstance(hab, GroupHab):
            raise ValidationError('registry-salt requires the intended local individual key')
        return hab

    def prepareInit(self, *, issuer, discloser, party, representative, stamp=None):
        """Explicitly begin an attempt and persist its private key before outbound approval.

        Parameters: issuer/discloser are distinct trusted parties; party is the
            initiating one; representative is a supported locally controlled
            member; stamp optionally fixes the initial body timestamp.
        Returns: unsigned exact init SerderKERI, ready for approveReply.
        Raises: ValidationError/ConfigurationError for unsupported authority or
            recipients; AuthError if private recovery cannot be protected.
        """
        if party not in (issuer, discloser) or issuer == discloser:
            raise ValidationError('registry-salt initializer must be one of two distinct parties')
        self._preflight(issuer)
        self._preflight(discloser)
        self._local(representative)
        _, _, event, _ = self._member(party, representative)
        public, private = registry_salts.generateKeypair()
        body = replies.initReply(sender=party, issuer=issuer, discloser=discloser,
            rep=representative, est=self._coordinate(event), key=public.qb64, stamp=stamp)
        self.state.retainPending(body.said, representative, body.raw, private)
        return body

    def prepareBind(self, initSaid, registry, representative, *, stamp=None):
        """Explicitly bind an authenticated init, reusing a retained private attempt.

        Parameters: initSaid names a full authenticated proof; registry is the
            accepted issuer rip SAID; representative is a local opposite-party
            member; stamp applies only to a new attempt, never a recovered one.
        Returns: exact unsigned bind SerderKERI. Raises: domain/history/auth errors.
        """
        init = self._proof(initSaid, replies.INIT_ROUTE)
        data = init.sad['a']
        party = data['discloser'] if init.pre == data['issuer'] else data['issuer']
        self._preflight(data['issuer'])
        self._preflight(data['discloser'])
        self._representative(init)
        self._local(representative)
        _, _, event, _ = self._member(party, representative)
        rip = self._rip(registry, data['issuer'])
        origin = self.state.origin(registry)
        if origin is not None:
            if origin.init != initSaid:
                raise ValidationError('registry-salt registry already has another established origin')
            body = self._proof(origin.bind, replies.BIND_ROUTE)
            if body.sad['a']['rep'] != representative:
                raise ValidationError('registry-salt existing agreement has another original representative')
            return body
        if not self.state.hasPending(initSaid, representative):
            if self._retainedBind(initSaid, representative):
                raise ConfigurationError('registry-salt bind private state is lost; recover it or start a new agreement')
            public, private = registry_salts.generateKeypair()
            body = replies.bindReply(init, rip, sender=party, rep=representative,
                est=self._coordinate(event), key=public.qb64, stamp=stamp)
            self.state.retainPending(initSaid, representative, body.raw, private)
        else:
            saved = self.state.openPending(initSaid, representative)
            body = SerderKERI(raw=saved.body)
            replies.validateBind(init, body, rip)
            self._representative(body)
        return body

    def _retainedBind(self, init, representative):
        """Detect prior local bind evidence before allowing absent-pending key creation."""
        for _, record in self.state.db.saltProofs.getTopItemIter():
            frame = b64decode(record.frame, validate=True)
            body = parseReply(self.parser, frame, ROUTES[:4]).serder
            if (body.route == replies.BIND_ROUTE and body.sad['a'].get('init') == init
                    and body.sad['a'].get('rep') == representative):
                return True
        for _, wrapper in self.hby.db.exns.getTopItemIter():
            if wrapper.route != '/multisig/rpy' or wrapper.pre not in self.hby.habs:
                continue
            for child in loadParsedNestedSubstreams(self.hby, wrapper.said):
                body = child.serder
                if (body.route == replies.BIND_ROUTE and body.sad['a'].get('init') == init
                        and body.sad['a'].get('rep') == representative
                        and any(member.qb64 == wrapper.pre
                                for member in self.hby.db.maids.get((body.said,)))):
                    return True
        return False

    def resume(self, initSaid, representative):
        """Recover the exact local init/bind without generating replacement material.

        Parameters: initSaid/representative select PendingDH. Returns: original
            SerderKERI. Raises: recovery/authentication errors; no fallback creation.
        """
        return SerderKERI(raw=self.state.openPending(initSaid, representative).body)

    def _derive(self, init, bind, party):
        """Derive only from an exact retained, authenticated local initial action."""
        own, peer = (init, bind) if init.pre == party else (bind, init)
        self._representative(own)
        self._local(own.sad['a']['rep'])
        pending = self.state.openPending(init.said, own.sad['a']['rep'])
        if pending.body != own.raw:
            raise ValidationError('registry-salt pending local approval differs from the transcript')
        return registry_salts.deriveRoot(pending.private, peer.sad['a']['key'], init.raw, bind.raw)

    def prepareConfirm(self, initSaid, bindSaid, *, stamp=None):
        """Prepare issuer confirmation from its approved representative's retained DH.

        Parameters: initSaid/bindSaid identify full authenticated exact proofs.
        Returns: unsigned issuer confirmation; the private root is never returned.
        Raises: domain/history/recovery errors. Nonrepresentatives instead approve
            the representative's exact retained /multisig/rpy proposal.
        """
        init, bind, rip = self._transcript(initSaid, bindSaid)
        origin = self.state.origin(rip.said)
        if origin is not None:
            if (origin.init, origin.bind) != (initSaid, bindSaid):
                raise ValidationError('registry-salt registry already has another established origin')
            return self._proof(origin.confirm, replies.CONFIRM_ROUTE)
        own = init if init.pre == init.sad['a']['issuer'] else bind
        pending = self.state.openPending(init.said, own.sad['a']['rep'])
        root = self._derive(init, bind, init.sad['a']['issuer'])
        if pending.confirmation is not None:
            body = SerderKERI(raw=pending.confirmation)
            replies.validateConfirm(init, bind, body, rip)
            if body.sad['a']['commitment'] != registry_salts.commitment(root, init.raw, bind.raw).qb64:
                raise ValidationError('registry-salt retained confirmation differs from the DH root')
            return body
        body = replies.confirmReply(init, bind, rip, root, stamp=stamp)
        self.state.retainConfirmationDraft(init.said, own.sad['a']['rep'], body.raw)
        return body

    def _approvalPolicy(self, body):
        """Enforce concrete domain invariants before any local logical-party signature."""
        if not isinstance(body, SerderKERI):
            raise ValidationError('registry-salt approval requires an exact reply body')
        if body.route == replies.INIT_ROUTE:
            replies.validateInit(body)
            self._preflight(body.sad['a']['issuer'])
            self._preflight(body.sad['a']['discloser'])
            self._representative(body)
        elif body.route == replies.BIND_ROUTE:
            init = self._proof(self._said(body, 'init'), replies.INIT_ROUTE)
            rip = self._rip(self._said(body, 'registry'), init.sad['a']['issuer'])
            replies.validateBind(init, body, rip)
            self._preflight(init.sad['a']['issuer'])
            self._preflight(init.sad['a']['discloser'])
            self._representative(init)
            self._representative(body)
        elif body.route == replies.CONFIRM_ROUTE:
            init, bind, rip = self._transcript(self._said(body, 'init'), self._said(body, 'bind'))
            replies.validateConfirm(init, bind, body, rip)
            self._preflight(init.sad['a']['issuer'])
            self._preflight(init.sad['a']['discloser'])
            self._representative(init)
            self._representative(bind)
            # Available local custody is a consistency check, never a co-signer
            # prerequisite. A nonrepresentative can approve public provenance.
            if self.custody.db.custody.get((rip.said,)) is not None:
                existing = self.custody._load(rip.said)
                expected = registry_salts.commitment(Salter(qb64=existing.salt), init.raw, bind.raw).qb64
                if expected != body.sad['a']['commitment']:
                    raise ValidationError('registry-salt confirmation differs from the retained root')
        elif body.route == replies.ASSIGN_ROUTE:
            _, _, confirm, _ = self._confirmed(self._said(body, 'origin'))
            replies.validateAssign(confirm, body)
            self._preflight(body.sad['a']['party'])
            existing = self.state.assignment(confirm.sad['a']['registry'], body.sad['a']['party'])
            if existing is not None and existing != body.said:
                raise ValidationError('registry-salt party already has another immutable issuer assignment')
        else:
            raise ValidationError('registry-salt logical approval route is unsupported')

    def _representativeContribution(self, child):
        """Require the named representative's group contribution before co-signing DH statements."""
        body = child.serder
        if body.route == replies.CONFIRM_ROUTE:
            init, bind, _ = self._transcript(self._said(body, 'init'), self._said(body, 'bind'))
            own = init if init.pre == body.pre else bind
        else:
            own = body
        roster, member, _, _ = self._member(body.pre, own.sad['a']['rep'])
        kever = self.hby.kevers[body.pre]
        if not any((aid.qb64, number.sn, digest.qb64) == (body.pre, roster.sn, roster.digest)
                and any(siger.index == member.index and
                        kever.verfers[member.index].verify(siger.raw, body.raw) for siger in sigers)
                for aid, number, digest, sigers in child.tsgs):
            raise ValidationError('registry-salt confirmation lacks its approved representative contribution')

    def approveReply(self, body, *, proposal=None):
        """Explicitly approve one exact local statement using existing signature owners.

        Parameters: body is an exact domain SerderKERI; proposal optionally names
            an authenticated retained member wrapper for a group co-signer.
        Returns: SaltOutbound; caller fans group proposals to members and sends
            only a fully authenticated logical reply to the other party.
        Raises: domain/history/auth errors. Incoming requests never invoke this.
        """
        self.checkLive(body)
        self._approvalPolicy(body)
        hab = self.hby.habByPre(body.pre)
        if hab is None:
            raise ValidationError('registry-salt approval requires the local logical party')
        if body.route == replies.ASSIGN_ROUTE:
            _, _, confirm, _ = self._confirmed(self._said(body, 'origin'))
            prepared = self._assignmentProposal(confirm, body.sad['a']['party'])
            if prepared is not None and prepared.raw != body.raw:
                raise ValidationError('registry-salt approval differs from the retained local assignment proposal')
        if isinstance(hab, GroupHab):
            if self.exc is None or self.mux is None:
                raise ConfigurationError('registry-salt group approval requires existing group owners')
            roster = self._roster(body.pre)
            if proposal is not None:
                child = replyProposal(self.hby, self.exc, self.mux, proposal,
                    ghab=hab, roster=roster, validate=self._approvalPolicy)
                if child.serder.raw != body.raw:
                    raise ValidationError('registry-salt approval differs from the retained child')
                if body.route in (replies.INIT_ROUTE, replies.BIND_ROUTE, replies.CONFIRM_ROUTE):
                    self._representativeContribution(child)
            else:
                child = MsgParseDom(serder=body)
                if body.route in (replies.INIT_ROUTE, replies.BIND_ROUTE):
                    if body.sad['a']['rep'] != hab.mhab.pre:
                        raise ValidationError('registry-salt originating member must be the named DH representative')
                    own = self.state.openPending(body.said if body.route == replies.INIT_ROUTE
                                                 else body.sad['a']['init'], body.sad['a']['rep'])
                    if own.body != body.raw:
                        raise ValidationError('registry-salt local proposal has no exact initial action')
                elif body.route == replies.CONFIRM_ROUTE:
                    self._requireConfirmationDraft(body)
            stream, wrapper, attachments = endorseReply(self.hby, hab, child,
                roster=roster, validate=self._approvalPolicy)
            # Existing Multiplexor records own-wrapper consent and merges remote
            # contributions. No extra approval row or autonomous parser is added.
            self.parser.parse(ims=bytearray(wrapper.raw + attachments), local=True)
            try:
                self.receive(stream, local=True)
            except UnverifiedReplyError:
                pass  # ordinary partial group reply escrow, never success
            return SaltOutbound(body, bytes(stream), wrapper, bytes(attachments))
        self._local(body.pre)
        if body.route in (replies.INIT_ROUTE, replies.BIND_ROUTE):
            pending = self.state.openPending(body.said if body.route == replies.INIT_ROUTE
                                            else body.sad['a']['init'], body.sad['a']['rep'])
            if pending.body != body.raw:
                raise ValidationError('registry-salt local reply has no exact initial action')
        elif body.route == replies.CONFIRM_ROUTE:
            self._requireConfirmationDraft(body)
        stream = bytes(hab.endorse(body, gvrsn=Vrsn_2_0))
        self.receive(stream, local=True)
        return SaltOutbound(body, stream)

    def inspectProposal(self, said):
        """Inspect a retained group proposal with concrete policy and no approval.

        Parameters: said is the authenticated /multisig/rpy wrapper SAID.
        Returns: exact reply body, safe for pre-consent display.
        Raises: authentication, accepted-roster or domain-policy errors.
        """
        if self.exc is None or self.mux is None:
            raise ConfigurationError('registry-salt proposal inspection requires existing group owners')
        wrapper = self.hby.db.exns.get((said,))
        if wrapper is None or not isinstance(wrapper.sad.get('a'), dict):
            raise ValidationError('registry-salt proposal wrapper is unavailable')
        hab = self.hby.habByPre(wrapper.sad['a'].get('gid'))
        if not isinstance(hab, GroupHab):
            raise ValidationError('registry-salt proposal requires a local group')
        child = replyProposal(self.hby, self.exc, self.mux, said, ghab=hab,
            roster=self._roster(hab.pre), validate=self._approvalPolicy)
        self.checkLive(child.serder)
        if child.serder.route in (replies.INIT_ROUTE, replies.BIND_ROUTE, replies.CONFIRM_ROUTE):
            self._representativeContribution(child)
        return child.serder

    def checkLive(self, body):
        """Refuse stale outbound statements using current configured KRAM signature windows.

        Parameters: body is the exact proposed or archived public reply.
        Returns: body unchanged. Raises: ConfigurationError with an actionable
            new-agreement instruction when its time/signing context expired.
        This performs no live intake or cache write and never refreshes a body.
        """
        if not isinstance(body, SerderKERI):
            raise ValidationError('registry-salt live check requires an exact reply body')
        kever = self.hby.kevers.get(body.pre)
        if kever is None:
            raise ConfigurationError('registry-salt live signing state is unavailable')
        kramer = self.parser.kvy.kramer
        kramer.reconcileConfig()
        window = kramer._fetchCacheType(Ilks.rpy, body.route)
        now = helping.fromIso8601(helping.nowIso8601()).timestamp() * 1000
        stamp = helping.fromIso8601(body.stamp).timestamp() * 1000
        lag = window.sl if len(kever.verfers) == 1 else window.ll
        if not now - window.d - lag <= stamp <= now + window.d:
            raise ConfigurationError('registry-salt statement is outside its live KRAM window; start a new agreement')
        streams = []
        archived = self.state.proof(body.said)
        if archived is not None:
            streams.append(archived)
        local = self.hby.habByPre(body.pre)
        for said in self.hby.db.meids.get((body.said,)):
            wrapper = self.hby.db.exns.get((said.qb64,))
            if (isinstance(local, GroupHab) and wrapper is not None
                    and wrapper.route == '/multisig/rpy' and wrapper.pre == local.mhab.pre
                    and any(member.qb64 == local.mhab.pre for member in self.hby.db.maids.get((body.said,)))):
                streams.extend(serializeParsedSubstream(child) for child in
                               loadParsedNestedSubstreams(self.hby, wrapper.said))
        for stream in streams:
            parsed = self.parser.parse(ims=bytearray(stream), processive=False)[0]
            if any((aid.qb64, number.sn, digest.qb64) !=
                   (body.pre, kever.lastEst.s, kever.lastEst.d)
                   for aid, number, digest, _ in parsed.tsgs):
                raise ConfigurationError('registry-salt statement has prior signing keys; start a new agreement')
        return body

    def _requireConfirmationDraft(self, body):
        """Require exact issuer-representative preparation for an originating confirmation."""
        init, bind, _ = self._transcript(self._said(body, 'init'), self._said(body, 'bind'))
        own = init if init.pre == body.pre else bind
        pending = self.state.openPending(init.said, own.sad['a']['rep'])
        if pending.confirmation != body.raw:
            raise ValidationError('registry-salt confirmation has no exact retained local preparation')

    def receive(self, stream, *, local=False):
        """Dispatch one exact reply through the borrowed live Kevery/KRAM pipeline.

        Parameters: stream is a complete signed reply frame; local marks an
            explicit local outbound action. Returns: None, never a transport or
            custody success assertion. Inspect durable state for acceptance.
        Raises: framing, domain or authentication errors; KRAM may drop/escrow.
        """
        parsed = parseReply(self.parser, stream, ROUTES)
        parsed.local = local
        self.parser.msgProcess(exts=asdict(parsed), kvy=self.parser.kvy,
            rvy=self.rvy, tvy=None, exc=None, vry=None)

    def _authenticate(self, body, diger, route, cigars, tsgs):
        """Apply normal reply signatures, then require current live establishment authority."""
        if not self.rvy.acceptReply(serder=body, saider=diger, route=route,
                                   aid=body.pre, cigars=cigars, tsgs=tsgs):
            raise UnverifiedReplyError('registry-salt reply has not satisfied its logical signing threshold')
        try:
            kever = self.hby.kevers.get(body.pre)
            if kever is None:
                raise MissingEntryError('registry-salt live signing state is unavailable')
            if kever.prefixer.transferable:
                if cigars or not tsgs or any((aid.qb64, number.sn, digest.qb64) !=
                        (body.pre, kever.lastEst.s, kever.lastEst.d) for aid, number, digest, _ in tsgs):
                    raise ValidationError('registry-salt live signatures require current explicit establishment')
            elif tsgs or not cigars or any(cigar.verfer.qb64 != body.pre for cigar in cigars):
                raise ValidationError('registry-salt nontransferable reply has another signer')
            # Revery may have reached threshold using separately delivered partial
            # frames. Archive its accepted aggregate, not just the last packet.
            groups = [group for group in fetchTsgs(self.hby.db.tsgs, diger)
                      if (group[0].qb64, group[1].sn, group[2].qb64) ==
                         (body.pre, kever.lastEst.s, kever.lastEst.d)]
            couples = []
            for verfer, cigar in self.hby.db.scgs.get((body.said,)):
                if verfer.qb64 == body.pre:
                    cigar.verfer = verfer
                    couples.append(cigar)
            frame = bytes(messagize(body, cigars=couples or None, tsgs=groups or None, gvrsn=Vrsn_2_0))
            verifyArchivedReply(self.hby, self.parser, frame, route, body.pre)
            return frame
        except UnverifiedReplyError:
            raise
        except ValidationError:
            self._discardRejected(body, diger, route)
            raise

    def _discardRejected(self, body, diger, route):
        """Remove terminal reply artifacts through their owner, preserving accepted proofs.

        body/diger/route identify the exact rejected live statement. A replay
        with outdated attachment authority must not erase previously accepted
        transcript history. Pending dependencies remain in ordinary Revery
        escrow; KRAM keeps its separately bounded replay-protection record.
        """
        self.hby.db.rpes.rem(keys=route, val=diger)
        if self.state.proof(body.said) is None:
            self.rvy.removeReply(diger)

    @staticmethod
    def _origin(init, bind, confirm):
        """Build immutable original metadata after full transcript authentication."""
        data = init.sad['a']
        return SaltOrigin(bind.sad['a']['registry'], data['issuer'], data['discloser'],
            init.said, bind.said, confirm.said, confirm.sad['a']['commitment'])

    def _jobs(self, origin, party, assignment):
        """Create fresh operations for every accepted recipient, including nonsigners."""
        roster = self._roster(party)
        return tuple(SaltDelivery(origin.registry, party, member.aid, roster.digest, assignment)
                     for member in roster.members if self.hby.habByPre(member.aid) is None)

    def _establish(self, init, bind, confirm):
        """Commit only a locally initiated representative's matching confirmed root."""
        origin = self._origin(init, bind, confirm)
        info = CustodyInfo(origin.registry, origin.issuer, origin.discloser)
        jobs = self._jobs(origin, origin.issuer, origin.confirm) + self._jobs(origin, origin.discloser, origin.confirm)
        for party in (origin.issuer, origin.discloser):
            own = init if init.pre == party else bind
            if self.hby.habByPre(own.sad['a']['rep']) is None:
                continue
            if not self.state.hasPending(init.said, own.sad['a']['rep']):
                continue  # public confirmation is not implicit local initiation
            root = self._derive(init, bind, party)
            if registry_salts.commitment(root, init.raw, bind.raw).qb64 != origin.commitment:
                raise ValidationError('registry-salt root does not match issuer confirmation')
            self.state.retainEstablished(info, root, origin, jobs,
                                         (init.said, own.sad['a']['rep']))

    @property
    def maxAge(self):
        """Return the smaller current single-key provision/receipt KRAM lag in seconds."""
        kramer = self.parser.kvy.kramer
        kramer.reconcileConfig()
        return min(kramer._fetchCacheType(Ilks.rpy, route).sl
                   for route in (replies.PROVISION_ROUTE, replies.RECEIPT_ROUTE)) / 1000.0

    def prepareAssign(self, origin, party, *, stamp=None):
        """Explicitly prepare issuer entitlement for a later party under the same root.

        Parameters: origin is the original confirmation SAID; party is the new
            logical AID with a trusted supported roster; stamp is optional.
        Returns: unsigned issuer assignment, or the exact already accepted grant.
        Raises: domain/history errors; never starts another DH or changes metadata.
        """
        init, bind, confirm, _ = self._confirmed(origin)
        self._roster(confirm.pre)
        self._preflight(party)
        if self.hby.habByPre(confirm.pre) is None:
            raise ValidationError('registry-salt assignment requires the local issuer')
        if party in confirm.sad['a']['entitled']:
            raise ValidationError('registry-salt initial party already has its original entitlement')
        existing = self.state.assignment(bind.sad['a']['registry'], party)
        if existing is not None:
            return self._proof(existing, replies.ASSIGN_ROUTE)
        prepared = self._assignmentProposal(confirm, party)
        if prepared is not None:
            return prepared
        return replies.assignReply(confirm, party=party, stamp=stamp)

    def _assignmentProposal(self, confirm, party):
        """Recover an exact locally approved grant draft from existing group coordination."""
        hab = self.hby.habByPre(confirm.pre)
        if not isinstance(hab, GroupHab):
            return None
        candidates = {}
        for _, wrapper in self.hby.db.exns.getTopItemIter():
            data = wrapper.sad.get('a')
            if (wrapper.route != '/multisig/rpy' or wrapper.pre != hab.mhab.pre
                    or not isinstance(data, dict) or data.get('gid') != hab.pre
                    or not any(member.qb64 == hab.mhab.pre
                               for member in self.hby.db.maids.get((data.get('rpy', ''),)))):
                continue
            children = loadParsedNestedSubstreams(self.hby, wrapper.said)
            if len(children) != 1:
                continue
            body = children[0].serder
            if (body.route == replies.ASSIGN_ROUTE and body.sad['a'].get('origin') == confirm.said
                    and body.sad['a'].get('party') == party):
                candidates[body.said] = self.inspectProposal(wrapper.said)
        if len(candidates) > 1:
            raise ValidationError('registry-salt has conflicting locally approved assignment proposals')
        return next(iter(candidates.values()), None)

    def importProof(self, stream):
        """Explicitly verify and archive public historical evidence without live dispatch.

        Parameters: stream is one exact signed init/bind/confirm/assign frame.
        Import dependencies in that order, with accepted historical KEL/rip
        evidence already present. Returns: verified exact body. This never
        approves, derives a root, dispatches Revery or updates KRAM/BADA state.
        Raises: historical signature, semantic or missing-evidence errors.
        """
        parsed = parseReply(self.parser, stream, ROUTES[:4])
        body = verifyArchivedReply(self.hby, self.parser, stream, parsed.serder.route, parsed.serder.pre)
        if body.route == replies.INIT_ROUTE:
            replies.validateInit(body)
        elif body.route == replies.BIND_ROUTE:
            init = self._proof(self._said(body, 'init'), replies.INIT_ROUTE)
            replies.validateBind(init, body, self._rip(self._said(body, 'registry'), init.sad['a']['issuer']))
        elif body.route == replies.CONFIRM_ROUTE:
            init, bind, rip = self._transcript(self._said(body, 'init'), self._said(body, 'bind'))
            replies.validateConfirm(init, bind, body, rip)
        else:
            _, _, confirm, _ = self._confirmed(self._said(body, 'origin'))
            replies.validateAssign(confirm, body)
        self.state.retainProof(body, bytes(stream))
        if body.route == replies.ASSIGN_ROUTE:
            init, bind, confirm, _ = self._confirmed(self._said(body, 'origin'))
            self.state.retainAssignment(self._origin(init, bind, confirm), body, bytes(stream))
        return body

    def process(self):
        """Retry normal previously authenticated reply dependency escrows, without new DH."""
        self.rvy.processEscrowReply()

    def _entitled(self, confirm, party):
        """Resolve initial entitlement or one exact retained issuer assignment proof."""
        if party in confirm.sad['a']['entitled']:
            return None
        said = self.state.assignment(confirm.sad['a']['registry'], party)
        if said is None:
            raise ValidationError('registry-salt logical party has no issuer entitlement')
        assignment = self._proof(said, replies.ASSIGN_ROUTE)
        replies.validateAssign(confirm, assignment)
        if assignment.sad['a']['party'] != party:
            raise ValidationError('registry-salt issuer assignment names another party')
        return assignment

    def _acceptAssignment(self, body):
        """Retain authenticated same-origin entitlement; queue only with existing custody."""
        init, bind, confirm, _ = self._confirmed(self._said(body, 'origin'))
        replies.validateAssign(confirm, body)
        origin = self._origin(init, bind, confirm)
        jobs = ()
        if self.custody.db.custody.get((origin.registry,)) is not None:
            jobs = self._jobs(origin, body.sad['a']['party'], body.said)
        self.state.retainAssignment(origin, body, self.state.proof(body.said), jobs)

    def reconcile(self, registry, party):
        """Queue current accepted remote members of an already entitled same-root party.

        Parameters: registry and party select existing custody and explicit
            entitlement. Returns: durable jobs, preserving prior progress.
        Raises: missing custody/proof/roster errors; this grants no entitlement.
        """
        origin = self.state.origin(registry)
        if origin is None:
            raise ConfigurationError('registry-salt reconciliation requires an established origin')
        _, _, confirm, _ = self._confirmed(origin.confirm)
        grant = self._entitled(confirm, party)
        return self.state.queueDeliveries(registry, self._jobs(origin, party, grant.said if grant else origin.confirm))

    def reconcileKnown(self, party):
        """Refresh trusted local membership and queue only this party's known entitlements.

        Parameters: party selects one logical role, never every local alias.
        Returns: current durable remote delivery jobs across its existing roots.
        Local GroupHab maps are adopted only when acceptedRoster verifies them;
        proposed maps preserve an existing current snapshot. Remote updated maps
        always require explicit trustRoster input. No membership protocol starts.
        """
        local = self.hby.habByPre(party)
        if isinstance(local, GroupHab):
            try:
                candidate = acceptedRoster(self.hby, party, local.smids)
            except ValidationError:
                if self.state.roster(party) is None:
                    raise
            else:
                if self.state.roster(party) != candidate:
                    self.state.retainRoster(candidate)
        elif local is not None:
            candidate = acceptedRoster(self.hby, party, [party])
            if self.state.roster(party) != candidate:
                self.state.retainRoster(candidate)
        jobs = []
        for origin in self.state.origins():
            if self.state.assignment(origin.registry, party) is not None:
                jobs.extend(self.reconcile(origin.registry, party))
        return tuple(jobs)

    def _bundle(self, provision):
        """Verify every archival threshold and exact relationship without live replay."""
        streams = replies.decodeProofs(provision)
        parsed = parseReply(self.parser, streams['init'], {replies.INIT_ROUTE}).serder
        init = verifyArchivedReply(self.hby, self.parser, streams['init'], replies.INIT_ROUTE, parsed.pre)
        replies.validateInit(init)
        data = init.sad['a']
        other = data['discloser'] if init.pre == data['issuer'] else data['issuer']
        bind = verifyArchivedReply(self.hby, self.parser, streams['bind'], replies.BIND_ROUTE, other)
        confirm = verifyArchivedReply(self.hby, self.parser, streams['confirm'], replies.CONFIRM_ROUTE, data['issuer'])
        assignments = tuple(verifyArchivedReply(self.hby, self.parser, stream,
            replies.ASSIGN_ROUTE, data['issuer']) for stream in streams['assignments'])
        rip = self._rip(bind.sad['a']['registry'], data['issuer'])
        replies.validateProvision(init, bind, confirm, provision, rip,
                                  assignments=assignments, parser=self.parser)
        return streams, init, bind, confirm, assignments

    def _provisionMembers(self, provision, *, current=True):
        """Require current source and recipient rosters, admission, key and local target."""
        data = provision.sad['a']
        self._member(data['source'], provision.pre)
        roster, _, event, _ = self._member(data['party'], data['target'])
        if current:
            if data['admission'] != dict(s=f'{roster.sn:x}', d=roster.digest):
                raise ValidationError('registry-salt provision names a stale or pending admission')
            if data['recipientEst'] != self._coordinate(event):
                raise ValidationError('registry-salt provision names a stale or foreign recipient key')
        else:
            # Receipts may acknowledge a previously committed envelope after an
            # independent member/group rotation. They release no additional root.
            for aid, coordinate in ((data['party'], data['admission']),
                                    (data['target'], data['recipientEst'])):
                sn = int(coordinate['s'], 16)
                saved = self.hby.db.evts.get((aid, coordinate['d']))
                if (self.hby.db.kels.getLast(aid, on=sn) != coordinate['d'] or saved is None
                        or not saved.estive or (saved.pre, saved.sn, saved.said) !=
                           (aid, sn, coordinate['d'])):
                    raise ValidationError('registry-salt receipt provision history is not canonical')
        return event

    def _acceptProvision(self, provision):
        """Verify fresh member authority and archival origin before atomic private retention."""
        streams, init, bind, confirm, assignments = self._bundle(provision)
        event = self._provisionMembers(provision)
        data = provision.sad['a']
        local = self._local(data['target'])
        if local.kever.lastEst.d != event.said:
            raise ValidationError('registry-salt ultimate local recipient differs from the provision')
        self.custody._manager()  # unavailable Keeper is a retryable dependency
        try:
            root = self.custody.openRoot(data['cipher'], event.verfers[0])
        except AuthError:
            raise ValidationError('registry-salt cipher cannot be opened by its bound local recipient') from None
        if registry_salts.commitment(root, init.raw, bind.raw).qb64 != confirm.sad['a']['commitment']:
            raise ValidationError('registry-salt provision root differs from the confirmed commitment')
        origin = self._origin(init, bind, confirm)
        # Public evidence can be archived independently. Private custody, new
        # entitlement indexes, jobs and receipt intent share one transaction.
        for name, body in (('init', init), ('bind', bind), ('confirm', confirm)):
            self.state.retainProof(body, streams[name])
        grants = tuple(zip(assignments, streams['assignments']))
        assignment = next((body.said for body in assignments if body.sad['a']['party'] == data['party']), origin.confirm)
        intent = SaltReceiptIntent(provision.said, origin.registry, data['party'], data['target'],
            data['admission']['d'], provision.pre, b64encode(provision.raw).decode('ascii'))
        self.state.retainEstablished(CustodyInfo(origin.registry, origin.issuer, origin.discloser),
            root, origin, self._jobs(origin, data['party'], assignment),
            receiptIntent=intent, assignments=grants)

    def _source(self, party):
        """Select a currently accepted locally controlled sending member, without a lease."""
        roster = self._roster(party)
        for member in roster.members:
            hab = self.hby.habByPre(member.aid)
            if hab is not None and not isinstance(hab, GroupHab):
                return hab
        raise ConfigurationError('registry-salt has no local current source member')

    def _outgoing(self, job, source, body=None):
        """Revalidate exact operation, both entitlements, local custody and current keys."""
        origin = self.state.origin(job.registry)
        if origin is None:
            raise ConfigurationError('registry-salt delivery requires retained origin')
        secret = self.custody._load(job.registry)
        init, bind, confirm, _ = self._confirmed(origin.confirm)
        if registry_salts.commitment(Salter(qb64=secret.salt), init.raw, bind.raw).qb64 != origin.commitment:
            raise ValidationError('registry-salt retained root differs from its immutable origin')
        grants = []
        for party in (source, job.party):
            grant = self._entitled(confirm, party)
            if grant is not None and grant.said not in [item.said for item in grants]:
                grants.append(grant)
        expected = next((item.said for item in grants if item.sad['a']['party'] == job.party), origin.confirm)
        if job.assignment != expected:
            raise ValidationError('registry-salt delivery references another assignment')
        sender = self._source(source) if body is None else self._local(body.pre)
        self._member(source, sender.pre)
        roster, _, target, key = self._member(job.party, job.member)
        if job.admission != roster.digest:
            raise ValidationError('registry-salt delivery admission is no longer current')
        if body is not None:
            data = body.sad['a']
            if (data['source'], data['party'], data['target'], data['recipientEst']) != (
                    source, job.party, job.member, self._coordinate(target)):
                raise ValidationError('registry-salt retained delivery attempt has stale bindings')
            replies.validateProvision(init, bind, confirm, body, self._rip(job.registry, origin.issuer),
                                      assignments=tuple(grants), parser=self.parser)
        return origin, confirm, grants, sender, roster, target, key

    def prepareProvision(self, job, source, *, stamp=None):
        """Prepare or reuse an exact unsent member provision and ultimate ESSR envelope.

        Parameters: job is a retained SaltDelivery; source is an explicitly
            entitled logical sending party; stamp optionally fixes a new reply.
        Returns: (provision body, signed inner bytes, ultimate ESSR bytes).
            The worker must durably record this attempt before transport starts.
        Raises: domain/custody/history errors; this method sends nothing.
        """
        if self.state.delivery(*job.key) != job or job.state != 'pending':
            raise ValidationError('registry-salt provision requires the current pending job')
        previous = self.state.currentAttempt(job.key)
        body = self._unsent(previous, replies.PROVISION_ROUTE) if job.retryAt == 0 else None
        if body is not None:
            try:
                self._outgoing(job, source, body)
            except ValidationError:
                pass  # rotated bindings require a fresh envelope for the same operation
            else:
                return body, previous.signedBytes, previous.essrBytes
        origin, confirm, grants, sender, roster, target, key = self._outgoing(job, source)
        proofs = replies.encodeProofs(self.state.proof(origin.init), self.state.proof(origin.bind),
            self.state.proof(origin.confirm), tuple(self.state.proof(grant.said) for grant in grants))
        body = replies.provisionReply(confirm, sender=sender.pre, source=source,
            party=job.party, target=job.member, admission=dict(s=f'{roster.sn:x}', d=roster.digest),
            recipientEst=self._coordinate(target), cipher=self.custody.sealRoot(job.registry, key).qb64,
            proofs=proofs, stamp=stamp)
        stream = bytes(sender.endorse(body, gvrsn=Vrsn_2_0))
        sealed = bytes(envelope(sender, stream, job.member, target.verfers[0],
                                 version=Vrsn_2_0, establishment=(target.sn, target.said)))
        return body, stream, sealed

    def _unsent(self, attempt, route):
        """Reuse only an unexpired exact local frame whose signing key is still current."""
        if attempt is None or time() >= min(attempt.expiresAt, attempt.createdAt + self.maxAge):
            return None
        parsed = parseReply(self.parser, attempt.signedBytes, {route})
        kever = self.hby.kevers.get(parsed.serder.pre)
        if kever is None:
            return None
        if kever.prefixer.transferable and any((aid.qb64, number.sn, digest.qb64) !=
                (parsed.serder.pre, kever.lastEst.s, kever.lastEst.d)
                for aid, number, digest, _ in parsed.tsgs):
            return None
        return verifyArchivedReply(self.hby, self.parser, attempt.signedBytes, route, parsed.serder.pre)

    def prepareReceipt(self, provisionSaid, *, stamp=None):
        """Sign retention acknowledgement only from a committed durable receipt intent.

        Parameters: provisionSaid names committed custody/intent; stamp is optional.
        Returns: (receipt body, signed inner bytes, ultimate ESSR bytes), for the
            worker to durably record before transport. Raises: domain/auth errors.
        No root transaction or invented successful receipt occurs here.
        """
        intent = self.state.receipt(provisionSaid)
        if intent is None:
            raise ConfigurationError('registry-salt retention receipt has no committed intent')
        provision = SerderKERI(raw=intent.bodyBytes)
        _, init, bind, confirm, _ = self._bundle(provision)
        self._provisionMembers(provision, current=False)
        secret = self.custody._load(intent.registry)
        if registry_salts.commitment(Salter(qb64=secret.salt), init.raw, bind.raw).qb64 != confirm.sad['a']['commitment']:
            raise ValidationError('registry-salt receipt requires the exact durably retained root')
        sender = self._local(intent.member)
        _, _, target, _ = self._member(provision.sad['a']['source'], intent.source)
        previous = self.state.attempt(intent.reply) if intent.reply else None
        body = self._unsent(previous, replies.RECEIPT_ROUTE) if intent.retryAt == 0 else None
        if body is not None:
            replies.validateReceipt(provision, body, confirm)
            if previous.recipientEst == self._coordinate(target):
                return body, previous.signedBytes, previous.essrBytes
        body = replies.receiptReply(provision, confirm, stamp=stamp)
        stream = bytes(sender.endorse(body, gvrsn=Vrsn_2_0))
        sealed = bytes(envelope(sender, stream, intent.source, target.verfers[0],
                                 version=Vrsn_2_0, establishment=(target.sn, target.said)))
        return body, stream, sealed

    def _acceptReceipt(self, receipt):
        """Complete only the exact retained provision operation after live member authentication."""
        provisionSaid = self._said(receipt, 'provision')
        attempt = self.state.attempt(provisionSaid)
        if attempt is None or attempt.kind != 'provision':
            raise MissingEntryError('registry-salt receipt references an unknown provision attempt')
        provision = parseReply(self.parser, attempt.signedBytes, {replies.PROVISION_ROUTE}).serder
        _, _, _, confirm, _ = self._bundle(provision)
        self._provisionMembers(provision, current=False)
        replies.validateReceipt(provision, receipt, confirm)
        self.state.confirmDelivery(attempt.jobKey, provisionSaid, receipt.said)

    def processReplyRegistrySalt(self, *, serder, diger, route, cigars=None, tsgs=None, **kwa):
        """Authenticate and handle a live domain reply; never approve an incoming request.

        Parameters: supplied by borrowed Revery after ordinary live dispatch.
        Returns: None. Domain side effects occur only after normal signatures.
        Raises: semantic, history, supported-profile or transaction errors.
        """
        if route not in ROUTES or serder.route != route:
            raise ValidationError('registry-salt live route is unsupported')
        frame = self._authenticate(serder, diger, route, cigars or [], tsgs or [])
        # KRAM has already admitted this exact signed frame. Preserve ordinary
        # authenticated reply escrow before a missing dependency or wallet error
        # can strand it behind KRAM's equal-message replay gate after restart.
        for prefixer, number, digest, sigers in tsgs or []:
            self.rvy.escrowReply(serder=serder, saider=diger, dater=Dater(dts=serder.stamp),
                route=route, prefixer=prefixer, snumber=number, sdiger=digest, sigers=sigers)
        if cigars:
            self.rvy.escrowReply(serder=serder, saider=diger, dater=Dater(dts=serder.stamp),
                                 route=route, cigars=cigars)
        try:
            if route in (replies.INIT_ROUTE, replies.BIND_ROUTE, replies.CONFIRM_ROUTE, replies.ASSIGN_ROUTE):
                self._approvalPolicy(serder)
                self.state.retainProof(serder, frame)
                if route == replies.CONFIRM_ROUTE:
                    init, bind, _ = self._transcript(self._said(serder, 'init'), self._said(serder, 'bind'))
                    self._establish(init, bind, serder)
                elif route == replies.ASSIGN_ROUTE:
                    self._acceptAssignment(serder)
            elif route == replies.PROVISION_ROUTE:
                self._acceptProvision(serder)
            else:
                self._acceptReceipt(serder)
        except (MissingEntryError, ConfigurationError, AuthError):
            raise UnverifiedReplyError('registry-salt authenticated reply is waiting for local evidence or custody') from None
        except ValidationError:
            self._discardRejected(serder, diger, route)
            raise
        except (OSError, RuntimeError, lmdb.Error):
            raise UnverifiedReplyError('registry-salt authenticated retention is pending retry') from None
        else:
            self.hby.db.rpes.rem(keys=route, val=diger)
