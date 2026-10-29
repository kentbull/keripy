"""Explicit ACDC v2 adapters for the existing credential command hierarchy."""
from contextlib import ExitStack, contextmanager
from dataclasses import asdict
import json
import math
from pathlib import Path
import time

from hio.base import doing

from .existing import setupHby
from ...acdc import messaging, scheming
from ...acdc.regeventing import issuerRegistry, _blindCandidates, vet
from ...acdc.registraring import Regery, Registrar
from ...app import GroupHab, HaberyDoer, Keeper, Notifier, Organizer, Receiptor
from ...app.credential_disclosing import boundEvent as resolveBoundEvent
from ...acdc.ipexing import AcdcV2IpexVerification
from ...vdr.eventing import Reger
from ...db import openLMDB
from ...app.registry_custody import RegistryCustody
from ...app.acdc_v2_grouping import AcdcV2GroupCoordinator
from ...core import (Blinder, Codens, Counter, Number, Prefixer, SealEvent,
                     SealSource, SerderACDC, Parser, Salter, messagize)
from ...kering import AuthError, ConfigurationError, Vrsn_2_0
from ...peer import Exchanger


from .witness_authing import readWitnessAuth


def options(parser, *, author=False):
    """Add explicit v2 selection and optional authoring controls to parser.

    Mutate the argument parser and return None. author adds anchor timeout and
    explicit witness authorization and exact group/bound-evidence options.
    V1 remains the command default. This flag never toggles core authentication."""
    parser.add_argument('--acdc-v2', dest='acdc_v2', action='store_true',
                        help='use ACDC v2 registries and IPEX')
    if author:
        parser.add_argument("--witness-auth-file", help="JSON witness AID to short-lived authorization header map")
        parser.add_argument('--timeout', type=float, default=30.0,
                            help='seconds to wait for authenticated anchor acceptance')
        parser.add_argument('--bound-event', help='exact accepted issuee KEL event for a bound state update')
        parser.add_argument('--proposal', help='approve this exact signed ACDC v2 group registry proposal')
        parser.add_argument('--proposal-output', help='write a member proposal for file handoff instead of network fanout')


def load(value):
    """Decode an inline JSON value or an explicit @file; preserve None.

    value is a CLI string or None. Return the decoded JSON object/value without
    coercing its shape; each operation validates its own contract. File I/O and
    JSON decoding failures propagate before the caller authors protocol data."""
    if value is None:
        return None
    return json.loads(Path(value[1:]).read_text() if value.startswith('@') else value)


def loadOpening(path):
    """Read one event-specific CESR Blinder from path, without accessing custody.

    Return the parsed candidate, not an authenticated opening. Callers must verify
    it against their exact event and credential. Reuses the existing IPEX CLI
    file contract; malformed or multiple openings raise ConfigurationError.
    """
    candidates = _blindCandidates(Path(path).read_bytes().strip())
    if len(candidates) != 1:
        raise ConfigurationError('opening file must contain exactly one CESR Blinder')
    return candidates[0]


def issuanceOrigin(hby, rgy, acdc, record, *, opening=None, custody=None):
    """Compose exact historical issuance evidence after common core verification.

    hby and rgy supply accepted TEL/KEL history and explicitly selected
    custody; acdc and record identify the original issued credential/event.
    opening is a possessed event-specific Blinder and takes precedence over
    derivation. Return credential bytes with verified proof/source attachments.
    Missing evidence raises ConfigurationError; core authentication failures
    propagate before the caller creates any output file.

    Unlike registryProof's current-head traversal, this export fixes its head at
    record.update. Later revocation or issuee rotation cannot substitute a newer
    event. This local CLI composition reuses regeventing.vet, not a new verifier.
    """
    event = rgy.store.event(record.update)
    if event is None or event.ilk not in ('upd', 'bup'):
        raise ConfigurationError('retained issuance event is unavailable')
    sn = Number(numh=event.sad['n']).num
    accepted = rgy.store.seqEvent(record.registry, sn)
    if accepted is None or accepted.said != record.update:
        raise ConfigurationError('retained issuance event is not accepted')
    if event.ilk == 'bup' and opening is None:
        opening = rgy.store.verifiedOpening(event)
        if opening is None:
            if custody is None:
                raise ConfigurationError('issuance opening unavailable; supply --opening or use --derive with provisioned custody')
            bound = (dict(bound=True, bsn=record.bound['bn'], bd=record.bound['bd'])
                     if record.bound else {})
            opening = custody.derive(record.registry, sn, acdc.said, 'issued', **bound)
    if event.ilk == 'upd' and opening is not None:
        raise ConfigurationError('public issuance does not use an --opening')
    updates = [rgy.store.seqEvent(record.registry, ordinal) for ordinal in range(1, sn + 1)]
    verified = vet(rgy.store.seqEvent(record.registry, 0), updates,
                   db=hby.db, acdc=acdc, blinder=opening)
    if verified.state != 'issued':
        raise ConfigurationError('retained event does not establish issuance')
    bonds = [opening.data] if opening is not None else []
    if issuerRegistry(acdc) is None:
        bonds.append(SealEvent(i=record.registry, s=event.sad['n'], d=event.said))
    return (messagize(acdc, bonds=bonds, gvrsn=Vrsn_2_0) if bonds else
            acdc.raw + Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b)


@contextmanager
def openedRegistry(args):
    """Yield identity and registry owners without opening credential inventory.

    ``args`` supplies existing identity name/base/passcode.
    Encrypted identities still authenticate through setupHby. A passcode
    supplied for an unencrypted identity is ignored, preventing implicit AEID
    migration. All opened stores close when this context exits.
    """
    keeper = Keeper(name=args.name, base=args.base, reopen=True)
    try:
        aeid = keeper.gbls.get('aeid')
        if aeid is None:
            raise ConfigurationError('ACDC v2 operation requires an existing Keeper')
    finally:
        keeper.close()
    hby = setupHby(name=args.name, base=args.base,
                   bran=args.bran if aeid else None, version=Vrsn_2_0)
    rgy = None
    try:
        rgy = Regery(hby=hby, name=args.name, base=args.base)
        yield hby, rgy
    finally:
        if rgy is not None:
            rgy.close()
        hby.close()


@contextmanager
def openedCredentials(args, *, derive=False):
    """Yield identity, registry, credential store and optional derivation provider.

    ``args`` selects the existing identity. ``derive`` explicitly composes Keeper
    custody; it never changes encryption policy. All stores close on context exit.
    Use openedRegistry alone for operations that do not read issued credentials.
    """
    with (openedRegistry(args) as (hby, rgy),
          openLMDB(cls=Reger, name=hby.name, base=hby.base, temp=hby.db.temp,
                   headDirPath=hby.db.headDirPath) as reger):
        yield hby, rgy, reger, RegistryCustody(hby, rgy) if derive else None


def registry(rgy, name, hab=None):
    """Resolve one named ACDC v2 registry and optionally require its controller.

    rgy owns the registry inventory; name selects its local alias. If hab is
    provided, its AID must control that registry. Return the registry object or
    raise ConfigurationError for an unknown name or a different controller."""
    reg = rgy.registryByName(name)
    if reg is None:
        raise ConfigurationError(f'unknown ACDC v2 registry {name}')
    if hab is not None and reg.hab.pre != hab.pre:
        raise ConfigurationError('registry is controlled by a different identifier')
    return reg


def standing(hby, rgy, reger, reg, acdc, *, custody=None, derive=False):
    """Return known current state, or unknown if the accepted head cannot be opened.

    reger supplies issued evidence and custody is optional; reg supplies
    accepted registry history; acdc is the exact credential being queried. A
    retained public opening needs no secret. derive permits event-specific
    derivation only when custody is composed; ordinary enumeration/historical
    retries do not load it.
    Return issued/revoked only when the current head binds this credential; a
    missing/nonmatching head or unavailable capability returns unknown. Core bound
    or derivation failures propagate rather than becoming a freshness claim."""
    head = reg.store.headEvent(reg.regk)
    if head is not None and head.ilk == 'upd':
        raise ConfigurationError('historical upd heads are unsupported for current-standing claims')
    if head is None or head.ilk != 'bup':
        return 'unknown'
    sn = Number(numh=head.sad['n']).num
    retained = Registrar(rgy).issuedRecord(reger, acdc.said)
    opening = rgy.store.verifiedOpening(head)
    if opening is None and derive and custody is not None:
        bound = (dict(bound=True, bsn=retained.bound['bn'], bd=retained.bound['bd'])
                 if retained and retained.update == head.said and retained.bound else {})
        for state in ('issued', 'revoked'):
            candidate = custody.derive(reg.regk, sn, acdc.said, state, **bound)
            if candidate.said == head.sad['b']:
                opening = candidate
                break
    if opening is None:
        return 'unknown'
    updates = [reg.store.seqEvent(reg.regk, ordinal) for ordinal in range(1, sn + 1)]
    return vet(reg.store.seqEvent(reg.regk, 0), updates, db=hby.db,
               acdc=acdc, blinder=opening).state or 'unknown'


class AcdcV2Author(doing.DoDoer):
    """Author exact ACDC v2 registry events through individual or group controllers.

    Staging, KEL anchoring, authenticated receipt acceptance, and issued inventory
    recording are separate steps. Public ``bup`` openings need no custody;
    derived authoring explicitly composes that capability. Exact retries
    preserve history."""
    def __init__(self, args, operation):
        """Schedule one ACDC v2 inception, credential creation, or revocation.

        args is the parsed command namespace and operation selects the action.
        Initialize pending group/anchor/opening references and one cooperative run
        child. This constructor opens no identity, registry, or custody store."""
        self.args, self.operation = args, operation
        self.auths = {}
        self.group = self.proposedEvent = self.proposedAnchor = self.proposedBlinder = None
        self.proposedSalts = None
        self.blinder = None
        self.publishOpening = False
        super().__init__(doers=[doing.doify(self.run)])

    def anchor(self, hby, reg, event, receiptor):
        """Yield until the exact event is accepted through authenticated anchoring.

        hby owns KEL evidence, reg owns the target registry, event is the already
        staged ACDC v2 event, and receiptor is the scheduled individual receipt worker.
        Group work instead approves the exact proposed anchor and waits for member
        and witness evidence. Reuse an existing sealing event on retry; do not author
        a second anchor merely to poll. Return None only after accepted event equality;
        raise TimeoutError when the configured wall-clock deadline expires. Proposal
        file creation and core authentication failures propagate to run's cleanup."""
        if self.group is not None:
            accepted = reg.store.seqEvent(reg.regk, Number(numh=event.sad['n']).num)
            if accepted is not None and accepted.said == event.said:
                return
            wrapper, attachments = self.group.approveRegistry(
                event, self.proposedAnchor, opening=self.blinder if self.publishOpening else None,
                salts=self.proposedSalts)
            if self.args.proposal_output:
                # The file contains public KELs and a member-signed proposal,
                # never the registry custody salt or encrypted custody record.
                stream = bytearray(self.group.ghab.mhab.replay(gvrsn=Vrsn_2_0))
                stream.extend(self.group.ghab.replay(gvrsn=Vrsn_2_0))
                stream.extend(wrapper.raw + attachments)
                with Path(self.args.proposal_output).open('xb') as output:
                    output.write(stream)
            else:
                self.group.send(wrapper, attachments)
            deadline = time.monotonic() + self.args.timeout
            while True:
                self.group.process()
                reg.processEscrows()
                accepted = reg.store.seqEvent(reg.regk, Number(numh=event.sad['n']).num)
                if accepted is not None and accepted.said == event.said:
                    return
                if time.monotonic() >= deadline:
                    raise TimeoutError(f'ACDC v2 group event {event.said} is pending member approval or witness receipts')
                yield self.tock

        seal = dict(s=event.sad['n'], d=event.said)
        anchor = None
        # Reuse an already signed, possibly still unreceipted sealing event on
        # command retry. Never create a second anchor just to poll acceptance.
        for sn in range(reg.hab.kever.sn + 1):
            dig = hby.db.kels.getLast(keys=reg.hab.pre, on=sn)
            candidate = hby.db.evts.get(keys=(reg.hab.pre, dig)) if dig else None
            if candidate is not None and any(item in candidate.sad.get('a', [])
                                            for item in (seal, dict(i=reg.regk, **seal))):
                anchor = candidate
                break
        if anchor is None:
            author = reg.hab.rotate if reg.hab.kever.estOnly else reg.hab.interact
            author(data=[seal], version=Vrsn_2_0, gvrsn=Vrsn_2_0)
            anchor = reg.hab.kever.serder
        receiptor.msgs.append(dict(pre=reg.hab.pre, sn=anchor.sn, auths=self.auths))
        deadline = time.monotonic() + self.args.timeout
        while True:
            hby.kvy.processEscrows()
            reg.processEscrows()
            accepted = reg.store.seqEvent(reg.regk, Number(numh=event.sad['n']).num)
            if accepted is not None and accepted.said == event.said:
                return
            if time.monotonic() >= deadline:
                raise TimeoutError(f'ACDC v2 event {event.said} is pending authenticated anchor receipts')
            yield self.tock

    def update(self, hby, reger, reg, acdc, state, *, custody=None):
        """Stage one idempotent ``bup`` under the public or derived profile.

        Public authoring creates and retains one random event opening, then
        explicitly publishes it where this command emits evidence. Derived
        authoring reproduces the opening from separately provisioned custody.
        Neither mode authors or interprets ``upd`` as current standing.
        """
        head = reg.store.headEvent(reg.regk)
        if head is None:
            raise ConfigurationError('registry inception is not accepted')
        if head.ilk == 'upd':
            raise ConfigurationError('historical upd heads cannot be extended by the selected ACDC v2 profile')
        sn = Number(numh=head.sad['n']).num
        public = self.args.public
        boundEvent = getattr(self.args, 'bound_event', None)
        if public and boundEvent:
            raise ConfigurationError('--bound-event requires a private blinded update')
        bound = resolveBoundEvent(hby, acdc, boundEvent) if boundEvent else {}

        def makeOpening(ordinal):
            """Select this credential/state opening for the given TEL ordinal.

            Public mode generates an opening for explicit publication; private
            mode requires the supplied custody provider and resolved issuee
            binding. Retain and return the selected opening for this command.
            """
            if public:
                self.blinder = Blinder.blind(sn=ordinal, acdc=acdc.said, state=state)
                self.publishOpening = True
            else:
                if custody is None:
                    raise ConfigurationError('derived authoring requires provisioned registry custody')
                self.blinder = custody.derive(reg.regk, ordinal, acdc.said, state, **bound)
            return self.blinder

        def matches(event, proof):
            """Match a retained BUP and opening to the requested credential/state.

            event must commit to proof's exact digest; a missing proof or a
            different credential/state returns False and cannot justify reuse.
            """
            return (event.ilk == 'bup' and proof is not None
                    and event.sad.get('b') == proof.said
                    and proof.acdc == acdc.said and proof.state == state)

        def acceptedOpening(event):
            """Read possessed public or private proof without reconstructing metadata."""
            opening = reg.store.verifiedOpening(event)
            return (opening, True) if opening is not None else (reger.privateOpening(event), False)

        if self.proposedEvent is not None:
            event = self.proposedEvent
            if event.ilk != 'bup':
                raise ConfigurationError('selected ACDC v2 profile requires a bup group proposal')
            ordinal = Number(numh=event.sad['n']).num
            if public:
                if self.proposedBlinder is None:
                    raise ConfigurationError('public bup group proposal requires its explicit opening')
                self.blinder = self.proposedBlinder
                self.publishOpening = True
            else:
                makeOpening(ordinal)
                if (self.proposedBlinder is not None
                        and self.proposedBlinder.qb64 != self.blinder.qb64):
                    raise ConfigurationError('group proposal opening differs from derived custody')
            if event.sad.get('rd') != reg.regk or not matches(event, self.blinder):
                raise ConfigurationError('group proposal does not bind the requested credential and state')
            if not public:
                reger.retainPrivateOpening(event, self.blinder)
            accepted = reg.store.seqEvent(reg.regk, ordinal)
            if accepted is not None and accepted.said == event.said:
                if public:
                    reg.store.retainOpening(event, self.blinder)
                return event
            if event.sad.get('p') != head.said or ordinal != sn + 1:
                raise ConfigurationError('group proposal does not extend this registry head')
            reg.processEvent(event)
            if public:
                reg.store.retainOpening(event, self.blinder)
            return event

        pending = [event for _, event in reg.store.baser.evts.getTopItemIter()
                   if event.sad.get('rd') == reg.regk
                   and event.sad.get('n') == Number(num=sn + 1).numh]
        if pending:
            event = pending[0]
            if public:
                self.blinder = reg.store.verifiedOpening(event)
                self.publishOpening = True
                if self.blinder is None:
                    raise ConfigurationError('pending public bup is missing its retained opening')
            else:
                makeOpening(Number(numh=event.sad['n']).num)
            if len(pending) != 1 or not matches(event, self.blinder) or event.sad['p'] != head.said:
                raise ConfigurationError('registry has a different pending update; resolve it first')
            if not public:
                reger.retainPrivateOpening(event, self.blinder)
            return event

        if sn and head.ilk == 'bup':
            if public:
                self.blinder, self.publishOpening = acceptedOpening(head)
                if self.blinder is None:
                    raise ConfigurationError(
                        'accepted bup has no retained public or private opening')
            else:
                makeOpening(sn)
            if matches(head, self.blinder) and (not public or self.publishOpening):
                if not public:
                    reger.retainPrivateOpening(head, self.blinder)
                return head

        if bound and hby.kevers[acdc.iseaid].serder.said != boundEvent:
            raise ConfigurationError('new bound update must reference the known current issuee event')
        proof = makeOpening(sn + 1)
        event = messaging.blindate(reg.regk, head.said, proof.said,
                                   sn=sn + 1, stamp=self.args.time)
        if not public:
            reger.retainPrivateOpening(event, proof)
        # Store/validate the exact event through ordinary TEL processing before
        # publishing its opening. Pending anchors remain ordinary TEL escrow.
        reg.processEvent(event)
        if public:
            reg.store.retainOpening(event, proof)
        return event

    def run(self, tymth, tock=0.03125, **kwa):
        """Execute one selected ACDC v2 authoring operation through normal acceptance.

        tymth/tock/kwa supply cooperative scheduling. args selects identity/registry,
        public or blinded state, explicit custody provisioning, and optional group
        proposal. Print JSON acceptance only after the verified registry transition,
        and return None on completion. Unknown aliases, inconsistent flags/proposals,
        invalid credential/schema data, missing capability, and timeout fail normally.
        Cancel scheduled receipt/group workers before opened stores leave scope."""
        self.wind(tymth)
        self.tock = tock
        yield self.tock
        args = self.args
        self.auths = readWitnessAuth(getattr(args, "witness_auth_file", None))
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ConfigurationError('--timeout must be positive')
        wantsCustody = (getattr(args, 'with_custody', False) if self.operation == 'incept'
                        else not args.public)
        with openedRegistry(args) as (hby, rgy), ExitStack() as inventory:
            custody = RegistryCustody(hby, rgy) if wantsCustody else None
            # RIP has no credential bytes. Issuance/revocation borrow Reger for
            # exact credential/source evidence, with no wallet owner in between.
            if self.operation != 'incept':
                reger = inventory.enter_context(openLMDB(cls=Reger, name=hby.name,
                    base=hby.base, temp=hby.db.temp, headDirPath=hby.db.headDirPath))
            hab = hby.habByName(args.alias)
            if hab is None:
                raise ConfigurationError('ACDC v2 authoring requires a local alias')
            if set(self.auths) - set(hab.kever.wits):
                raise ConfigurationError('witness authorization names an AID outside the controller witness set')
            if self.auths and isinstance(hab, GroupHab):
                raise ConfigurationError('group authoring does not yet support per-command witness authorization')
            receiptor = Receiptor(hby=hby)
            if isinstance(hab, GroupHab):
                self.group = AcdcV2GroupCoordinator(hby, rgy, hab, Exchanger(hby, handlers=[]), Notifier(hby=hby))
            elif args.proposal or args.proposal_output:
                raise ConfigurationError('group proposal options require a GroupHab alias')
            workers = [HaberyDoer(habery=hby), self.group or receiptor]
            self.extend(workers)
            try:
                if args.proposal:
                    (self.proposedEvent, self.proposedAnchor,
                     self.proposedBlinder) = self.group.registryProposal(Path(args.proposal).read_bytes())
                    # The authenticated EXN retains encrypted member copies separately
                    # from the optional public event opening returned above.
                    proposals = Parser(version=Vrsn_2_0).parse(
                        ims=bytearray(Path(args.proposal).read_bytes()), processive=False)
                    wrapper = next(item.serder for item in proposals
                                   if item.serder.ilk == 'exn' and item.serder.route in
                                   ('/multisig/rip', '/multisig/bup'))
                    self.proposedSalts = wrapper.sad['a'].get('salts')
                if self.operation == 'incept':
                    if wantsCustody:
                        # Explicit provisioning authenticates before public mutation.
                        custody._manager()
                    elif args.discloser:
                        raise ConfigurationError('--discloser requires --with-custody')
                    if args.backers:
                        raise ConfigurationError('ACDC v2 registries use controller witnesses, not TEL backers')
                    if args.establishment_only:
                        raise ConfigurationError('ACDC v2 anchoring follows the controlling identifier establishment-only trait')
                    if args.discloser and args.discloser not in hby.kevers:
                        raise ConfigurationError('designated discloser key state is unknown')
                    name = args.registry_name or args.alias
                    reg = rgy.registryByName(name)
                    if reg is None:
                        if self.proposedEvent is not None:
                            proposal = self.proposedEvent
                            if proposal.ilk != 'rip' or proposal.sad['i'] != hab.pre:
                                raise ConfigurationError('group inception requires a matching rip proposal')
                            reg = rgy.makeRegistry(name=name, prefix=hab.pre,
                                uuid=proposal.sad['u'], stamp=proposal.sad['dt'], kind=proposal.kind)
                            if reg.regk != proposal.said:
                                raise ConfigurationError('group inception proposal serialization mismatch')
                        else:
                            reg = rgy.makeRegistry(name=name, prefix=hab.pre, uuid=args.nonce)
                    if reg.hab.pre != hab.pre:
                        raise ConfigurationError('registry is controlled by a different identifier')
                    event = reg.store.event(reg.regk)
                    if self.proposedEvent is not None and self.proposedEvent.said != event.said:
                        raise ConfigurationError('group proposal is for a different registry inception')
                    if self.group is not None and wantsCustody:
                        if args.discloser and args.discloser != hab.pre:
                            raise ConfigurationError('group custody belongs to the issuer; send an encrypted reply to a discloser after inception')
                        if self.proposedEvent is not None and self.proposedSalts is None:
                            raise ConfigurationError('the proposed inception has no encrypted salt; approve without --with-custody')
                        if self.proposedSalts is None:
                            # Recover ciphertext from ordinary retained proposals for
                            # this pending anchor, never from a separate salt journal.
                            pending = hby.db.pses.getLast(keys=hab.pre, on=hab.kever.sn + 1)
                            anchor = hby.db.evts.get((hab.pre, pending)) if pending else None
                            accepted_anchor = reg.store.anchor(event.said)
                            if anchor is None and accepted_anchor is not None:
                                anchor = hby.db.evts.get((hab.pre, accepted_anchor[1].qb64))
                            if anchor is not None:
                                for said in hby.db.meids.get((anchor.said,)):
                                    proposal = hby.db.exns.get((said.qb64,))
                                    if (proposal is not None and proposal.pre == hab.mhab.pre
                                            and proposal.sad['a'].get('tel') == event.said
                                            and proposal.sad['a'].get('salts')):
                                        self.proposedSalts = proposal.sad['a']['salts']
                                        break
                            if self.proposedSalts is None:
                                root = (Salter(qb64=custody._load(reg.regk).salt)
                                        if hby.ks.custody.get((reg.regk,)) else Salter())
                                self.proposedSalts = custody.sealMembers(hab, root)
                        # Fail before signing if this member cannot open its copy.
                        custody.openRoot(self.proposedSalts[hab.mhab.pre], hab.mhab.kever.verfers[0])
                    yield from self.anchor(hby, reg, event, receiptor)
                    if not wantsCustody:
                        print(json.dumps(dict(registry=reg.regk, name=name, controller=hab.pre,
                                              accepted=True, custody='not requested')))
                        return
                    info = (custody.retainMemberCopy(reg.regk, hab, self.proposedSalts)
                            if self.group is not None else
                            custody.createCustody(reg.regk, args.discloser or hab.pre))
                    print(json.dumps(dict(registry=reg.regk, name=name, controller=hab.pre,
                                          discloser=info.discloser, accepted=True)))
                    return

                reg = registry(rgy, args.registry_name or args.alias, hab)
                if self.operation == 'create':
                    if args.credential:
                        acdc = SerderACDC(sad=load(args.credential))
                    else:
                        data = load(args.data)
                        if not isinstance(data, dict):
                            raise ConfigurationError('ACDC v2 credential --data must be a JSON object')
                        if args.private and not (args.private_credential_nonce and args.private_subject_nonce):
                            raise ConfigurationError('ACDC v2 --private requires both explicit nonce options or --credential')
                        attribute = dict(data)
                        attribute.setdefault('d', '')
                        if args.private_subject_nonce:
                            attribute['u'] = args.private_subject_nonce
                        recipient = args.recipient
                        if recipient is not None:
                            try:
                                Prefixer(qb64=recipient)
                            except Exception:
                                contacts = Organizer(hby=hby).findExact('alias', recipient)
                                if len(contacts) != 1:
                                    raise ConfigurationError('recipient must be an AID or one unambiguous contact alias') from None
                                recipient = contacts[0]['id']
                        acdc = messaging.acdcmap(israid=hab.pre, regid=reg.regk, schema=args.schema,
                            attribute=attribute, iseaid=recipient, edge=load(args.edges), rule=load(args.rules),
                            uuid=args.private_credential_nonce)
                    if not acdc.verify() or acdc.sad.get('i') != hab.pre or issuerRegistry(acdc) not in (None, reg.regk):
                        raise ConfigurationError('ACDC v2 credential does not match issuer and registry')
                    scheming.validateSchema(acdc, hby.db)
                    old = Registrar(rgy).issuedRecord(reger, acdc.said)
                    event = reg.store.event(old.update) if old else self.update(hby, reger, reg, acdc, 'issued', custody=custody)
                    yield from self.anchor(hby, reg, event, receiptor)
                    # An exact Reger-source retry reports retained history. Do not
                    # re-derive an old opening or require healthy salt custody.
                    record = Registrar(rgy).recordIssued(reger, acdc, event.said,
                                                 blinder=self.blinder if event.ilk == 'bup' else None)
                    print(json.dumps(dict(credential=acdc.said, registry=reg.regk, update=record.update,
                                          accepted=True, state=standing(hby, rgy, reger, reg, acdc, custody=custody, derive=old is None))))
                else:
                    if args.send:
                        raise ConfigurationError('ACDC v2 revocation publication uses the registrar service')
                    record = Registrar(rgy).issuedRecord(reger, args.said)
                    if record is None or record.registry != reg.regk:
                        raise ConfigurationError('credential is not in this ACDC v2 issued inventory')
                    acdc = Registrar(rgy).issuedCredential(reger, record.credential)
                    event = self.update(hby, reger, reg, acdc, 'revoked', custody=custody)
                    yield from self.anchor(hby, reg, event, receiptor)
                    print(json.dumps(dict(credential=acdc.said, registry=reg.regk, update=event.said,
                                          accepted=True, state='revoked')))
            finally:
                self.remove(workers)


def read(args, operation):
    """Return scheduled ACDC v2 inventory and evidence reads.

    args carries identity, filters, registry, file, and capability options;
    operation chooses registries/status/inventory/export. Return a list of
    hio-compatible generator functions. Ordinary listing never enables custody;
    only explicit --derive enables it. --full selects public
    evidence plus the historical issuance proof, never permission to load salts.
    The worker prints results or writes an exclusive destination, propagating
    invalid option, authentication, proof, and file errors with store cleanup."""
    def run(tymth, tock=0.0, **kwa):
        """Execute one selected read after the scheduler's initial yield.

        tymth/tock/kwa follow hio's generator contract; args and operation come from
        the enclosing read adapter. Print JSON inventory/evidence results or write the
        explicit export file; return None on completion. Validation, authentication,
        file-exclusivity, and custody failures propagate. The opened context closes
        credential, registry, and identity owners even when the operation fails."""
        yield tock
        if operation in ('registries', 'status'):
            # Public registry inspection owns no credential inventory or custody.
            with openedRegistry(args) as (hby, rgy):
                if operation == 'registries':
                    for name, reg in rgy.names.items():
                        head = reg.store.headEvent(reg.regk)
                        print(json.dumps(dict(name=name, registry=reg.regk, controller=reg.hab.pre,
                            accepted=head is not None, head=head.said if head else None, sn=reg.sn)))
                elif operation == 'status':
                    reg = registry(rgy, args.registry_name)
                    head = reg.store.headEvent(reg.regk)
                    pending = [dict(said=said, sn=sn, dependency=dependency)
                               for escrow, dependency in ((rgy.baser.maes, 'anchor'), (rgy.baser.ooes, 'prior'))
                               for _, sn, said in escrow.getTopItemIter(keys=reg.regk)]
                    print(json.dumps(dict(registry=reg.regk, controller=reg.hab.pre,
                        accepted=head is not None, head=head.said if head else None, sn=reg.sn, pending=pending)))
                    if args.verbose:
                        for raw in reg.store.cloneTelIter(reg.regk):
                            print(raw.decode())

            return
        with openedRegistry(args) as (hby, rgy), ExitStack() as stores:
            reger = None
            if operation == 'export' or args.issued:
                reger = stores.enter_context(openLMDB(cls=Reger, name=hby.name,
                    base=hby.base, temp=hby.db.temp, headDirPath=hby.db.headDirPath))
            custody = RegistryCustody(hby, rgy) if operation == 'export' and args.derive else None
            if operation == 'inventory':
                if args.poll:
                    raise ConfigurationError('ACDC v2 IPEX admission uses accepted IPEX and explicit holder consent')
                hab = hby.habByName(args.alias) if args.alias else None
                if args.alias and hab is None:
                    raise ConfigurationError('unknown ACDC v2 inventory alias')
                if args.schema and not args.issued:
                    raise ConfigurationError('ACDC v2 held inventory lists admitted references; schema filtering requires the accepted disclosure')
                records = (Registrar(rgy).issuedRecords(reger) if args.issued
                           else AcdcV2IpexVerification(hby, rgy).admissions())
                for record in records:
                    owner = record.controller if args.issued else record.holder
                    if hab and owner != hab.pre:
                        continue
                    acdc = Registrar(rgy).issuedCredential(reger, record.credential) if args.issued else None
                    if args.schema and (acdc is None or acdc.sad['s'] != args.schema):
                        continue
                    if args.said:
                        print(record.credential)
                    else:
                        result = asdict(record)
                        if not args.verbose:
                            result.pop('raw', None)
                        if acdc:
                            result['state'] = standing(hby, rgy, reger, rgy.regs[record.registry], acdc)
                        print(json.dumps(result))
            elif operation == 'export':
                hab = hby.habByName(args.alias)
                if hab is None:
                    raise ConfigurationError('unknown ACDC v2 export alias')
                reg = registry(rgy, args.registry_name, hab)
                record = Registrar(rgy).issuedRecord(reger, args.said)
                if record is None or record.registry != reg.regk:
                    raise ConfigurationError('ACDC v2 export requires an issued inventory credential')
                acdc = Registrar(rgy).issuedCredential(reger, record.credential)
                if args.chains or (args.full and acdc.sad.get('e')):
                    raise ConfigurationError('ACDC v2 chained evidence must be exported from its accepted IPEX disclosure')
                # Authenticate the exact historical opening before constructing
                # output. A salt-derived Blinder is only a candidate until vet.
                origin = (issuanceOrigin(hby, rgy, acdc, record, custody=custody,
                          opening=loadOpening(args.opening) if args.opening else None)
                          if args.full else None)
                stream = bytearray()
                if args.kels or args.full:
                    for msg in hby.db.clonePreIter(pre=record.controller, version=Vrsn_2_0):
                        stream.extend(msg)
                if args.full and record.bound and acdc.iseaid != record.controller:
                    for msg in hby.db.clonePreIter(pre=acdc.iseaid, version=Vrsn_2_0):
                        stream.extend(msg)
                if args.tels or args.full:
                    for raw in reg.store.cloneTelIter(reg.regk):
                        event = SerderACDC(raw=raw)
                        number, diger = reg.store.anchor(event.said)
                        bonds = [SealSource(s=number.numh, d=diger.qb64)]
                        # Public bup is public because every publication carries
                        # its exact expanded opening. The registry store retains
                        # event evidence across restarts without retaining registry
                        # custody or synthesizing an opening during export.
                        if (opening := rgy.store.verifiedOpening(event)) is not None:
                            bonds.insert(0, opening.data)
                        stream.extend(messagize(event, bonds=bonds, gvrsn=Vrsn_2_0))
                if args.full:
                    stream.extend(origin)
                elif not (args.tels or args.kels):
                    stream.extend(acdc.raw)
                with Path(args.output).open('xb') as output:
                    output.write(stream)
    return [doing.doify(run)]
