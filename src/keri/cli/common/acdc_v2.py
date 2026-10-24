"""Explicit ACDC v2 adapters for the existing credential command hierarchy."""
from contextlib import contextmanager
from dataclasses import asdict
import json
import math
from pathlib import Path
import time

from hio.base import doing

from .existing import setupHby
from ...acdc import messaging, scheming
from ...acdc.regeventing import issuerRegistry, _blindCandidates, vet
from ...acdc.registraring import Regery
from ...app import GroupHab, HaberyDoer, Keeper, Notifier, Organizer, Receiptor
from ...app.credentialing import Wallet
from ...app.registry_custody import RegistryCustody
from ...app.acdc_v2_grouping import AcdcV2GroupCoordinator
from ...core import Codens, Counter, Number, Prefixer, SealEvent, SealSource, SerderACDC, messagize
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


def issuanceOrigin(wallet, acdc, record, *, opening=None):
    """Compose exact historical issuance evidence after common core verification.

    wallet supplies accepted TEL/KEL history and optional explicitly selected
    custody; acdc and record identify the original issued credential/event.
    opening is a possessed event-specific Blinder and takes precedence over
    derivation. Return credential bytes with verified proof/source attachments.
    Missing evidence raises ConfigurationError; core authentication failures
    propagate before the caller creates any output file.

    Unlike registryProof's current-head traversal, this export fixes its head at
    record.update. Later revocation or issuee rotation cannot substitute a newer
    event. This local CLI composition reuses regeventing.vet, not a new verifier.
    """
    rgy = wallet.rgy
    event = rgy.store.event(record.update)
    if event is None or event.ilk not in ('upd', 'bup'):
        raise ConfigurationError('retained issuance event is unavailable')
    sn = Number(numh=event.sad['n']).num
    accepted = rgy.store.seqEvent(record.registry, sn)
    if accepted is None or accepted.said != record.update:
        raise ConfigurationError('retained issuance event is not accepted')
    if event.ilk == 'bup' and opening is None:
        if wallet.custody is None:
            raise ConfigurationError('issuance opening unavailable; supply --opening or use --derive with provisioned custody')
        bound = (dict(bound=True, bsn=record.bound['bn'], bd=record.bound['bd'])
                 if record.bound else {})
        opening = wallet.custody.derive(record.registry, sn, acdc.said, 'issued', **bound)
    if event.ilk == 'upd' and opening is not None:
        raise ConfigurationError('public issuance does not use an --opening')
    updates = [rgy.store.seqEvent(record.registry, ordinal) for ordinal in range(1, sn + 1)]
    verified = vet(rgy.store.seqEvent(record.registry, 0), updates,
                   db=wallet.hby.db, acdc=acdc, blinder=opening)
    if verified.state != 'issued':
        raise ConfigurationError('retained event does not establish issuance')
    bonds = [opening.data] if opening is not None else []
    if issuerRegistry(acdc) is None:
        bonds.append(SealEvent(i=record.registry, s=event.sad['n'], d=event.said))
    return (messagize(acdc, bonds=bonds, gvrsn=Vrsn_2_0) if bonds else
            acdc.raw + Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b)


@contextmanager
def opened(args, *, custody=False):
    """Yield ACDC v2 evidence/inventory owners without changing Keeper encryption.

    ``args`` supplies existing identity name/base/passcode. ``custody`` explicitly
    composes the optional registry derivation owner; ordinary operations leave it
    absent. Encrypted identities still authenticate through setupHby. A passcode
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
    rgy = wallet = None
    try:
        rgy = Regery(hby=hby, name=args.name, base=args.base)
        wallet = Wallet(hby, rgy)
        if custody:
            wallet.custody = RegistryCustody(hby, rgy, db=wallet.db)
        yield hby, rgy, wallet
    finally:
        if wallet is not None:
            wallet.close()
        if rgy is not None:
            rgy.close()
        hby.close()


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


def standing(wallet, reg, acdc, *, derive=False):
    """Return known current state, or unknown if the accepted head cannot be opened.

    wallet supplies issued inventory and optionally explicit custody; reg supplies
    accepted registry history; acdc is the exact credential being queried. Public
    upd state needs no secret. derive permits event-specific derivation only when
    custody is composed; ordinary enumeration/historical retries do not load it.
    Return issued/revoked only when the current head binds this credential; a
    missing/nonmatching head or unavailable capability returns unknown. Core bound
    or derivation failures propagate rather than becoming a freshness claim."""
    head = reg.store.headEvent(reg.regk)
    if head is not None and head.ilk == 'upd':
        return head.sad['ts'] if head.sad['td'] == acdc.said else 'unknown'
    if head is None or head.ilk != 'bup':
        return 'unknown'
    if not derive or wallet.custody is None:
        return 'unknown'
    sn = Number(numh=head.sad['n']).num
    retained = wallet.db.issued.get((acdc.said,))
    bound = (dict(bound=True, bsn=retained.bound['bn'], bd=retained.bound['bd'])
             if retained and retained.update == head.said and retained.bound else {})
    for state in ('issued', 'revoked'):
        if wallet.custody.derive(reg.regk, sn, acdc.said, state, **bound).said == head.sad['b']:
            return state
    return 'unknown'


class AcdcV2Author(doing.DoDoer):
    """Author exact ACDC v2 registry events through individual or group controllers.

    Staging, KEL anchoring, authenticated receipt acceptance, and issued inventory
    recording are separate steps. Ordinary public updates need no custody; blinded
    authoring explicitly composes that capability. Exact retries preserve history."""
    def __init__(self, args, operation):
        """Schedule one ACDC v2 inception, credential creation, or revocation.

        args is the parsed command namespace and operation selects the action.
        Initialize pending group/anchor/opening references and one cooperative run
        child. This constructor opens no identity, registry, or custody store."""
        self.args, self.operation = args, operation
        self.auths = {}
        self.group = self.proposedEvent = self.proposedAnchor = self.blinder = None
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
            wrapper, attachments = self.group.approveRegistry(event, self.proposedAnchor)
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

    def update(self, wallet, reg, acdc, state):
        """Stage an idempotent public or explicitly derived blinded update.

        ``wallet`` supplies optional custody, ``reg`` the accepted history,
        ``acdc`` the exact credential, and ``state`` its requested state. Return
        the existing matching or newly staged event. Reject inconsistent group
        proposals, missing capability, and conflicting pending work before
        authoring a controller anchor.
        """
        head = reg.store.headEvent(reg.regk)
        if head is None:
            raise ConfigurationError('registry inception is not accepted')
        sn = Number(numh=head.sad['n']).num
        unblinded = self.args.unblinded
        boundEvent = getattr(self.args, 'bound_event', None)
        if unblinded and boundEvent:
            raise ConfigurationError('--bound-event requires a blinded update')
        bound = wallet.boundEvent(acdc, boundEvent) if boundEvent else {}

        def opening(ordinal):
            """Derive and retain one explicitly requested event-specific opening.

            ordinal is the target registry sequence number. Return its Blinder and retain
            it on this author for inventory recording; raise ConfigurationError when the
            caller did not compose custody. The derivation salt never leaves its owner."""
            if wallet.custody is None:
                raise ConfigurationError('blinded authoring requires provisioned registry custody')
            self.blinder = wallet.custody.derive(reg.regk, ordinal, acdc.said, state, **bound)
            return self.blinder
        if self.proposedEvent is not None:
            event = self.proposedEvent
            ordinal = Number(numh=event.sad['n']).num
            matches = (event.sad.get('td') == acdc.said and event.sad.get('ts') == state
                       if event.ilk == 'upd' else event.ilk == 'bup'
                       and opening(ordinal).said == event.sad['b'])
            if event.sad.get('rd') != reg.regk or not matches:
                raise ConfigurationError('group proposal does not bind the requested credential and state')
            accepted = reg.store.seqEvent(reg.regk, ordinal)
            if accepted is not None and accepted.said == event.said:
                return event
            if event.sad.get('p') != head.said or ordinal != sn + 1:
                raise ConfigurationError('group proposal does not extend this registry head')
            reg.processEvent(event)
            return event
        if unblinded and head.ilk == 'upd' and head.sad['td'] == acdc.said and head.sad['ts'] == state:
            return head
        if not unblinded and sn and head.ilk == 'bup' and opening(sn).said == head.sad.get('b'):
            return head
        proof = None if unblinded else opening(sn + 1)
        pending = [event for _, event in reg.store.baser.evts.getTopItemIter()
                   if event.sad.get('rd') == reg.regk and event.sad.get('n') == Number(num=sn + 1).numh]
        if pending:
            matches = (pending[0].sad.get('td') == acdc.said and pending[0].sad.get('ts') == state
                       if unblinded else pending[0].sad.get('b') == proof.said)
            if len(pending) != 1 or not matches or pending[0].sad['p'] != head.said:
                raise ConfigurationError('registry has a different pending update; resolve it first')
            return pending[0]
        if bound and wallet.hby.kevers[acdc.iseaid].serder.said != boundEvent:
            raise ConfigurationError('new bound update must reference the known current issuee event')
        event = (messaging.update(reg.regk, head.said, acdc.said, state, sn=sn + 1, stamp=self.args.time)
                 if unblinded else messaging.blindate(reg.regk, head.said, proof.said, sn=sn + 1, stamp=self.args.time))
        reg.processEvent(event)
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
                        else not args.unblinded)
        with opened(args, custody=wantsCustody) as (hby, rgy, wallet):
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
                    self.proposedEvent, self.proposedAnchor = self.group.registryProposal(Path(args.proposal).read_bytes())
                if self.operation == 'incept':
                    if wantsCustody:
                        # Explicit provisioning authenticates before public mutation.
                        wallet.custody._manager()
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
                    yield from self.anchor(hby, reg, event, receiptor)
                    if not wantsCustody:
                        print(json.dumps(dict(registry=reg.regk, name=name, controller=hab.pre,
                                              accepted=True, custody='not requested')))
                        return
                    if self.proposedEvent is not None and wallet.db.custody.get((reg.regk,)) is None:
                        print(json.dumps(dict(registry=reg.regk, name=name, controller=hab.pre,
                            accepted=True, custody='requires explicit protected import')))
                        return
                    info = wallet.custody.createCustody(reg.regk, args.discloser or hab.pre)
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
                    old = wallet.db.issued.get((acdc.said,))
                    event = reg.store.event(old.update) if old else self.update(wallet, reg, acdc, 'issued')
                    yield from self.anchor(hby, reg, event, receiptor)
                    # An exact issued-row retry reports retained history. Do not
                    # re-derive an old opening or require healthy salt custody.
                    record = wallet.recordIssued(acdc, event.said,
                                                 blinder=self.blinder if event.ilk == 'bup' else None)
                    print(json.dumps(dict(credential=acdc.said, registry=reg.regk, update=record.update,
                                          accepted=True, state=standing(wallet, reg, acdc, derive=old is None))))
                else:
                    if args.send:
                        raise ConfigurationError('ACDC v2 revocation publication uses the registrar service')
                    record = wallet.db.issued.get((args.said,))
                    if record is None or record.registry != reg.regk:
                        raise ConfigurationError('credential is not in this ACDC v2 issued inventory')
                    acdc = wallet.issuedCredential(record.credential)
                    event = self.update(wallet, reg, acdc, 'revoked')
                    yield from self.anchor(hby, reg, event, receiptor)
                    print(json.dumps(dict(credential=acdc.said, registry=reg.regk, update=event.said,
                                          accepted=True, state='revoked')))
            finally:
                self.remove(workers)


def read(args, operation):
    """Return scheduled ACDC v2 inventory/evidence reads or explicit handoff work.

    args carries identity, filters, registry, file, and capability options;
    operation chooses registries/status/inventory/export/import. Return a list of
    hio-compatible generator functions. Ordinary listing never enables custody;
    explicit custody import/export or --derive may do so. --full selects public
    evidence plus the historical issuance proof, never permission to load salts.
    The worker prints results or writes an exclusive destination, propagating
    invalid option, authentication, proof, and file errors with store cleanup."""
    def run(tymth, tock=0.0, **kwa):
        """Execute one selected read/handoff after the scheduler's initial yield.

        tymth/tock/kwa follow hio's generator contract; args and operation come from
        the enclosing read adapter. Print JSON inventory/evidence results or write the
        explicit export file; return None on completion. Validation, authentication,
        file-exclusivity, and custody failures propagate. The opened context closes
        wallet, registry, and identity owners even when the operation fails."""
        yield tock
        # Plain inventory/status never composes derivation capability; only
        # the explicit handoff/export operations below may request it.
        with opened(args, custody=(operation == 'import' or operation == 'export'
                    and (args.custody or args.derive))) as (hby, rgy, wallet):
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
            elif operation == 'inventory':
                if args.poll:
                    raise ConfigurationError('ACDC v2 IPEX admission uses accepted IPEX and explicit wallet consent')
                hab = hby.habByName(args.alias) if args.alias else None
                if args.alias and hab is None:
                    raise ConfigurationError('unknown ACDC v2 inventory alias')
                if args.schema and not args.issued:
                    raise ConfigurationError('ACDC v2 held inventory lists admitted references; schema filtering requires the accepted disclosure')
                records = wallet.inventory()['issued' if args.issued else 'held']
                for record in records:
                    owner = record.controller if args.issued else record.holder
                    if hab and owner != hab.pre:
                        continue
                    acdc = wallet.issuedCredential(record.credential) if args.issued else None
                    if args.schema and (acdc is None or acdc.sad['s'] != args.schema):
                        continue
                    if args.said:
                        print(record.credential)
                    else:
                        result = asdict(record)
                        if not args.verbose:
                            result.pop('raw', None)
                        if acdc:
                            result['state'] = standing(wallet, rgy.regs[record.registry], acdc)
                        print(json.dumps(result))
            elif operation == 'export':
                hab = hby.habByName(args.alias)
                if hab is None:
                    raise ConfigurationError('unknown ACDC v2 export alias')
                reg = registry(rgy, args.registry_name, hab)
                if args.custody:
                    path = wallet.custody.exportCustody(reg.regk, args.output)
                    print(json.dumps(dict(registry=reg.regk, custody_file=str(path))))
                else:
                    record = wallet.db.issued.get((args.said,))
                    if record is None or record.registry != reg.regk:
                        raise ConfigurationError('ACDC v2 export requires an issued inventory credential')
                    acdc = wallet.issuedCredential(record.credential)
                    if args.chains or (args.full and acdc.sad.get('e')):
                        raise ConfigurationError('ACDC v2 chained evidence must be exported from its accepted IPEX disclosure')
                    # Authenticate the exact historical opening before constructing
                    # output. A salt-derived Blinder is only a candidate until vet.
                    origin = (issuanceOrigin(wallet, acdc, record,
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
                            stream.extend(messagize(event,
                                bonds=[SealSource(s=number.numh, d=diger.qb64)], gvrsn=Vrsn_2_0))
                    if args.full:
                        stream.extend(origin)
                    elif not (args.tels or args.kels):
                        stream.extend(acdc.raw)
                    with Path(args.output).open('xb') as output:
                        output.write(stream)
            elif operation == 'import':
                wallet.custody.importCustody(args.file, regid=args.registry, controller=args.controller,
                                            discloser=args.discloser, rewrap=args.rewrap)
                print(json.dumps(dict(registry=args.registry, custody_imported=True)))
    return [doing.doify(run)]
