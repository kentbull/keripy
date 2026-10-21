"""Explicit native adapters for the existing credential command hierarchy."""
from contextlib import contextmanager
from dataclasses import asdict
import json
import math
from pathlib import Path
import time

from hio.base import doing

from .existing import setupHby
from ...acdc import messaging, scheming
from ...acdc.regeventing import issuerRegistry
from ...acdc.registraring import Regery
from ...app import GroupHab, HaberyDoer, Keeper, Notifier, Organizer, Receiptor
from ...app.credentialing import Wallet
from ...app.native_grouping import NativeGroup
from ...core import Codens, Counter, Number, Prefixer, SealSource, SerderACDC, messagize
from ...kering import AuthError, ConfigurationError, Vrsn_2_0
from ...peer import Exchanger


def options(parser, *, author=False):
    parser.add_argument('--native', action='store_true', help='use native v2 ACDC registries and wallet')
    if author:
        parser.add_argument('--timeout', type=float, default=30.0,
                            help='seconds to wait for authenticated anchor acceptance')
        parser.add_argument('--bound-event', help='exact accepted issuee KEL event for a bound state update')
        parser.add_argument('--proposal', help='approve this exact signed native group registry proposal')
        parser.add_argument('--proposal-output', help='write a member proposal for file handoff instead of network fanout')


def load(value):
    if value is None:
        return None
    return json.loads(Path(value[1:]).read_text() if value.startswith('@') else value)


@contextmanager
def opened(args):
    # Habery can migrate an unencrypted Keeper when given a passcode. Native
    # custody requires existing encryption, never an implicit AEID change.
    keeper = Keeper(name=args.name, base=args.base, reopen=True)
    try:
        if not keeper.gbls.get('aeid'):
            raise AuthError('native custody requires an existing authenticated encrypted Keeper')
    finally:
        keeper.close()
    hby = setupHby(name=args.name, base=args.base, bran=args.bran, version=Vrsn_2_0)
    rgy = wallet = None
    try:
        rgy = Regery(hby=hby, name=args.name, base=args.base)
        wallet = Wallet(hby, rgy)
        yield hby, rgy, wallet
    finally:
        if wallet is not None:
            wallet.close()
        if rgy is not None:
            rgy.close()
        hby.close()


def registry(rgy, name, hab=None):
    reg = rgy.registryByName(name)
    if reg is None:
        raise ConfigurationError(f'unknown native registry {name}')
    if hab is not None and reg.hab.pre != hab.pre:
        raise ConfigurationError('registry is controlled by a different identifier')
    return reg


def standing(wallet, reg, acdc):
    head = reg.store.headEvent(reg.regk)
    if head is not None and head.ilk == 'upd':
        return head.sad['ts'] if head.sad['td'] == acdc.said else 'unknown'
    if head is None or head.ilk != 'bup':
        return 'unknown'
    sn = Number(numh=head.sad['n']).num
    retained = wallet.db.issued.get((acdc.said,))
    bound = (dict(bound=True, bsn=retained.bound['bn'], bd=retained.bound['bd'])
             if retained and retained.update == head.said and retained.bound else {})
    for state in ('issued', 'revoked'):
        if wallet.derive(reg.regk, sn, acdc.said, state, **bound).said == head.sad['b']:
            return state
    return 'unknown'


class NativeAuthor(doing.DoDoer):
    """Author individual native registry events and await their real KEL receipts."""
    def __init__(self, args, operation):
        self.args, self.operation = args, operation
        self.group = self.proposedEvent = self.proposedAnchor = self.blinder = None
        super().__init__(doers=[doing.doify(self.run)])

    def anchor(self, hby, reg, event, receiptor):
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
                    raise TimeoutError(f'native group event {event.said} is pending member approval or witness receipts')
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
        receiptor.msgs.append(dict(pre=reg.hab.pre, sn=anchor.sn))
        deadline = time.monotonic() + self.args.timeout
        while True:
            hby.kvy.processEscrows()
            reg.processEscrows()
            accepted = reg.store.seqEvent(reg.regk, Number(numh=event.sad['n']).num)
            if accepted is not None and accepted.said == event.said:
                return
            if time.monotonic() >= deadline:
                raise TimeoutError(f'native event {event.said} is pending authenticated anchor receipts')
            yield self.tock

    def update(self, wallet, reg, acdc, state):
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
            self.blinder = wallet.derive(reg.regk, ordinal, acdc.said, state, **bound)
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
        self.wind(tymth)
        self.tock = tock
        yield self.tock
        args = self.args
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ConfigurationError('--timeout must be positive')
        with opened(args) as (hby, rgy, wallet):
            hab = hby.habByName(args.alias)
            if hab is None:
                raise ConfigurationError('native authoring requires a local alias')
            receiptor = Receiptor(hby=hby)
            if isinstance(hab, GroupHab):
                self.group = NativeGroup(hby, rgy, hab, Exchanger(hby, handlers=[]), Notifier(hby=hby))
            elif args.proposal or args.proposal_output:
                raise ConfigurationError('group proposal options require a GroupHab alias')
            workers = [HaberyDoer(habery=hby), self.group or receiptor]
            self.extend(workers)
            try:
                if args.proposal:
                    self.proposedEvent, self.proposedAnchor = self.group.registryProposal(Path(args.proposal).read_bytes())
                if self.operation == 'incept':
                    wallet._manager()  # fail before creating public state without encrypted custody
                    if args.backers:
                        raise ConfigurationError('native registries use controller witnesses, not TEL backers')
                    if args.establishment_only:
                        raise ConfigurationError('native anchoring follows the controlling identifier establishment-only trait')
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
                    if reg.sn > 0 and wallet.db.custody.get((reg.regk,)) is None:
                        raise ConfigurationError('nonempty registry requires custody import; its secret cannot be regenerated')
                    if self.proposedEvent is not None and wallet.db.custody.get((reg.regk,)) is None:
                        print(json.dumps(dict(registry=reg.regk, name=name, controller=hab.pre,
                            accepted=True, custody='requires explicit protected import')))
                        return
                    info = wallet.createCustody(reg.regk, args.discloser or hab.pre)
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
                            raise ConfigurationError('native credential --data must be a JSON object')
                        if args.private and not (args.private_credential_nonce and args.private_subject_nonce):
                            raise ConfigurationError('native --private requires both explicit nonce options or --credential')
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
                        raise ConfigurationError('native credential does not match issuer and registry')
                    scheming.validateSchema(acdc, hby.db)
                    old = wallet.db.issued.get((acdc.said,))
                    event = reg.store.event(old.update) if old else self.update(wallet, reg, acdc, 'issued')
                    yield from self.anchor(hby, reg, event, receiptor)
                    if old is not None and event.ilk == 'bup':
                        params = dict(bound=True, bsn=old.bound['bn'], bd=old.bound['bd']) if old.bound else {}
                        self.blinder = wallet.derive(reg.regk, Number(numh=event.sad['n']).num,
                                                     acdc.said, 'issued', **params)
                    record = wallet.recordIssued(acdc, event.said,
                                                 blinder=self.blinder if event.ilk == 'bup' else None)
                    print(json.dumps(dict(credential=acdc.said, registry=reg.regk, update=record.update,
                                          accepted=True, state=standing(wallet, reg, acdc))))
                else:
                    if args.send:
                        raise ConfigurationError('native revocation publication uses the registrar service')
                    record = wallet.db.issued.get((args.said,))
                    if record is None or record.registry != reg.regk:
                        raise ConfigurationError('credential is not in this native issued inventory')
                    acdc = wallet.issuedCredential(record.credential)
                    event = self.update(wallet, reg, acdc, 'revoked')
                    yield from self.anchor(hby, reg, event, receiptor)
                    print(json.dumps(dict(credential=acdc.said, registry=reg.regk, update=event.said,
                                          accepted=True, state='revoked')))
            finally:
                self.remove(workers)


def read(args, operation):
    """Read existing native state or perform explicit protected custody handoff."""
    def run(tymth, tock=0.0, **kwa):
        yield tock
        with opened(args) as (hby, rgy, wallet):
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
                    raise ConfigurationError('native admission uses accepted IPEX and explicit wallet consent')
                hab = hby.habByName(args.alias) if args.alias else None
                if args.alias and hab is None:
                    raise ConfigurationError('unknown native inventory alias')
                if args.schema and not args.issued:
                    raise ConfigurationError('native held inventory lists admitted references; schema filtering requires the accepted disclosure')
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
                    raise ConfigurationError('unknown native export alias')
                reg = registry(rgy, args.registry_name, hab)
                if args.custody:
                    path = wallet.exportCustody(reg.regk, args.output)
                    print(json.dumps(dict(registry=reg.regk, custody_file=str(path))))
                else:
                    record = wallet.db.issued.get((args.said,))
                    if record is None or record.registry != reg.regk:
                        raise ConfigurationError('native export requires an issued inventory credential')
                    acdc = wallet.issuedCredential(record.credential)
                    if args.chains or (args.full and acdc.sad.get('e')):
                        raise ConfigurationError('native chained evidence must be exported from its accepted IPEX disclosure')
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
                        event = reg.store.event(record.update)
                        if event.ilk == 'bup':
                            bound = dict(bound=True, bsn=record.bound['bn'], bd=record.bound['bd']) if record.bound else {}
                            proof = wallet.derive(reg.regk, Number(numh=event.sad['n']).num, acdc.said, 'issued', **bound)
                            stream.extend(messagize(acdc, bonds=[proof.data], gvrsn=Vrsn_2_0))
                        else:
                            stream.extend(acdc.raw + Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b)
                    elif not (args.tels or args.kels):
                        stream.extend(acdc.raw)
                    with Path(args.output).open('xb') as output:
                        output.write(stream)
            elif operation == 'import':
                wallet.importCustody(args.file, regid=args.registry, controller=args.controller,
                                     discloser=args.discloser, rewrap=args.rewrap)
                print(json.dumps(dict(registry=args.registry, custody_imported=True)))
    return [doing.doify(run)]
