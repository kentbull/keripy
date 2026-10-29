# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.multisig module

"""
import argparse
import json
import math
import time
from ordered_set import OrderedSet as oset

from hio.base import doing
from hio.help import ogler
from prettytable import PrettyTable

from ...common import Parsery, setupHby, printIdentifier, parseVersion

from ....kering import (TraitCodex, ConfigurationError, KeriError, Roles,
                        Kinds, Ilks, MissingAnchorError, MissingRegistryError, MissingEntryError, ValidationError,
                        Version, Vrsn_1_0, Vrsn_2_0)
from ....app import (GroupHab, HaberyDoer, MailboxDirector, WitnessInquisitor,
                     Notifier, Multiplexor, Counselor, Organizer, Poster,
                     multisigInceptExn, multisigInteractExn, multisigRotateExn,
                     multisigRpyExn, multisigRegistryInceptExn, multisigIssueExn,
                     multisigRevokeExn)
from ....app.grouping import loadHandlers, replyProposal, endorseReply
from ....app.acdc_v2_grouping import RegistryApproval
from ....app.forwarding import StreamPoster
from ....app.evidencing import ServiceConfig
from ....acdc import Regery as NativeRegery
from ....acdc.regeventing import Rever

from ....core import (Prefixer, Number, Diger, Tholder,
                      Schemer, Kramer, Pruner, Parser, Revery, SerderKERI,
                      SerderACDC, TraitDex, messagize)

from ....peer import Exchanger, cloneMessage, serializeMessage
from ....vdr import Verifier, Regery, Credentialer, Registrar


logger = ogler.getLogger()

parser = argparse.ArgumentParser(description='Approve pending group multisig events, including native registry proposals.',
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: join(args))
parser.add_argument('--group', '-g', help='human-readable name for the multisig group identifier prefix', required=False, default=None)
parser.add_argument("--auto", "-Y", help="approve pending multisig events non-interactively", action="store_true")
parser.add_argument('--timeout', type=float, default=30.0,
                    help='seconds to await native registry acceptance and member delivery')
parser.add_argument('--version', default=None, required=False, type=parseVersion,
                    help='KERI protocol version for mailbox queries while joining, such as 1.0 or 2.0')
parser.add_argument('--registry-salt', action='store_true',
                    help='enable optional encrypted registry-salt reply approval')

def join(args):
    """ Wait for and provide interactive confirmation of group multisig inception, rotation or interaction events

    Parameters:
        args(Namespace): parsed arguments namespace object

    """
    name = args.name
    base = args.base
    bran = args.bran
    auto = args.auto
    group = args.group
    version = args.version

    joinDoer = JoinDoer(name=name, base=base, bran=bran, group=group, auto=auto,
                        version=version, timeout=args.timeout, registrySalt=args.registry_salt)

    doers = [joinDoer]
    return doers


class JoinDoer(doing.DoDoer):
    """ Doist doer capable of polling for group multisig events and prompting user for action

    """

    def __init__(self, name, base, bran, group, auto=False, version=None, timeout=30.0,
                 registrySalt=False):
        """ Create doer for polling for group multisig events and either approve automatically or prompt user

        Parameters:
            name (str): database environment name
            base (str): database directory prefix
            bran (str): passcode to unlock keystore
            group (str): human-readable name for the multisig identifier prefix
            auto (bool): non-interactively auto approve any inception, rotation, interaction, or other event
                         while using the default group of "default-group"
            version (Versionage | None): Protocol version for existing join processors.
            timeout (float): Positive native registry acceptance and delivery deadline.
            registrySalt (bool): Explicitly compose optional salt reply policy and
                durable delivery using existing processors and trusted saved rosters.
        """
        if not math.isfinite(timeout) or timeout <= 0:
            raise ConfigurationError('--timeout must be positive')
        if registrySalt and (version or Version) != Vrsn_2_0:
            raise ConfigurationError('--registry-salt requires native v2 processing')
        if registrySalt and not group:
            raise ConfigurationError('--registry-salt requires an explicit --group')
        self.registrySalt = registrySalt
        self.saltWallet = self.saltService = None
        self.timeout = timeout
        self.group = group
        self.version = version
        self.hby = setupHby(name=name, base=base, bran=bran, version=self.version)
        self.rgy = Regery(hby=self.hby, name=name, base=base)
        self.hbyDoer = HaberyDoer(habery=self.hby)  # setup doer
        self.witq = WitnessInquisitor(hby=self.hby)
        self.org = Organizer(hby=self.hby)
        self.notifier = Notifier(hby=self.hby)
        self.exc = Exchanger(hby=self.hby, handlers=[])
        self.verifier = Verifier(hby=self.hby, reger=self.rgy.reger)
        self.rvy = Revery(db=self.hby.db,  lax=True)
        self.hby.kvy.registerReplyRoutes(self.rvy.rtr)
        parser_kwa = dict()
        if self.version is not None:
            parser_kwa["version"] = self.version

        # Native TEL intake shares the existing local and mailbox parsers. It
        # does not introduce another coordinator or autonomous mailbox lifecycle.
        self.rgyV2 = (NativeRegery(hby=self.hby, name=name, base=base)
                      if (self.version or Version) == Vrsn_2_0 else None)
        self.reverV2 = (Rever(db=self.hby.db, reger=self.rgyV2.baser)
                        if self.rgyV2 is not None else None)
        mux_kwa = dict(exc=self.exc, rgy=self.reverV2) if self.reverV2 is not None else {}
        mux = Multiplexor(hby=self.hby, notifier=self.notifier, **mux_kwa)
        self.mux = mux
        self.pruner = None
        kvy = self.hby.kvy
        if self.reverV2 is not None:
            # Preserve the native coordinator's mandatory KRAM policy at each
            # intake boundary, with one cache owner and one pruning lifecycle.
            kvy = mux.kvy
            kvy.kramer = Kramer(db=self.hby.db, cf=ServiceConfig(), cues=kvy.cues)
            self.hby.kvy.kramer = kvy.kramer
            self.rvy = mux.rvy
            self.pruner = Pruner(kvy.kramer, tock=1.0)
        self.psr = Parser(kvy=kvy, tvy=self.rgy.tvy,
                          rvy=self.rvy, vry=self.verifier, exc=self.exc,
                          rgy=self.reverV2, **parser_kwa)

        loadHandlers(exc=self.exc, mux=mux)
        self.counselor = Counselor(hby=self.hby, version=self.version, kind=Kinds.json)

        self.registrar = Registrar(hby=self.hby, rgy=self.rgy, counselor=self.counselor)
        self.credentialer = Credentialer(hby=self.hby, rgy=self.rgy, registrar=self.registrar,
                                         verifier=self.verifier)

        kwa = dict(version=self.version, gvrsn=self.version, kind=Kinds.json) if self.version is not None else {}
        if self.reverV2 is not None:
            kwa.update(kvy=self.mux.kvy, rvy=self.rvy)
        self.mbx = MailboxDirector(hby=self.hby, exc=self.exc, topics=['/receipt', '/multisig', '/replay',
                                                                       '/delegate'],
                                   **kwa)
        self.mbx.parser.rgy = self.reverV2
        self.postman = Poster(hby=self.hby, version=self.version, kind=Kinds.json)

        doers = [self.hbyDoer, self.witq,  self.mbx, self.counselor, self.registrar, self.credentialer, self.postman]
        self.toRemove = list(doers)
        doers.extend([doing.doify(self.joinDo)])
        if self.reverV2 is not None:
            escrow = doing.doify(self.registryEscrowDo)
            doers.append(escrow)
            self.toRemove.append(escrow)
            doers.append(self.pruner)
            self.toRemove.append(self.pruner)
        self.auto = auto
        super(JoinDoer, self).__init__(doers=doers)
        if self.registrySalt:
            self.enableRegistrySalt()

    def joinDo(self, tymth, tock=0.0, **kwa):
        """
        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:
            doifiable Doist compatible generator method
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        print("Waiting for group multisig events...")

        while self.notifier.noter.notes.cnt() == 0:
            yield self.tock

        for keys, notice in self.notifier.noter.notes.getTopItemIter():
            attrs = notice.attrs
            route = attrs['r']

            match route:
                case '/multisig/icp':
                    done = yield from self.incept(attrs)
                case '/multisig/ixn':
                    done = yield from self.interact(attrs)
                case '/multisig/rot':
                    done = yield from self.rotate(attrs)
                case '/multisig/rpy':
                    done = yield from self.rpy(attrs)
                case '/multisig/rip' | '/multisig/bup':
                    done = yield from self.registry(attrs)
                case '/multisig/vcp':
                    done = yield from self.vcp(attrs)
                case '/multisig/iss':
                    done = yield from self.iss(attrs)
                case '/multisig/rev':
                    done = yield from self.rev(attrs)
                case _:
                    continue

            if done:
                self.notifier.noter.notes.rem(keys=keys)

            elif done is not None or route not in ('/multisig/rip', '/multisig/bup', '/multisig/rpy'):
                delete = input(f"\nDelete event [Y|n]? ")
                if delete in ("Y", "y"):
                    self.notifier.noter.notes.rem(keys=keys)

            yield self.tock

        self.remove(self.toRemove)

    def exit(self, deeds=None):
        """Close native storage on owner exit, after cancelling owned children.

        Removing individual doers also calls exit with an explicit deeds queue;
        that narrower cancellation must leave the shared TEL store open.
        """
        try:
            super().exit(deeds=deeds)
        finally:
            if deeds is None and getattr(self, 'saltWallet', None) is not None:
                self.saltWallet.close()
            if deeds is None and self.rgyV2 is not None and self.rgyV2.store.opened:
                self.rgyV2.close()

    def enableRegistrySalt(self):
        """Compose optional salt work once the selected group is actually accepted.

        Existing join still owns KEL admission and one parser/mailbox lifecycle.
        Current local GroupHab membership supplies recipient selection. No
        incoming request implies group approval or generates a private root.
        """
        hab = self.hby.habByName(self.group)
        if not isinstance(hab, GroupHab) or not hab.accepted:
            return  # initial group join is still responsible for admission
        if self.saltService is None:
            from ....app.credentialing import Wallet
            from ....app.registry_custody import RegistryCustody
            from ....app.registry_salt_service import RegistrySaltService, ROUTES
            from ....app.essring import EssrReplyHandler

            self.saltWallet = Wallet(self.hby, self.rgyV2)
            custody = RegistryCustody(self.hby, self.rgyV2, db=self.saltWallet.db)
            self.saltWallet.custody = custody
            self.saltService = RegistrySaltService(self.hby, self.rgyV2, custody, self.rvy)
            self.saltService.register()
            self.exc.addHandler(EssrReplyHandler(self.hby, hab.mhab, self.psr, ROUTES))

    def registryEscrowDo(self, tymth, tock=0.03125, **kwa):
        """Retry native TEL dependencies only while the join command is running."""
        yield tock
        while True:
            self.reverV2.processEscrows()
            if getattr(self, 'registrySalt', False):
                self.enableRegistrySalt()
                if self.saltService is not None:
                    self.rvy.processEscrowReply()
            yield tock

    def registry(self, attrs):
        """Approve a retained native rip or bup without authoring a credential.

        Args:
            attrs (dict): Notification route and authenticated proposal SAID.

        Returns:
            bool | None: True after the exact TEL event is accepted, False after
                a human decline, or None while accepted inception evidence is
                missing. Pending notifications remain available on the next run.
        """
        if self.rgyV2 is None:
            raise ConfigurationError('native registry approval requires --version 2.0')
        wrapper = self.hby.db.exns.get((attrs['d'],))
        if wrapper is None or wrapper.route != attrs['r']:
            raise ValidationError('native registry notification has no matching retained proposal')
        ghab = self.hby.habs.get(wrapper.sad['a']['gid'])
        approval = RegistryApproval(self.hby, self.rgyV2, ghab, self.exc,
                                    self.mux, self.psr, self.counselor)
        try:
            event, anchor, opening = approval.proposal(serializeMessage(self.hby, wrapper.said))
        except MissingRegistryError:
            print('Registry proposal pending: accepted inception evidence is unavailable.')
            return None

        regid = event.said if event.ilk == Ilks.rip else event.sad['rd']
        copies = wrapper.sad['a'].get('salts')
        custody = None
        if copies and ghab.mhab.pre in copies:
            from ....app.credentialing import Wallet
            from ....app.registry_custody import RegistryCustody
            if self.saltWallet is None:
                self.saltWallet = Wallet(self.hby, self.rgyV2)
            custody = RegistryCustody(self.hby, self.rgyV2, db=self.saltWallet.db)
            # Validate local decryption before human approval and KEL signing.
            custody.openRoot(copies[ghab.mhab.pre], ghab.mhab.kever.verfers[0])
        print(f'\nGroup registry {event.ilk} proposed for {ghab.name} ({ghab.pre}):')
        print(f'    Registry: {regid}')
        print(f"    TEL event: {event.said} at ordinal {event.sad['n']}")
        print(f'    Exact group anchor: {anchor.said}')
        if not self.auto and input('\nApprove exact TEL anchor [Y|n]? ') not in ('', 'y', 'Y'):
            return False

        # Borrow the existing group processors. Root custody and event openings
        # are not prerequisites for signing the exact proposed commitment.
        proposed, attachments = approval.approve(event, anchor, opening=opening,
                                                   salts=wrapper.sad['a'].get('salts'))
        deliveries = []
        deadline = time.monotonic() + self.timeout
        try:
            for member in self.hby.db.signingMembers(pre=ghab.pre):
                if member == ghab.mhab.pre:
                    continue
                poster = StreamPoster(hby=self.hby, hab=ghab.mhab, recp=member,
                                      topic='multisig', version=Vrsn_2_0)
                poster.send(proposed, attachment=attachments, gvrsn=Vrsn_2_0)
                children = poster.deliver()
                deliveries.extend(children)
                self.extend(children)
            while True:
                approval.process()
                accepted = self.rgyV2.store.seqEvent(regid, Number(numh=event.sad['n']).num)
                complete = accepted is not None and accepted.said == event.said
                delivered = all(child.done for child in deliveries)
                if complete and delivered:
                    break
                if time.monotonic() >= deadline:
                    if not complete:
                        print('Registry proposal pending: the exact TEL event is not accepted.')
                        return None
                    print('Some member deliveries did not complete before timeout.')
                    break
                yield self.tock
        finally:
            self.remove(deliveries)
        if custody is not None:
            custody.retainMemberCopy(regid, ghab, copies)
        print(f'Registry event {event.said} accepted.')
        return True

    def incept(self, attrs):
        """ Join a group multisig inception event

        """
        said = attrs["d"]
        exn, pathed = cloneMessage(self.hby, said=said)
        payload = exn.ked['a']

        smids = payload["smids"]
        rmids = payload["rmids"] if "rmids" in payload else None
        both = list(set(smids + (rmids or [])))

        mhab = None
        for mid in both:
            if mid in self.hby.habs:
                mhab = self.hby.habs[mid]
                break

        if mhab is None:
            print("Invalid multisig group inception request, aid list must contain a local identifier'")
            return False

        inits = dict()

        #original icp
        embeds = exn.ked['e']
        oicp = SerderKERI(sad=embeds["icp"])

        inits["version"] = oicp.pvrsn
        inits["kind"] = oicp.kind
        inits["isith"] = oicp.ked["kt"]
        inits["nsith"] = oicp.ked["nt"]

        inits["estOnly"] = TraitCodex.EstOnly in oicp.ked["c"]
        inits["DnD"] = TraitCodex.DoNotDelegate in oicp.ked["c"]

        inits["toad"] = oicp.ked["bt"]
        inits["wits"] = oicp.ked["b"]
        inits["delpre"] = oicp.ked["di"] if "di" in oicp.ked else None

        print()
        print("Group Multisig Inception proposed:")
        self.showEvent(mhab, both, oicp.ked)

        if self.auto:
            approve = True
        else:
            yn = input(f"\nJoin [Y|n]? ")
            approve = yn in ('', 'y', 'Y')

        if approve:
            if self.auto:
                if self.group is None:
                    group = "default-group"
                else:
                    group = self.group
            else:
                while True:
                    group = input(f"\nEnter group name for new AID: ")
                    if self.hby.habByName(group) is not None:
                        print(f"AID group name {group} is already in use, please try again")
                    else:
                        break

            try:
                ghab = self.hby.makeGroupHab(group=group, mhab=mhab,
                                             smids=smids, rmids=rmids, **inits)
            except ValueError as e:
                return False

            icp = ghab.msgOwnInception(allowPartiallySigned=True,
                                       gvrsn=self.version if self.version is not None else Version)

            exn, ims = multisigInceptExn(ghab.mhab,
                                         smids=ghab.smids,
                                         rmids=ghab.rmids,
                                         icp=icp,
                                         version=Vrsn_1_0,
                                         kind=oicp.kind)
            local = Parser(version=exn.pvrsn).parse(ims=bytearray(exn.raw + ims),
                                                    framed=True,
                                                    processive=False)[0]
            self.mux.exc.logEvent(serder=local.serder, pathed=local.ptds,
                                  tsgs=local.tsgs, cigars=local.cigars,
                                  essrs=local.essrs)
            self.mux.add(local.serder)
            others = list(oset(smids + (rmids or [])))

            others.remove(ghab.mhab.pre)

            for recpt in others:  # this goes to other participants only as a signaling mechanism
                self.postman.send(src=ghab.mhab.pre,
                                  dest=recpt,
                                  topic="multisig",
                                  serder=exn,
                                  attachment=ims, gvrsn=Vrsn_1_0)

                while not self.postman.sent(said=exn.said):
                    yield self.tock

                self.postman.cues.clear()

            prefixer = Prefixer(qb64=ghab.pre)
            number = Number(sn=0)
            diger = Diger(qb64=prefixer.qb64)
            yield from self.startCounselor(ghab, prefixer, number, diger)

            print()
            printIdentifier(self.hby, ghab.pre)

            return True

    def interact(self, attrs):
        said = attrs["d"]
        exn, pathed = cloneMessage(self.hby, said=said)
        payload = exn.ked['a']

        pre = payload["gid"]
        smids = payload["smids"]
        rmids = payload["rmids"] if "rmids" in payload else None

        embeds = exn.ked['e']
        # original ixn
        oixn = SerderKERI(sad=embeds["ixn"])
        data = oixn.ked['a']

        if pre not in self.hby.habs:
            print(f"Invalid multisig group interaction request {pre} not in Habs")
            return False

        ghab = self.hby.habs[pre]

        both = list(set(smids + (rmids or [])))

        if ghab.mhab.pre not in both:
            print(f"Local AID {ghab.mhab.pre} not a requested signer in {both}")
            return False

        print(f"Group Multisig Interaction for {ghab.name} ({ghab.pre}) proposed:")
        print(f"Data:")
        print(json.dumps(data, indent=2))

        if self.auto:
            approve = True
        else:
            yn = input(f"\nJoin [Y|n]? ")
            approve = yn in ('', 'y', 'Y')

        if approve:
            event_version = oixn.pvrsn
            ixn = ghab.interact(data=data, framed=True, version=event_version, gvrsn=event_version)
            serder = SerderKERI(raw=ixn)

            ixn = ghab.msgOwnEvent(allowPartiallySigned=True, sn=oixn.sn, framed=True, gvrsn=event_version)

            exn, ims = multisigInteractExn(ghab, aids=ghab.smids, ixn=ixn,
                                           version=Vrsn_1_0,
                                           kind=oixn.kind)
            local = Parser(version=exn.pvrsn).parse(ims=bytearray(exn.raw + ims),
                                                    framed=True,
                                                    processive=False)[0]
            self.mux.exc.logEvent(serder=local.serder, pathed=local.ptds,
                                  tsgs=local.tsgs, cigars=local.cigars,
                                  essrs=local.essrs)
            self.mux.add(local.serder)
            others = list(oset(smids + (rmids or [])))

            others.remove(ghab.mhab.pre)

            for recpt in others:  # this goes to other participants only as a signaling mechanism
                self.postman.send(src=ghab.mhab.pre,
                                  dest=recpt,
                                  topic="multisig",
                                  serder=exn,
                                  attachment=ims, gvrsn=Vrsn_1_0)

                while not self.postman.sent(said=exn.said):
                    yield self.tock

                self.postman.cues.clear()

            prefixer = Prefixer(qb64=ghab.pre)
            number = Number(sn=serder.sn)
            diger = Diger(qb64b=serder.saidb)
            yield from self.startCounselor(ghab, prefixer, number, diger)

            print()
            printIdentifier(self.hby, ghab.pre)

            return True

    def startCounselor(self, hab, prefixer, number, diger):
        self.counselor.start(prefixer=prefixer, number=number, diger=diger, ghab=hab)

        while True:
            saider = self.hby.db.cgms.get(keys=(prefixer.qb64, number.qb64))
            if saider is not None:
                break

            yield self.tock

    def showEvent(self, hab, mids, ked):
        print("Participants:")

        thold = Tholder(sith=ked["kt"])
        self.printMemberTable(mids, hab, thold)

        print()
        print("Configuration:")

        tab = PrettyTable()
        tab.field_names = ["Name", "Value"]
        tab.align["Name"] = "l"

        if "di" in ked:
            m = self.org.get(ked["di"])
            alias = m['alias'] if m else "Unknown Delegator"
            tab.add_row(["Delegator", f"{alias} ({ked['di']}))"])

        if not thold.weighted:
            tab.add_row(["Signature Threshold", thold.num])

        tab.add_row(["Establishment Only", TraitDex.EstOnly in ked["c"]])
        tab.add_row(["Do Not Delegate", TraitDex.DoNotDelegate in ked["c"]])
        tab.add_row(["Witness Threshold", ked["bt"]])
        tab.add_row(["Witnesses", "\n".join(ked["b"])])

        print(tab)

    def rotate(self, attrs):
        """ Rotate group multisig

        """
        said = attrs["d"]
        exn, pathed = cloneMessage(self.hby, said=said)

        payload = exn.ked['a']
        smids = payload["smids"]
        rmids = payload["rmids"]
        ked = exn.ked

        embeds = ked['e']
        orot = SerderKERI(sad=embeds["rot"])

        both = list(set(smids + (rmids or [])))

        mhab = None
        for mid in both:
            if mid in self.hby.habs:
                mhab = self.hby.habs[mid]
                break

        if mhab is None:
            print("Invalid multisig group rotation request, signing member list must contain a local identifier'")
            return False

        print()
        print("Group Multisig Rotation proposed:")
        self.showRotation(mhab, smids, rmids, orot.ked)

        if self.auto:
            approve = True
        else:
            yn = input(f"\nJoin [Y|n]? ")
            approve = yn in ('', 'y', 'Y')

        if approve:
            pre = orot.ked['i']
            if pre in self.hby.habs:
                ghab = self.hby.habs[pre]
            else:
                if self.auto:
                    if self.group is None:
                        group = "default-group"
                    else:
                        group = self.group
                else:
                    while True:
                        group = input(f"\nEnter group name for new AID: ")
                        if self.hby.habByName(group) is not None:
                            print(f"AID group name {group} is already in use, please try again")
                        else:
                            break

                ghab = self.hby.joinGroupHab(pre, group=group, mhab=mhab, smids=smids, rmids=rmids)

            try:
                ghab.rotate(serder=orot, smids=smids, rmids=rmids, framed=True, gvrsn=orot.pvrsn)
            except ValueError:
                return False

            rot = ghab.msgOwnEvent(allowPartiallySigned=True, sn=orot.sn, gvrsn=orot.pvrsn)

            exn, ims = multisigRotateExn(ghab,
                                         smids=ghab.smids,
                                         rmids=ghab.rmids,
                                         rot=rot,
                                         version=Vrsn_1_0,
                                         kind=orot.kind)
            local = Parser(version=exn.pvrsn).parse(ims=bytearray(exn.raw + ims),
                                                    framed=True,
                                                    processive=False)[0]
            self.mux.exc.logEvent(serder=local.serder, pathed=local.ptds,
                                  tsgs=local.tsgs, cigars=local.cigars,
                                  essrs=local.essrs)
            self.mux.add(local.serder)
            others = list(oset(smids + (rmids or [])))

            others.remove(ghab.mhab.pre)

            for recpt in others:  # this goes to other participants only as a signaling mechanism
                self.postman.send(src=ghab.mhab.pre,
                                  dest=recpt,
                                  topic="multisig",
                                  serder=exn,
                                  attachment=ims, gvrsn=Vrsn_1_0)

                while not self.postman.sent(said=exn.said):
                    yield self.tock

                self.postman.cues.clear()

            serder = SerderKERI(raw=rot)
            prefixer = Prefixer(qb64=ghab.pre)
            number = Number(sn=serder.sn)

            yield from self.startCounselor(ghab, prefixer, number, Diger(qb64=serder.said))

            print()
            printIdentifier(self.hby, ghab.pre)

            return True

    def showRotation(self, hab, smids, rmids, ked):
        print()
        print("Signing Members")
        thold = Tholder(sith=ked["kt"])
        self.printMemberTable(smids, hab, thold)

        print()
        print("Rotation Members")
        nthold = Tholder(sith=ked["nt"])
        self.printMemberTable(rmids, hab, nthold)

        print()
        print("Configuration:")

        tab = PrettyTable()
        tab.field_names = ["Name", "Value"]
        tab.align["Name"] = "l"

        if "di" in ked:
            m = self.org.get(ked["di"])
            alias = m['alias'] if m else "Unknown Delegator"
            tab.add_row(["Delegator", f"{alias} ({ked['di']}))"])

        if not thold.weighted:
            tab.add_row(["Signature Threshold", thold.num])

        tab.add_row(["Witness Threshold", ked["bt"]])
        if "ba" in ked and ked["ba"]:
            tab.add_row(["Added Witnesses", "\n".join(ked["ba"])])
        if "br" in ked and ked["br"]:
            tab.add_row(["Removed Witnesses", "\n".join(ked["br"])])

        print(tab)

    def printMemberTable(self, mids, hab, thold):
        tab = PrettyTable()
        fields = ["Local", "Name", "AID"]

        if thold.weighted:
            fields.append("Threshold")

        tab.field_names = fields
        tab.align["Name"] = "l"

        for idx, mid in enumerate(mids):
            if mid == hab.pre:
                row = ["*", hab.name, hab.pre]
                if thold.weighted:
                    row.append(thold.sith[idx])

                tab.add_row(row)
            else:
                m = self.org.get(mid)
                alias = m['alias'] if m else "Unknown Participant"
                row = [" ", alias, mid]
                if thold.weighted:
                    row.append(thold.sith[idx])
                tab.add_row(row)

        print(tab)

    def rpy(self, attrs):
        """  Handle reply messages

        Parameters:
            attrs (dict): attributes of the reply message

        Returns:
            bool: True when the reply is approved and processed, otherwise False
            """
        said = attrs["d"]
        retained = self.hby.db.exns.get(keys=said)
        if retained is not None and retained.pvrsn == Vrsn_2_0:
            return (yield from self.rpyV2(attrs))
        exn, pathed = cloneMessage(self.hby, said=said)

        sender = exn.ked['i']
        payload = exn.ked['a']
        gid = payload["gid"]
        hab = self.hby.habs[gid] if gid in self.hby.habs else None
        if hab is None:
            raise ValueError(f"credential issuer not a valid AID={gid}")

        contact = self.org.get(sender)
        senderAlias = contact['alias']

        embeds = exn.ked['e']
        rpy = embeds['rpy']
        cid = rpy['a']['cid']
        eid = rpy['a']['eid']
        role = rpy['a']['role']

        if cid == gid:
            controller = hab.name
        else:
            raise ValueError(f"Endpoint role authorization request for wrong controller {gid} != {cid}")

        endpoint = self.org.get(eid)
        if endpoint is None or 'alias' not in endpoint:
            endpointAlias = "Unknown Endpoint"
        else:
            endpointAlias = endpoint['alias']

        print(f"\nEndpoint Role Authorization (from {senderAlias}):")
        print(f"    Controller: {controller} ({cid})")
        print(f"    Role: {role.capitalize()}")
        print(f"    Endpoint Provider: {endpointAlias} ({eid})")

        if self.auto:
            approve = True
        else:
            yn = input(f"\nApprove [Y|n]? ")
            approve = yn in ('', 'y', 'Y')

        if approve:
            # Create and parse the event with "their" signatures
            rserder = SerderKERI(sad=rpy)
            anc = bytearray(rserder.raw) + pathed["rpy"]
            self.psr.parseOne(ims=bytes(anc))

            # Now sign the event and parse it with our signatures
            anc = hab.endorse(rserder, framed=False,
                              gvrsn=rserder.gvrsn or rserder.pvrsn)
            self.psr.parseOne(ims=bytes(anc))

            smids = hab.db.signingMembers(pre=hab.pre)
            smids.remove(hab.mhab.pre)

            for recp in smids:  # this goes to other participants only as a signaling mechanism
                exn, atc = multisigRpyExn(ghab=hab, rpy=anc,
                                          version=Vrsn_1_0,
                                          kind=rserder.kind)
                self.postman.send(src=hab.mhab.pre,
                                  dest=recp,
                                  topic="multisig",
                                  serder=exn,
                                  attachment=atc, gvrsn=Vrsn_1_0)

            while not hab.loadEndRole(cid=cid, role=role, eid=eid):
                self.rgy.processEscrows()
                self.rvy.processEscrowReply()
                yield self.tock

            print(f"End role authorization added for role {role}")
            return True

        return False

    def rpyV2(self, attrs):
        """Approve an exact retained v2 endpoint reply through existing group owners.

        Parameters: attrs identifies the retained /multisig/rpy notification.
        Returns: True after exact endpoint acceptance and finite fanout, False
            after decline, or None for unsupported policy or pending acceptance.
        Raises: ValidationError for invalid wrapper, group or endpoint semantics.
            Unsupported domain routes receive no prompt or local signature.
        """
        wrapper = self.hby.db.exns.get(keys=attrs['d'])
        if wrapper is None or wrapper.route != attrs['r']:
            raise ValidationError('reply notification has no matching retained proposal')
        hab = self.hby.habs.get(wrapper.sad['a'].get('gid'))
        if not isinstance(hab, GroupHab):
            raise ValidationError('reply proposal requires a local group')
        if getattr(self, 'saltService', None) is not None:
            from ....app.registry_salt_service import ROUTES
            from ....peer.exchanging import loadParsedNestedSubstreams

            children = loadParsedNestedSubstreams(self.hby, wrapper.said)
            if len(children) == 1 and children[0].serder.route in ROUTES:
                return (yield from self.rpySalt(wrapper.said))

        def validateEndpoint(serder):
            """Validate the installed endpoint policy before prompt and before signing."""
            if serder.route != '/end/role/add':
                raise ConfigurationError('reply domain policy is not installed')
            data = serder.sad['a']
            if not isinstance(data, dict) or not {'cid', 'role', 'eid'} <= set(data):
                raise ValidationError('endpoint reply is missing controller, role or endpoint')
            try:
                if (Prefixer(qb64=data['cid']).qb64 != data['cid']
                        or Prefixer(qb64=data['eid']).qb64 != data['eid']
                        or data['cid'] != hab.pre or data['role'] not in Roles):
                    raise ValueError
            except (KeriError, ValueError, TypeError):
                raise ValidationError('endpoint reply has invalid controller, role or endpoint') from None

        try:
            child = replyProposal(self.hby, self.exc, self.mux, wrapper.said,
                ghab=hab, validate=validateEndpoint)
        except ConfigurationError:
            print('Reply proposal pending: its domain approval policy is unavailable.')
            return None
        data = child.serder.sad['a']
        cid, role, eid = data['cid'], data['role'], data['eid']
        contact = self.org.get(wrapper.pre) or {}
        endpoint = self.org.get(eid) or {}
        print(f"\nEndpoint Role Authorization (from {contact.get('alias', wrapper.pre)}):")
        print(f'    Controller: {hab.name} ({cid})')
        print(f'    Role: {role.capitalize()}')
        print(f"    Endpoint Provider: {endpoint.get('alias', 'Unknown Endpoint')} ({eid})")
        establishment = hab.kever.lastEst.d
        if not self.auto and input('\nApprove exact endpoint reply [Y|n]? ') not in ('', 'y', 'Y'):
            return False

        # Approval applies to the signing establishment presented for review.
        if hab.kever.lastEst.d != establishment:
            raise ValidationError('group establishment changed during reply approval')

        signed, proposal, attachments = endorseReply(self.hby, hab, child,
            validate=validateEndpoint)
        self.psr.parse(ims=bytearray(signed), local=True)
        self.psr.parse(ims=bytearray(proposal.raw + attachments), local=True)
        deliveries = []
        deadline = time.monotonic() + self.timeout
        try:
            for member in hab.smids:
                if member == hab.mhab.pre:
                    continue
                poster = StreamPoster(hby=self.hby, hab=hab.mhab, recp=member,
                                      topic='multisig', version=Vrsn_2_0)
                poster.send(proposal, attachment=attachments, gvrsn=Vrsn_2_0)
                children = poster.deliver()
                deliveries.extend(children)
                self.extend(children)
            while True:
                self.rvy.processEscrowReply()
                accepted = self.hby.db.eans.get(keys=(cid, role, eid))
                complete = (accepted is not None and accepted.qb64 == child.serder.said
                            and hab.loadEndRole(cid=cid, role=role, eid=eid))
                if complete and all(delivery.done for delivery in deliveries):
                    break
                if time.monotonic() >= deadline:
                    if not complete:
                        print('Reply proposal pending: the exact endpoint reply is not accepted.')
                        return None
                    print('Some member deliveries did not complete before timeout.')
                    break
                yield self.tock
        finally:
            self.remove(deliveries)
        print(f'End role authorization added for role {role}')
        return True

    def rpySalt(self, said):
        """Approve one encrypted salt reply through the existing group reply flow.

        said identifies a retained multisig/rpy proposal. The member signs the
        exact displayed reply and shares its contribution with current members.
        Completion here means local approval and member submission, not recipient
        custody or completed group signature collection.
        """
        hab = self.hby.habByName(self.group)
        child = replyProposal(self.hby, self.exc, self.mux, said,
                              ghab=hab, validate=self.saltService.validate)
        body = child.serder
        print(f'\nRegistry salt reply: {body.said}\n    Group: {body.pre}')
        for key in ('registry', 'recipient', 'target'):
            print(f'    {key}: {body.sad["a"][key]}')
        establishment = hab.kever.lastEst.d
        if not self.auto and input('\nApprove this exact encrypted salt reply [Y|n]? ') not in ('', 'y', 'Y'):
            return False
        if hab.kever.lastEst.d != establishment:
            raise ValidationError('group establishment changed during reply approval')
        signed, proposal, attachments = endorseReply(self.hby, hab, child,
                                                      validate=self.saltService.validate)
        self.psr.parse(ims=bytearray(signed), local=True)
        self.psr.parse(ims=bytearray(proposal.raw + attachments), local=True)
        children = []
        proposer = self.hby.db.exns.get((said,)).pre
        returning = []
        deadline = time.monotonic() + self.timeout
        try:
            for member in hab.smids:
                if member == hab.mhab.pre:
                    continue
                if not ({Roles.controller, Roles.agent, Roles.mailbox, Roles.witness}
                        & set(hab.mhab.endsFor(member))):
                    if member == proposer:
                        raise ConfigurationError('registry salt proposer has no delivery route')
                    continue
                poster = StreamPoster(hby=self.hby, hab=hab.mhab, recp=member,
                                      topic='multisig', version=Vrsn_2_0)
                poster.send(proposal, attachment=attachments, gvrsn=Vrsn_2_0)
                pending = poster.deliver() or []
                if member == proposer:
                    returning.extend(pending)
                children.extend(pending)
                self.extend(pending)
            if not returning:
                raise ConfigurationError('registry salt proposer has no delivery route')
            # Return the cosignature to the proposer before closing finite I/O.
            # An unavailable optional member is not an additional quorum requirement.
            while not all(child.done for child in returning):
                if time.monotonic() >= deadline:
                    raise TimeoutError('registry salt member submission timed out')
                yield self.tock
            if any(getattr(child, 'error', None) is not None for child in returning):
                raise ConfigurationError('registry salt member submission failed')
        finally:
            self.remove(children)
        print(f'Approved registry salt reply: {body.said}; recipient acceptance is separate.')
        return True

    def vcp(self, attrs):
        """  Handle issue messages

        Parameters:
            attrs (dict): attributes of the reply message

        Returns:
            bool: True when the registry creation is approved and processed,
                otherwise False
            """
        said = attrs["d"]
        exn, pathed = cloneMessage(self.hby, said=said)

        sender = exn.ked['i']
        payload = exn.ked['a']
        usage = payload["usage"]
        gid = payload["gid"]
        hab = self.hby.habs[gid] if gid in self.hby.habs else None
        if hab is None:
            raise ValueError(f"credential issuer not a valid AID={gid}")

        contact = self.org.get(sender)
        senderAlias = contact['alias']

        embeds = exn.ked['e']
        print(f"\nGroup Credential Regitry Creation (from {senderAlias}):")
        print(f"Usage: {usage}:\n")

        if self.auto:
            approve = True
        else:
            yn = input(f"\nApprove [Y|n]? ")
            approve = yn in ('', 'y', 'Y')

        if approve:
            # Create and parse the event with "their" signatures
            registryName = input("Name for Registry: ")
            anc = embeds["anc"]
            aserder = SerderKERI(sad=anc)
            anc = bytearray(aserder.raw) + pathed["anc"]
            self.psr.parseOne(ims=bytes(anc))

            # Now sign the event and parse it with our signatures
            sigers = hab.sign(aserder.raw)
            anc = messagize(serder=aserder, sigers=sigers, framed=True)
            self.psr.parseOne(ims=bytes(anc))

            vcp = embeds["vcp"]
            vserder = SerderKERI(sad=vcp)
            try:
                self.rgy.tvy.processEvent(serder=vserder)
            except MissingAnchorError:
                pass

            self.rgy.makeRegistry(name=registryName, prefix=hab.pre, vcp=vserder)
            self.registrar.incept(vserder, aserder)

            smids = hab.db.signingMembers(pre=hab.pre)
            smids.remove(hab.mhab.pre)

            for recp in smids:  # this goes to other participants only as a signaling mechanism
                exn, atc = multisigRegistryInceptExn(
                    ghab=hab,
                    vcp=vserder.raw,
                    anc=anc,
                    usage=usage,
                    version=Vrsn_1_0,
                    kind=vserder.kind,
                )
                self.postman.send(src=hab.mhab.pre,
                                  dest=recp,
                                  topic="multisig",
                                  serder=exn,
                                  attachment=atc, gvrsn=Vrsn_1_0)

            while not self.registrar.complete(vserder.pre, sn=0):
                self.rgy.processEscrows()
                self.verifier.processEscrows()
                yield self.tock

            print(f"Registry {vserder.pre} created.")
            return True

        return False

    def iss(self, attrs):
        """  Handle issue messages

        Parameters:
            attrs (dict): attributes of the reply message

        Returns:
            bool: True when the credential issuance is approved and processed,
                otherwise False
            """
        said = attrs["d"]
        exn, pathed = cloneMessage(self.hby, said=said)

        sender = exn.ked['i']

        contact = self.org.get(sender)
        senderAlias = contact['alias']

        embeds = exn.ked['e']
        acdc = embeds["acdc"]
        schema = acdc['s']
        scraw = self.verifier.resolver.resolve(schema)
        if not scraw:
            raise ConfigurationError("Credential schema {} not found".format(schema))

        schemer = Schemer(raw=scraw)

        issr = acdc["i"]
        hab = self.hby.habs[issr] if issr in self.hby.habs else None
        if hab is None:
            raise ValueError(f"credential issuer not a valid AID={issr}")

        print(f"\nGroup Credential Issuance Proposed (from {senderAlias}):")
        print(f"Credential {acdc['d']}:")
        print(f"    Type: {schemer.sed['title']}")
        print(f"    Issued By: {hab.name} ({hab.pre})")

        if "i" in acdc["a"]:
            isse = acdc['a']['i']
            contact = self.org.get(isse)
            if contact is not None and "alias" in contact:
                print(f"    Issued To: {contact['alias']} ({isse})")
            else:
                print(f"    Issued To: Unknown AID ({isse})")

        print("    Data:")
        for k, v in acdc['a'].items():
            if k not in ('d', 'i'):
                print(f"        {k}: {v}")

        if self.auto:
            approve = True
        else:
            yn = input(f"\nApprove [Y|n]? ")
            approve = yn in ('', 'y', 'Y')

        if approve:
            # Create and parse the event with "their" signatures
            anc = embeds["anc"]
            aserder = SerderKERI(sad=anc)
            anc = bytearray(aserder.raw) + pathed["anc"]
            self.psr.parseOne(ims=bytes(anc))

            # Now sign the event and parse it with our signatures
            sigers = hab.sign(aserder.raw)
            anc = messagize(serder=aserder, sigers=sigers, framed=True)
            self.psr.parseOne(ims=bytes(anc))

            iss = embeds["iss"]
            iserder = SerderKERI(sad=iss)
            try:
                self.rgy.tvy.processEvent(serder=iserder)
            except MissingAnchorError:
                pass

            acdc = embeds["acdc"]
            creder = SerderACDC(sad=acdc)
            acdc = bytearray(creder.raw) + pathed["acdc"]
            self.psr.parseOne(ims=bytes(acdc))

            self.credentialer.issue(creder, iserder)
            self.registrar.issue(creder, iserder, aserder)

            smids = hab.db.signingMembers(pre=hab.pre)
            smids.remove(hab.mhab.pre)

            for recp in smids:  # this goes to other participants only as a signaling mechanism
                exn, atc = multisigIssueExn(
                    ghab=hab,
                    acdc=acdc,
                    iss=iserder.raw,
                    anc=anc,
                    version=Vrsn_1_0,
                    kind=iserder.kind,
                )
                self.postman.send(src=hab.mhab.pre,
                                  dest=recp,
                                  topic="multisig",
                                  serder=exn,
                                  attachment=atc, gvrsn=Vrsn_1_0)

            while not self.credentialer.complete(said=creder.said):
                self.rgy.processEscrows()
                self.verifier.processEscrows()
                yield self.tock

            print(f"Credential {creder.said} complete.")
            return True

        return False

    def rev(self, attrs):
        """  Handle revocation messages

        Parameters:
            attrs (dict): attributes of the reply message

        Returns:
            bool | None: True when the revocation is approved and processed,
                False when declined, or None when the credential SAID is invalid
            """
        said = attrs["d"]
        exn, pathed = cloneMessage(self.hby, said=said)

        sender = exn.ked['i']
        payload = exn.ked['a']
        said = payload['said']

        creder = self.verifier.reger.creds.get(keys=(said,))
        if creder is None:
            print(f"invalid credential SAID {said}")
            return

        contact = self.org.get(sender)
        senderAlias = contact['alias']

        embeds = exn.ked['e']
        scraw = self.verifier.resolver.resolve(creder.schema)
        if not scraw:
            raise ConfigurationError("Credential schema {} not found".format(creder.schema))

        schemer = Schemer(raw=scraw)

        hab = self.hby.habs[creder.israid]
        if hab is None:
            raise ValueError(f"credential issuer not a valid AID={creder.israid}")

        print(f"\nGroup Credential Revocation Proposed (from {senderAlias}):")
        print(f"Credential {creder.said}:")
        print(f"    Type: {schemer.sed['title']}")
        print(f"    Issued By: {hab.name} ({hab.pre})")

        # Resolve via .iseaid so an aggregate ('acg') credential names its issuee here too (#1529).
        isse = creder.iseaid
        if isse is not None:
            contact = self.org.get(isse)
            if contact is not None and "alias" in contact:
                print(f"    Issued To: {contact['alias']} ({isse})")
            else:
                print(f"    Issued To: Unknown AID ({isse})")

        if self.auto:
            approve = True
        else:
            yn = input(f"\nApprove Revocation [Y|n]? ")
            approve = yn in ('', 'y', 'Y')

        if approve:
            # Create and parse the event with "their" signatures
            anc = embeds["anc"]
            aserder = SerderKERI(sad=anc)
            anc = bytearray(aserder.raw) + pathed["anc"]
            self.psr.parseOne(ims=bytes(anc))

            # Now sign the event and parse it with our signatures
            sigers = hab.sign(aserder.raw)
            anc = messagize(serder=aserder, sigers=sigers, framed=True)
            self.psr.parseOne(ims=bytes(anc))

            rev = embeds["rev"]
            rserder = SerderKERI(sad=rev)
            try:
                self.rgy.tvy.processEvent(serder=rserder)
            except MissingAnchorError:
                pass

            self.registrar.revoke(creder, rserder, aserder)

            smids = hab.db.signingMembers(pre=hab.pre)
            smids.remove(hab.mhab.pre)

            for recp in smids:  # this goes to other participants only as a signaling mechanism
                exn, atc = multisigRevokeExn(
                    ghab=hab,
                    said=creder.said,
                    rev=rserder.raw,
                    anc=anc,
                    version=Vrsn_1_0,
                    kind=rserder.kind,
                )
                self.postman.send(src=hab.mhab.pre,
                                  dest=recp,
                                  topic="multisig",
                                  serder=exn,
                                  attachment=atc, gvrsn=Vrsn_1_0)

            while not self.registrar.complete(creder.said, sn=1):
                self.rgy.processEscrows()
                yield self.tock

            print(f"Credential {creder.said} revoked.")
            # Same resolution for the issuee this revocation is streamed to (#1529).
            recp = creder.iseaid
            if hab.witnesser() and recp is not None:
                msgs = []
                for msg in self.hby.db.clonePreIter(pre=creder.israid):
                    serder = SerderKERI(raw=msg)
                    atc = msg[serder.size:]
                    msgs.append((serder, atc))
                for msg in self.rgy.reger.clonePreIter(pre=creder.said):
                    serder = SerderKERI(raw=msg)
                    atc = msg[serder.size:]
                    msgs.append((serder, atc))

                for (serder, atc) in msgs:
                    self.postman.send(src=hab.mhab.pre, dest=recp, topic="credential", serder=serder,
                                      attachment=atc)

                last = msgs[-1][0]
                while not self.postman.sent(said=last.said):
                    yield self.tock

            return True

        return False
