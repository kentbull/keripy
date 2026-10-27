import argparse

from hio.base import doing
from hio.help import ogler

from ....common import Parsery, setupHby
from ....common import acdc_v2

from .....app import (GroupHab, Notifier, MailboxDirector,
                      HaberyDoer, Multiplexor, Counselor,
                      Poster, multisigRegistryInceptExn)
from .....app.grouping import loadHandlers

from .....kering import Vrsn_1_0
from .....core import SerderKERI, SealEvent
from .....peer import Exchanger
from .....vdr import Regery, Registrar


logger = ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a new credential registry',
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: registryIncept(args))
parser.add_argument('--registry-name', '-r', help='Human readable name for registry, defaults to name of Habitat',
                    default=None)
parser.add_argument('--nonce', help='Unique random value to seed the credential registry',
                    default=None, required=False)
parser.add_argument("--no-backers", "-nb", help="do not allow setting up backers different from the anchoring KEL "
                                                "witnesses", default=True, action="store")
parser.add_argument('--backers', help='New set of backers different from the anchoring KEL witnesses.  Can '
                                      'appear multiple times', metavar="<prefix>", default=[], action="append",
                    required=False)
parser.add_argument("--establishment-only", "-eo", help="Only allow establishment events for the anchoring events of "
                                                        "this registry", default=False, action="store")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--usage', '-u', help='For multisig issuers, a message to other participants about how this'
                                          ' registry is to be used',
                    default=None)
acdc_v2.options(parser, author=True)
parser.add_argument('--discloser', help='ACDC v2 registry designated disclosure identifier', default=None)
parser.add_argument('--with-custody', action='store_true',
                    help='explicitly provision encrypted per-registry derivation custody (ACDC v2 only)')


def registryIncept(args):
    """Select ACDC v2 registry authoring or the established legacy inception worker.

    args supplies controller alias, registry name, witnesses/backers and CLI policy.
    Return lifecycle Doers; ACDC v2 custody is provisioned only with --with-custody.
    The legacy conflicting no-backers/backers check retains its printed error and
    -1 return. Core authoring/authentication failures propagate from scheduled work."""
    if getattr(args, 'acdc_v2', False):
        return [acdc_v2.AcdcV2Author(args, 'incept')]
    name = args.name
    alias = args.alias
    bran = args.bran
    base = args.base
    registryName = args.registry_name if args.registry_name is not None else alias
    nonce = args.nonce
    estOnly = args.establishment_only
    noBackers = args.no_backers
    backers = args.backers
    usage = args.usage

    if noBackers and backers:
        print("--no-backers and --backers can not both be provided")
        return -1

    icpDoer = RegistryInceptor(name=name, base=base, alias=alias, bran=bran, registryName=registryName,
                               nonce=nonce, estOnly=estOnly, noBackers=noBackers, baks=backers, usage=usage)

    doers = [icpDoer]
    return doers


class RegistryInceptor(doing.DoDoer):
    """ Creates a registry

    """

    def __init__(self, name, base, alias, bran, registryName, nonce, estOnly, noBackers, baks, usage, toad=None, vcp=None, **kwa):
        """Open and schedule legacy registry inception for an existing local alias.

        Args:
            name (str): Habery and shared database name.
            base (str): Optional environment path namespace.
            alias (str): Existing identifier to control the registry.
            bran (str): Keeper authentication passcode material.
            registryName (str): Human-readable name of the new registry.
            nonce (str): Unique nonce used in registry construction.
            estOnly (bool): Anchor registry events in establishment events only.
            noBackers (bool): Disallow registry backers distinct from witnesses.
            baks (list): Explicit registry backers when permitted.
            usage (str): Optional group proposal description.
            toad (str | None): Hexadecimal registry backer threshold.
            vcp (Serder | None): Existing inception event for group participation.
            **kwa: Additional caller options, unused here.

        Return None, owning Habery, Regery and scheduled protocol work. Missing
        alias raises ValueError after closing the new Habery; identity,
        configuration and core validation errors otherwise propagate. Local and
        receipt/mailbox parsers follow the established alias protocol version.
        """
        self.name = name
        self.alias = alias
        self.registryName = registryName
        self.nonce = nonce
        self.estOnly = estOnly
        self.noBackers = noBackers
        self.baks = baks
        self.usage = usage
        self.toad = toad
        self.vcp = vcp
        self.hby = setupHby(name=name, base=base, bran=bran)
        selected = self.hby.habByName(alias)
        if selected is None:
            self.hby.close()
            raise ValueError(f'{alias} is not a valid AID alias')
        self.hby.version = selected.kever.serder.pvrsn
        self.hby.psr.version = self.hby.version
        self.rgy = Regery(hby=self.hby, name=name, base=base)
        self.hbyDoer = HaberyDoer(habery=self.hby)  # setup doer
        counselor = Counselor(hby=self.hby)
        self.postman = Poster(hby=self.hby)

        notifier = Notifier(self.hby)
        mux = Multiplexor(self.hby, notifier=notifier)
        exc = Exchanger(hby=self.hby, handlers=[])
        loadHandlers(exc, mux)

        mbx = MailboxDirector(hby=self.hby, topics=["/receipt", "/multisig", "/replay"], exc=exc, version=self.hby.version)
        self.registrar = Registrar(hby=self.hby, rgy=self.rgy, counselor=counselor)
        doers = [self.hbyDoer, counselor, self.registrar, self.postman, mbx]
        self.toRemove = list(doers)

        doers.extend([doing.doify(self.inceptDo, **kwa)])
        super(RegistryInceptor, self).__init__(doers=doers)

    def inceptDo(self, tymth, tock=0.0, **kwa):
        """Incept and witness a registry using its established protocol version.

        tymth/tock are HIO clock/delay inputs; additional scheduler arguments
        are unused. Yield cooperative scheduling delays while the ordinary
        registrar and witness receipt processors complete accepted work.
        Return None after completion. Core validation, authentication and
        transport errors propagate. Anchors and receipt parsing explicitly
        follow the selected registry/habitat version and serialization kind;
        no library-wide version default changes.
        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        hab = self.hby.habByName(self.alias)
        if hab is None:
            raise ValueError(f"{self.alias} is not a valid AID alias")

        registry_kwa = {
            'nonce': self.nonce,
            'noBackers': self.noBackers,
            'baks': self.baks,
            'estOnly': self.estOnly,
            'toad': self.toad,
            'vcp': self.vcp
        }
        registry = self.rgy.makeRegistry(name=self.registryName, prefix=hab.pre, **registry_kwa)

        rseal = SealEvent(registry.regk, "0", registry.regd)
        rseal = dict(i=rseal.i, s=rseal.s, d=rseal.d)
        if self.estOnly:
            anc = hab.rotate(data=[rseal], framed=True,
                             version=registry.versionSerder.pvrsn, kind=registry.versionSerder.kind)
        else:
            anc = hab.interact(data=[rseal], framed=True,
                               version=registry.versionSerder.pvrsn, kind=registry.versionSerder.kind)

        aserder = SerderKERI(raw=bytes(anc))
        self.registrar.incept(iserder=registry.vcp, anc=aserder)

        if isinstance(hab, GroupHab):
            usage = self.usage
            if usage is None:
                usage = input(f"Please enter a description of the credential registry: ")

            smids = hab.db.signingMembers(pre=hab.pre)
            smids.remove(hab.mhab.pre)

            for recp in smids:  # this goes to other participants only as a signaling mechanism
                exn, atc = multisigRegistryInceptExn(ghab=hab, vcp=registry.vcp.raw, anc=anc, usage=usage,
                                                     version=Vrsn_1_0)
                self.postman.send(src=hab.mhab.pre,
                                  dest=recp,
                                  topic="multisig",
                                  serder=exn,
                                  attachment=atc)

        while not self.registrar.complete(pre=registry.regk, sn=0):
            self.rgy.processEscrows()
            yield self.tock

        print("Registry:  {}({}) \n\tcreated for Identifier Prefix:  {}".format(self.registryName,
                                                                                registry.regk, hab.pre))

        self.remove(self.toRemove)
