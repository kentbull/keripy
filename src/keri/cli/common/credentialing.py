"""Create a public v2 ACDC credential body without issuing a registry event."""
import json
from pathlib import Path

from hio.base import doing

from . import setupHby
from ... import Vrsn_2_0
from ...acdc import Regery, acdcmap, acdcatt, acdcagg, scheming, regeventing
from ...app import Keeper, Organizer
from ...core import Prefixer, Saider, SerderACDC
from ...kering import ConfigurationError, KeriError


def load(value):
    """Read an explicit JSON value or @file; constructors own ACDC encoding."""
    return json.loads(Path(value[1:]).read_text() if value.startswith('@') else value)


def recipient(hby, value):
    """Resolve a local/contact alias or require one complete canonical AID."""
    if not value:
        raise ConfigurationError('v2 ACDC body creation requires --recipient')
    try:
        literal = Prefixer(qb64=value)
    except (KeriError, ValueError):
        literal = None
    if literal is not None:
        if literal.qb64 != value:
            raise ConfigurationError('recipient must be one complete canonical AID')
        return value
    if hab := hby.habByName(value):
        value = hab.pre
    else:
        contacts = Organizer(hby=hby).findExact('alias', value)
        if len(contacts) > 1:
            raise ConfigurationError('recipient alias is ambiguous; use its AID')
        if contacts:
            value = contacts[0]['id']
    if Prefixer(qb64=value).qb64 != value:
        raise ConfigurationError('recipient must be one complete canonical AID')
    return value


class AcdcV2Credential(doing.Doer):
    """Own one unsigned public-body output using existing issuer/registry state.

    Schema policy and commitments belong to ordinary constructors/validators.
    An accepted GroupHab can name its issuer without signing or root custody.
    This action creates no credential inventory, BUP, opening or Admit.
    """
    def __init__(self, args):
        self.args = args
        super().__init__()

    def recur(self, tyme):
        args = self.args
        if not args.output or Path(args.output).exists():
            raise ConfigurationError('--output must name a new public body file')
        if args.private or args.private_credential_nonce or args.private_subject_nonce or args.time:
            raise ConfigurationError('v2 ACDC public body creation does not use legacy private/time options')
        if (args.data is None) == (args.credential is None):
            raise ConfigurationError('provide exactly one of --data or --credential')
        if not args.registry_name:
            raise ConfigurationError('v2 ACDC body creation requires --registry-name')
        # Like schema import, preserve existing AEID policy even with a global passcode.
        keeper = Keeper(name=args.name, base=args.base, reopen=True)
        try:
            aeid = keeper.gbls.get('aeid')
            if aeid is None:
                raise ConfigurationError('v2 ACDC body creation requires an existing Keeper')
        finally:
            keeper.close()
        bran = args.bran if aeid else None
        hby = setupHby(name=args.name, base=args.base, bran=bran, noPrompt=bool(bran), version=Vrsn_2_0)
        rgy = None
        try:
            hab = hby.habByName(args.alias)
            if hab is None or not hab.accepted:
                raise ConfigurationError('issuer must be an accepted local alias')
            issuee = recipient(hby, args.recipient)
            rgy = Regery(hby=hby, name=args.name, base=args.base)
            reg = rgy.registryByName(args.registry_name)
            rip = rgy.store.seqEvent(reg.regk, 0) if reg is not None else None
            if rip is None or rip.israid != hab.pre:
                raise ConfigurationError('selected registry requires an accepted RIP owned by this issuer')
            regeventing.vetAnchor(rip, db=hby.db, issuer=hab.pre)
            if args.credential is not None:
                if any(value is not None for value in (args.ilk, args.schema, args.edges, args.rules)):
                    raise ConfigurationError('--credential cannot be combined with body construction options')
                body = SerderACDC(sad=load(args.credential))
            else:
                payload, ilk = load(args.data), args.ilk or 'acm'
                schema = args.schema
                if schema is not None:
                    if Saider(qb64=schema).qb64 != schema or hby.db.schema.get(schema) is None:
                        raise ConfigurationError('--schema must name one complete, already imported schema SAID')
                kwa = dict(israid=hab.pre, regid=reg.regk, schema=schema,
                           edge=load(args.edges) if args.edges is not None else None,
                           rule=load(args.rules) if args.rules is not None else None)
                if ilk == 'acg':
                    if not isinstance(payload, list):
                        raise ConfigurationError('acg --data must be a v2 ACDC aggregate section list')
                    body = acdcagg(aggregate=payload, **kwa)
                else:
                    if not isinstance(payload, dict) or payload.get('i', issuee) != issuee:
                        raise ConfigurationError('--data must be an attribute map matching --recipient')
                    build = acdcmap if ilk == 'acm' else acdcatt
                    body = build(attribute=payload, iseaid=issuee, **kwa)
            if (body.pvrsn != Vrsn_2_0 or body.ilk not in ('acm', 'act', 'acg') or not body.verify()
                    or body.israid != hab.pre or body.regid != reg.regk or body.iseaid != issuee):
                raise ConfigurationError('verified v2 ACDC body must match the selected issuer, registry and recipient')
            scheming.validateSchema(body, hby.db)
            with Path(args.output).open('xb') as output:
                output.write(body.raw)
            print(json.dumps(dict(credential=body.said, issuer=body.israid, registry=body.regid,
                                  recipient=body.iseaid, body_created=True, registry_issued=False, admitted=False)))
            return True
        finally:
            if rgy is not None:
                rgy.close()
            hby.close()
