"""Start Dolly using explicit issuer/schema/disclosure and observer/webhook policy."""
import argparse
import json
from pathlib import Path

from keri import Vrsn_1_0, Vrsn_2_0
from keri.app.dolly import serving
from keri.app.habbing import HaberyDoer
from keri.app.keeping import Keeper
from keri.app.oobiing import Oobiery
from keri.cli.common import Parsery, setupHby
from keri.kering import ConfigurationError
from keri.core import Schemer

parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.add_argument('--alias', '-a', required=True)
parser.add_argument('--config', required=True, help='JSON issuers, schemas, fields, required, observer, webhook')
parser.add_argument('--kel', action='append', default=[], help='public signed KEL bootstrap file')
parser.add_argument('--kel-genus', type=int, choices=(1, 2), default=2)
parser.add_argument('--schema', action='append', default=[], help='public JSON schema cache file')
parser.add_argument('--host', default='127.0.0.1')
parser.add_argument('--port', type=int, default=6644)
parser.add_argument('--no-prompt', action='store_true')
parser.set_defaults(handler=lambda args: handler(args))


def handler(args):
    policy = json.loads(Path(args.config).read_text())
    keeper = Keeper(name=args.name, base=args.base, reopen=True)
    try:
        if not keeper.gbls.get('aeid'):
            raise ConfigurationError('Dolly requires an existing encrypted Keeper')
    finally:
        keeper.close()
    hby = setupHby(args.name, args.base, args.bran, noPrompt=args.no_prompt)
    ctx = None
    try:
        hab = hby.habByName(args.alias)
        if not hby.mgr.aeid or hab is None:
            raise ConfigurationError('Dolly requires an encrypted Keeper and existing alias')
        ctx, doers = serving.setup(hby, hab, host=args.host, port=args.port, **policy)
        for path in args.schema:
            schema = Schemer(raw=Path(path).read_bytes())
            hby.db.schema.pin((schema.said,), schema)
        for path in args.kel:
            ctx.ingest(Path(path).read_bytes(),
                version=Vrsn_1_0 if args.kel_genus == 1 else Vrsn_2_0)
        return [HaberyDoer(habery=hby), *Oobiery(hby).doers, *doers]
    except BaseException:
        if ctx is not None:
            ctx.close()
        hby.close()
        raise
