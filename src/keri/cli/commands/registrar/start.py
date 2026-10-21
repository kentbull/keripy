"""Start the authorized registrar using an existing encrypted keystore."""
import argparse
from pathlib import Path

from keri.app.habbing import HaberyDoer
from keri.app.keeping import Keeper
from keri.app.registrar import serving
from keri.cli.common import Parsery, setupHby
from keri.kering import ConfigurationError

parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.add_argument('--publisher', action='append', required=True, help='authorized publisher AID')
parser.add_argument('--observer', action='append', required=True, help='authorized observer AID')
parser.add_argument('--kel', action='append', default=[], help='public signed KEL bootstrap file')
parser.add_argument('--host', default='127.0.0.1')
parser.add_argument('--port', type=int, default=6632)
parser.add_argument('--no-prompt', action='store_true')
parser.set_defaults(handler=lambda args: handler(args))


def handler(args):
    keeper = Keeper(name=args.name, base=args.base, reopen=True)
    try:
        if not keeper.gbls.get('aeid'):
            raise ConfigurationError('registrar requires an existing encrypted Keeper')
    finally:
        keeper.close()
    hby = setupHby(args.name, args.base, args.bran, noPrompt=args.no_prompt)
    ctx = None
    try:
        if not hby.mgr.aeid:
            raise ConfigurationError('registrar requires an existing encrypted Keeper')
        ctx, doers = serving.setup(hby, host=args.host, port=args.port,
                                   publishers=args.publisher, observers=args.observer)
        for path in args.kel:
            result = ctx.ingest(Path(path).read_bytes())
            if result['rejected']:
                raise ConfigurationError('invalid registrar KEL bootstrap')
        return [HaberyDoer(habery=hby), *doers]
    except BaseException:
        if ctx is not None:
            ctx.close()
        hby.close()
        raise
