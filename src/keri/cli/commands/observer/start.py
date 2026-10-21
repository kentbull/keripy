"""Start independent bulk polling and authorized cache-only registry queries."""
import argparse
from pathlib import Path

from keri.app.habbing import HaberyDoer
from keri.app.keeping import Keeper
from keri.app.oobiing import Oobiery
from keri.app.observer import serving
from keri.cli.common import Parsery, setupHby
from keri.kering import ConfigurationError

parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.add_argument('--alias', '-a', required=True)
parser.add_argument('--registrar', action='append', required=True, help='fixed bulk registrar URL')
parser.add_argument('--reader', action='append', required=True, help='authorized holder/verifier AID')
parser.add_argument('--kel', action='append', default=[], help='public signed KEL bootstrap file')
parser.add_argument('--interval', type=float, default=5.0)
parser.add_argument('--maximum-age', type=float, default=15.0)
parser.add_argument('--timeout', type=float, default=5.0)
parser.add_argument('--host', default='127.0.0.1')
parser.add_argument('--port', type=int, default=6633)
parser.add_argument('--no-prompt', action='store_true')
parser.set_defaults(handler=lambda args: handler(args))


def handler(args):
    keeper = Keeper(name=args.name, base=args.base, reopen=True)
    try:
        if not keeper.gbls.get('aeid'):
            raise ConfigurationError('observer requires an existing encrypted Keeper')
    finally:
        keeper.close()
    hby = setupHby(args.name, args.base, args.bran, noPrompt=args.no_prompt)
    ctx = None
    try:
        hab = hby.habByName(args.alias)
        if not hby.mgr.aeid or hab is None:
            raise ConfigurationError('observer requires an encrypted Keeper and existing alias')
        ctx, doers = serving.setup(hby, hab, host=args.host, port=args.port,
            urls=args.registrar, readers=args.reader, interval=args.interval,
            maximumAge=args.maximum_age, timeout=args.timeout)
        for path in args.kel:
            if ctx.ingest(Path(path).read_bytes())['rejected']:
                raise ConfigurationError('invalid observer KEL bootstrap')
        return [HaberyDoer(habery=hby), *Oobiery(hby).doers, *doers]
    except BaseException:
        if ctx is not None:
            ctx.close()
        hby.close()
        raise
