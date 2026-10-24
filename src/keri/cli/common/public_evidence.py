"""Operator adapters for public CESR evidence and explicit registry openings.

These commands expose ordinary processors and signed service requests. They do
not inject accepted KEL/TEL rows, wallet consent, or optional custody records.
"""
from dataclasses import asdict
import hashlib
import json
import math
from pathlib import Path
from urllib.parse import urlsplit

from hio.base import doing
from hio.core import http

from keri import Vrsn_2_0, Kinds
from keri.acdc import messaging
from keri.acdc.regeventing import vetBlind, vetBound
from keri.app import Receiptor, HaberyDoer, Keeper
from keri.app.httping import CESR_CONTENT_TYPE
from keri.app.evidencing import EvidenceContext, KEL_DEPENDENCIES, signedQuery
from keri.cli.common import native, setupHby
from keri.core import Parser, SerderKERI, Number
from keri.kering import ConfigurationError
from keri.peer import exchanging


def write(path, raw):
    """Create an exclusive public-evidence file and report its exact byte digest.

    Args:
        path (str | Path): Operator-selected destination; existing paths are refused.
        raw (bytes): Serialized public evidence or explicitly selected opening bytes.

    Returns:
        str: SHA-256 hexadecimal digest of raw, after the file write completes.

    Raises:
        OSError: Destination creation/write fails, including FileExistsError.

    This helper neither authenticates evidence nor changes destination permissions;
    private registry-salt export uses its separate protected custody boundary."""
    with Path(path).open('xb') as stream:
        stream.write(raw)
    return hashlib.sha256(raw).hexdigest()


def replyAccepted(db, event):
    """Check exact endpoint-reply acceptance markers for idempotent public import.

    Args:
        db (Baser): Caller-owned authenticated endpoint/KEL evidence database.
        event (SerderKERI): Parsed reply body whose exact SAID to compare.

    Returns:
        bool: Whether this /loc/scheme or /end/role reply is the current accepted
        reference at its precise endpoint key; False for another message/route.

    An authenticated equal-timestamp replay needs no new BADA authorization decision.
    An unaccepted body is never sufficient to manufacture an acceptance marker."""
    if event.ilk != 'rpy':
        return False
    attrs = event.sad['a']
    if event.route == '/loc/scheme':
        said = db.lans.get((attrs['eid'], attrs['scheme']))
    elif event.route.startswith('/end/role/'):
        said = db.eans.get((attrs['cid'], attrs['role'], attrs['eid']))
    else:
        return False
    return said is not None and said.qb64 == event.said


def kel(args, operation):
    """Build one cooperative public KEL import/export operation.

    Args:
        args (Namespace): Existing identity/version plus alias/output or input file.
        operation (str): export or import, selected by the concrete command adapter.

    Returns:
        list[Doer]: One scheduler-compatible operation; it does no work until driven.

    The operation prints success only after exact accepted KEL/endpoint checks. It
    opens no custody collaborator and preserves existing Keeper encryption mode."""
    def run(tymth, tock=0.0, **kwa):
        """Execute one public KEL operation and close the identity on every exit.

        Args:
            tymth (Callable): HIO injected clock, unused by this one-step operation.
            tock (float): Initial cooperative scheduling delay.
            **kwa: Additional HIO lifecycle metadata, unused here.

        Yields:
            float: Initial delay before synchronous local evidence/file processing.

        Returns:
            None. Prints the exported file digest or an accepted import summary.

        Raises:
            ConfigurationError: Keeper/alias is absent, frames/types are unsupported,
            parsing makes no progress, or exact supplied evidence remains unaccepted.
            OSError: Input/output cannot be accessed or an output already exists.
            Protocol authentication errors propagate; retryable KEL dependencies remain
            in the concrete processors' ordinary escrows before final acceptance checks.

        A passcode authenticates existing encryption only; an unencrypted Keeper is
        opened without bran so this public operation cannot implicitly migrate AEID."""
        yield tock
        keeper = Keeper(name=args.name, base=args.base, reopen=True)
        try:
            aeid = keeper.gbls.get('aeid')
            if aeid is None:
                raise ConfigurationError('KEL evidence operation requires an existing Keeper')
        finally:
            keeper.close()
        # A supplied passcode authenticates existing encryption; it must never
        # turn an unencrypted public-evidence operation into an AEID migration.
        hby = setupHby(args.name, args.base, args.bran if aeid else None,
                       noPrompt=True, version=args.version)
        try:
            if operation == 'export':
                hab = hby.habByName(args.alias)
                if hab is None:
                    raise ConfigurationError('unknown KEL export alias')
                raw = bytearray(b''.join(hby.db.clonePreIter(pre=hab.pre, gvrsn=args.version)))
                if args.ends:
                    # Keep authentic endpoint replies and their proof attachments.
                    raw.extend(hab.replyToOobi(aid=hab.pre, role='controller',
                        version=args.version, gvrsn=args.version, kind=Kinds.json))
                digest = write(args.output, bytes(raw))
                print(json.dumps(dict(aid=hab.pre, sn=hab.kever.sn,
                                      output=args.output, sha256=digest)))
                return
            remaining = bytearray(Path(args.file).read_bytes())
            parser = Parser(kvy=hby.kvy, rvy=hby.rvy, local=False, version=args.version)
            events = []
            while remaining:
                before = len(remaining)
                dom = parser.parseOne(ims=remaining, processive=False, local=False)
                if dom is None or not isinstance(dom.serder, SerderKERI) or len(remaining) >= before:
                    raise ConfigurationError('KEL import requires complete KERI message frames')
                events.append(dom.serder)
                if replyAccepted(hby.db, dom.serder):
                    continue  # exact previously authenticated reply is idempotent
                try:
                    parser.msgProcess(asdict(dom), kvy=hby.kvy, rvy=hby.rvy,
                                      tvy=None, exc=None, vry=None)
                except KEL_DEPENDENCIES:
                    pass  # concrete KEL processor retained the missing evidence
            hby.kvy.processEscrows()
            hby.rvy.processEscrowReply()
            for event in events:
                if event.ilk in ('icp', 'dip', 'rot', 'drt', 'ixn'):
                    accepted = hby.db.kels.getLast(keys=event.pre, on=event.sn) == event.said
                elif event.ilk == 'rpy':
                    accepted = replyAccepted(hby.db, event)
                else:
                    raise ConfigurationError('unsupported public KEL import message')
                if not accepted:
                    raise ConfigurationError(f'public KEL evidence remains unaccepted: {event.said}')
            print(json.dumps(dict(accepted=True, messages=len(events))))
        finally:
            hby.close()
    return [doing.doify(run)]


def inspect(args):
    """Build an inspection operation reporting exact retained native EXN views.

    Args:
        args (Namespace): Existing identity/store selection and exchange SAID.

    Returns:
        list[Doer]: One cooperative inspection operation, with no custody collaborator.

    Execution freshly verifies the native route before printing retained disclosure;
    it neither records consent nor loads unreceived credential content."""
    def run(tymth, tock=0.0, **kwa):
        """Verify one retained native exchange and print its original parsed views.

        Args:
            tymth (Callable): HIO injected clock, unused by this local inspection.
            tock (float): Initial cooperative scheduling delay.
            **kwa: Additional scheduler lifecycle metadata, unused here.

        Yields:
            float: Initial delay before local retained-evidence processing.

        Returns:
            None. Prints sender/recipient/thread, route, and exact retained node digests/maps.

        Raises:
            ConfigurationError: Exchange is unknown, route is unavailable, or fresh native
            semantic revalidation refuses it. Missing/invalid proof errors propagate.

        Native/section store contexts own cleanup; inspection creates no admission,
        observer freshness, or private derivation authority."""
        yield tock
        from keri.acdc.sectioning import SectionBaser
        from keri.cli.common.native_exchange import Peer
        from keri.db import openLMDB
        with (native.opened(args) as (hby, rgy, wallet),
              openLMDB(cls=SectionBaser, name=args.name, base=args.base, temp=False) as sections):
            peer = Peer(hby, rgy, wallet, sections)
            event = hby.db.exns.get((args.said,))
            if event is None:
                raise ConfigurationError('exchange is not accepted')
            handler = peer.exc.routes.get(event.route)
            if handler is None or not handler.verifyAccepted(args.said):
                raise ConfigurationError('exchange failed fresh native IPEX verification')
            nests = exchanging.loadParsedNestedSubstreams(hby, args.said)
            nodes = [dict(credential=node.serder.said, disclosure=node.serder.sad,
                sha256=hashlib.sha256(node.serder.raw).hexdigest()) for node in nests]
            print(json.dumps(dict(exchange=event.said, accepted=True, sender=event.pre,
                recipient=event.sad.get('ri'), prior=event.sad['p'], thread=event.sad.get('x'),
                route=event.route, nodes=nodes)))
    return [doing.doify(run)]
