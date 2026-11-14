"""Ask a registry issuer for the KEL events a held v2 TEL event waits on."""
import json

from ... import Kinds, Vrsn_2_0
from ...kering import ConfigurationError
from . import sending


def logsQuery(hab, cue):
    """Return the signed ``logs`` query bytes for one ``Regery`` anchor cue.

    The query names the issuer as both subject and source, replays its log from
    ``fn`` (the first event the local KEL lacks), and, when the cue carries the
    sender's anchor claim, asks the responder to have reached sn ``s``.
    """
    query = dict(fn=f"{cue['fn']:x}")
    if cue['s'] is not None:
        query['s'] = f"{cue['s']:x}"
    return bytes(hab.query(pre=cue['issuer'], src=cue['issuer'], route='logs',
                           query=query, pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json))


def pump(owner):
    """Send one signed ``logs`` query per cue the owner's ``Regery`` holds.

    ``owner`` is the finite command DoDoer that holds ``hab``, ``rgy`` and the
    ``check``/``tock`` used by ``sending.send``. The query is only a request to
    fetch evidence the TEL event already waits for, so a recipient with no
    reachable transport is reported and does not end the operation.
    """
    while owner.rgy.cues:
        cue = owner.rgy.cues.popleft()
        try:
            yield from sending.send(owner, logsQuery(owner.hab, cue), cue['dest'])
        except ConfigurationError as error:
            print(json.dumps(dict(phase='anchor_query_unsent', issuer=cue['issuer'],
                                  registry=cue['regk'], event=cue['said'],
                                  error=str(error))), flush=True)


def settle(owner):
    """Wait one tock of ``owner``, first sending the queries its ``Regery`` cued."""
    yield from pump(owner)
    yield owner.tock
