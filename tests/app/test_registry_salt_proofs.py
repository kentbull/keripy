"""Pure historical reply authentication, independent of live replay admission."""

from copy import deepcopy

import lmdb
import pytest

from keri import Vrsn_2_0
from keri.app import openCF, openHby
from keri.app.registry_salt_proofs import verifyArchivedReply
from keri.app.registry_salt_replies import CONFIRM_ROUTE
from keri.core import (Counter, Codens, Diger, Kramer, Number, Parser,
                       Prefixer, Texter, messagize, reply)
from keri.kering import Kinds, MissingEntryError, MissingSignatureError, ValidationError


OLD_STAMP = '2001-01-01T00:00:00.000000+00:00'


@pytest.fixture
def archive():
    """Yield a real 2-of-3 logical author and a receiver with accepted history."""
    with openHby(name='archive-author', temp=True, version=Vrsn_2_0) as source, \
            openHby(name='archive-receiver', temp=True, version=Vrsn_2_0) as target:
        author = source.makeHab(name='logical', icount=3, isith='2', ncount=3,
                                nsith='2', version=Vrsn_2_0)
        representative = source.makeHab(name='representative', version=Vrsn_2_0)
        parser = Parser(kvy=target.kvy, rvy=target.rvy, version=Vrsn_2_0)
        parser.parse(ims=author.replay(gvrsn=Vrsn_2_0), local=False)
        parser.parse(ims=representative.replay(gvrsn=Vrsn_2_0), local=False)
        body = reply(pre=author.pre, route=CONFIRM_ROUTE,
                     data=dict(commitment=Diger(ser=b'nonsecret archived evidence').qb64),
                     stamp=OLD_STAMP, version=Vrsn_2_0, kind=Kinds.json)
        group = (Prefixer(qb64=author.pre), Number(num=author.kever.lastEst.s),
                 Diger(qb64=author.kever.lastEst.d), author.sign(body.raw)[:2])
        yield target, parser, author, representative, body, group


def wire(body, groups):
    """Return ordinary canonical explicit establishment signature groups."""
    return messagize(body, tsgs=groups, framed=True, gvrsn=Vrsn_2_0)


def databaseSnapshot(hby):
    """Return every named table's raw records plus all operational cue queues."""
    with hby.db.env.begin() as txn:
        root = tuple((bytes(key), bytes(val)) for key, val in txn.cursor())
        tables = []
        for name, _ in root:
            try:
                table = hby.db.env.open_db(name, txn=txn, create=False)
            except lmdb.IncompatibleError:  # Main-DB metadata is covered by root.
                continue
            tables.append((name, tuple((bytes(key), bytes(val)) for key, val in
                                        txn.cursor(db=table))))
    cues = [[{key: value.raw if hasattr(value, 'raw') else deepcopy(value)
              for key, value in cue.items()} for cue in queue]
            for queue in (hby.kvy.cues, hby.rvy.cues)]
    return root, tables, cues


def test_historical_two_of_three_after_rotation_without_any_state_write(archive):
    """Historical threshold remains valid after rotation; archive intake is pure."""
    target, parser, author, representative, body, group = archive
    stream = wire(body, [group])
    author.rotate(gvrsn=Vrsn_2_0)
    parser.parse(ims=author.replay(gvrsn=Vrsn_2_0), local=False)
    assert target.kevers[author.pre].lastEst.s > group[1].sn
    before = databaseSnapshot(target)
    originalVersion = parser.version
    result = verifyArchivedReply(target, parser, stream, CONFIRM_ROUTE, author.pre)
    assert result.raw == body.raw and result.said == body.said
    assert parser.version == originalVersion
    assert databaseSnapshot(target) == before


def test_combine_partials_only_with_the_same_establishment(archive):
    """Separate partial groups may meet one threshold without mixing key states."""
    target, parser, author, representative, body, group = archive
    first = (*group[:3], group[3][:1])
    second = (*group[:3], group[3][1:])
    assert verifyArchivedReply(target, parser, wire(body, [first, second]),
                               CONFIRM_ROUTE, author.pre).raw == body.raw
    author.rotate(gvrsn=Vrsn_2_0)
    parser.parse(ims=author.replay(gvrsn=Vrsn_2_0), local=False)
    newer = (Prefixer(qb64=author.pre), Number(num=author.kever.lastEst.s),
             Diger(qb64=author.kever.lastEst.d), author.sign(body.raw)[1:2])
    before = databaseSnapshot(target)
    with pytest.raises(MissingSignatureError, match='historical threshold'):
        verifyArchivedReply(target, parser, wire(body, [first, newer]),
                            CONFIRM_ROUTE, author.pre)
    assert databaseSnapshot(target) == before


def test_representative_wrong_author_wrong_digest_and_duplicate_index(archive):
    """A representative, foreign establishment or repeated index cannot authorize."""
    target, parser, author, representative, body, group = archive
    representativeProof = representative.endorse(body, framed=True, gvrsn=Vrsn_2_0)
    forgedGroup = (*group[:3], representative.sign(body.raw))
    wrongDigest = (*group[:2], Diger(ser=b'wrong establishment digest'), group[3])
    repeatedIndex = (*group[:3], [group[3][0], group[3][0]])
    for stream in (representativeProof, wire(body, [forgedGroup]),
                   wire(body, [wrongDigest]), wire(body, [repeatedIndex])):
        before = databaseSnapshot(target)
        with pytest.raises(ValidationError):
            verifyArchivedReply(target, parser, stream, CONFIRM_ROUTE, author.pre)
        assert databaseSnapshot(target) == before
    with pytest.raises(ValidationError, match='logical author'):
        verifyArchivedReply(target, parser, wire(body, [group]), CONFIRM_ROUTE,
                            representative.pre)


def test_missing_historical_key_event_has_public_query_coordinates(archive):
    """Absent KEL evidence is explicit and leaves no new escrow or cue."""
    target, parser, author, representative, body, group = archive
    absent = (*group[:1], Number(num=42), group[2], group[3])
    before = databaseSnapshot(target)
    with pytest.raises(MissingEntryError, match=f'pre={author.pre} sn=2a dig={group[2].qb64}'):
        verifyArchivedReply(target, parser, wire(body, [absent]), CONFIRM_ROUTE, author.pre)
    assert databaseSnapshot(target) == before


def test_old_reply_remains_invalid_for_live_kram(archive):
    """Archive verification cannot reopen the operational replay/freshness path."""
    target, parser, author, representative, body, group = archive
    accepted = []

    class Owner:
        def processReply(self, **kwa):
            accepted.append(kwa['serder'].said)

    target.rvy.rtr.addRoute(CONFIRM_ROUTE, Owner())
    with openCF(name='archive-live-kram', temp=True) as cf:
        cf.put(dict(kram=dict(enabled=True, denials=[], caches={
            '~': [1000, 5000, 60000, 300000, 5000, 60000, 300000]})))
        parser.kvy.kramer = Kramer(db=target.db, cf=cf)
        stream = wire(body, [group])
        before = databaseSnapshot(target)
        assert verifyArchivedReply(target, parser, stream, CONFIRM_ROUTE, author.pre).raw == body.raw
        assert databaseSnapshot(target) == before
        parser.parse(ims=bytearray(stream), local=False)
        assert accepted == []
        assert target.db.kramMSGC.get(keys=(author.pre, body.said)) is None


def test_nontransferable_original_reply_authority():
    """A nontransferable author supplies its own verified nonindexed signature."""
    with openHby(name='archive-nontrans', temp=True, version=Vrsn_2_0) as hby:
        author = hby.makeHab(name='nontrans', transferable=False, version=Vrsn_2_0)
        body = reply(pre=author.pre, route=CONFIRM_ROUTE, data={},
                     version=Vrsn_2_0, kind=Kinds.json)
        stream = author.endorse(body, framed=True, gvrsn=Vrsn_2_0)
        assert verifyArchivedReply(hby, hby.psr, stream, CONFIRM_ROUTE, author.pre).raw == body.raw


@pytest.mark.parametrize('fault', ['truncated', 'trailing', 'multiple', 'unsigned',
                                  'last-est', 'bare', 'essr', 'nested', 'body-said', 'route'])
def test_archived_reply_frame_restrictions(archive, fault):
    """Archive intake accepts exactly one body and only explicit signer evidence."""
    target, parser, author, representative, body, group = archive
    stream = wire(body, [group])
    if fault == 'truncated':
        stream = stream[:-1]
    elif fault == 'trailing':
        stream += b'AAAA'
    elif fault == 'multiple':
        stream += wire(body, [group])
    elif fault == 'unsigned':
        stream = body.raw
    elif fault == 'last-est':
        stream = messagize(body, lsgs=[(group[0], group[3])], framed=True, gvrsn=Vrsn_2_0)
    elif fault == 'bare':
        stream = messagize(body, sigers=group[3], framed=True, gvrsn=Vrsn_2_0)
    elif fault == 'essr':
        texter = Texter(raw=b'nonsecret opaque attachment')
        stream += Counter(Codens.ESSRPayloadGroup, count=len(texter.qb64b) // 4,
                          gvrsn=Vrsn_2_0).qb64b + texter.qb64b
    elif fault == 'nested':
        nested = messagize(body, tsgs=[group], nested=True, gvrsn=Vrsn_2_0)
        stream = messagize(body, tsgs=[group], nests=[nested], gvrsn=Vrsn_2_0)
    elif fault == 'body-said':
        stream = stream.replace(b'/confirm', b'/confirn')
    before = databaseSnapshot(target)
    with pytest.raises(ValidationError):
        verifyArchivedReply(target, parser, stream,
                            '/another/route' if fault == 'route' else CONFIRM_ROUTE, author.pre)
    assert databaseSnapshot(target) == before
