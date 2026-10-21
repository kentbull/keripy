"""Credential source triples follow their message genus, not library defaults."""
import pytest

from keri import Kinds, Vrsn_1_0, Vrsn_2_0
from keri.acdc import acdcmap
from keri.app.signing import serialize
from keri.core import Diger, Parser, Prefixer, Seqner
from keri.vc import credential


@pytest.mark.parametrize('version', [Vrsn_1_0, Vrsn_2_0])
def test_credential_serialization_preserves_body_and_exact_source_triple(version):
    """Serialize a real credential body and recover its exact typed source triple.

    version selects legacy v1 or native v2. The source's nonzero ordinal and
    independent digest expose coordinate conversion errors, while exact body
    equality protects the credential commitment. Return None; pytest asserts
    footer decoding and coordinate equality. This tests framing, not issuer or
    registry acceptance, and opens no identity or accepted-evidence tables.
    """
    issuer = Diger(ser=b'credential issuer').qb64
    registry = Diger(ser=b'credential registry').qb64
    if version == Vrsn_1_0:
        creder = credential(issuer=issuer, schema=Diger(ser=b'local schema').qb64,
            status=registry, data=dict(status='authorized'), version=version, kind=Kinds.json)
    else:
        creder = acdcmap(israid=issuer, regid=registry,
            attribute=dict(d='', status='authorized'), kind=Kinds.json)
    source = Prefixer(qb64=Diger(ser=b'exact source prefix').qb64)
    ordinal = Seqner(sn=7)
    digest = Diger(ser=b'exact source event')
    original = bytes(creder.raw)
    wire = serialize(creder, source, ordinal, digest)
    assert creder.raw == original and wire.startswith(original)
    stream = bytearray(wire)
    parsed = Parser(version=version).parseOne(ims=stream, processive=False)
    assert stream == b'' and parsed.serder.raw == original
    assert len(parsed.ssts) == 1
    prefixer, number, diger = parsed.ssts[0]
    assert (prefixer.qb64, number.num, diger.qb64) == (source.qb64, 7, digest.qb64)
