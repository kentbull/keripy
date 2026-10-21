"""Declared BLID digests at the opening-verification boundary (R7).

ACDC f0bd097de318fbbe2d069a2b46cecd42550762e3, BLID d field permits
cryptographic digest codes with 44-character qb64 encodings. Bound blocks
inherit those semantics and also commit to bn/bd. No database is opened here.
"""

import hashlib

import pytest

from keri.acdc.regeventing import vetBlind
from keri.core import Blinder, BlindState, BoundState, Diger
from keri.core.coring import (DigDex, NonceDex, Noncer, NumDex, Number,
                              Labeler, Bexter)
from keri.kering import UnverifiedBlindError


CODES = (DigDex.Blake3_256, DigDex.Blake2b_256, DigDex.Blake2s_256,
         DigDex.SHA3_256, DigDex.SHA2_256)
UUID = Noncer(raw=b'0123456789abcdef0123456789abcdef',
              code=NonceDex.Salt_256).qb64
TARGET = Diger(ser=b'target ACDC').qb64
BOUND = Diger(ser=b'Issuee key event').qb64


def opening(code, bound, placeholder=False):
    """Build a deterministic CESR opening without opening a database.

    Parameters:
        code (str): digest derivation code passed to Blinder's saids mapping.
        bound (bool): include Issuee key event coordinates when true.
        placeholder (bool): use empty transaction fields and zero/empty
            bound coordinates when true.

    Returns:
        Blinder: real serialized opening using the requested digest.

    Raises:
        KeriError: propagated from Blinder for invalid primitive material.
    """
    fields = dict(d='', u=UUID, td='' if placeholder else TARGET,
                  ts='' if placeholder else 'issued')
    clan = BlindState
    if bound:
        clan = BoundState
        fields.update(bn=0 if placeholder else 1,
                      bd='' if placeholder else BOUND)
    return Blinder(crew=clan(**fields), makify=True, saids={'d': code})


@pytest.mark.parametrize('code', CODES)
@pytest.mark.parametrize('bound', (False, True))
@pytest.mark.parametrize('placeholder', (False, True))
def test_supported_declared_digest(code, bound, placeholder):
    """Accept each supported code in object/text/bytes forms and both clans.

    Parameters select the digest, bound fields, and empty placeholder case.
    Returns None; assertion failures identify a rejected or miscomputed opening.
    """
    disclosed = opening(code, bound, placeholder)
    assert disclosed.data.d.code == code
    assert len(disclosed.said) == 44
    expected = ('', '') if placeholder else (TARGET, 'issued')
    for material in (disclosed, disclosed.qb64, disclosed.qb64b):
        assert vetBlind(material, blid=disclosed.said) == expected

    # The reported SHA-256 counterexample also has an independent digest
    # oracle, rather than relying solely on Blinder to construct and verify.
    if code == DigDex.SHA2_256:
        fields = [value.qb64 for value in disclosed.data]
        fields[0] = '#' * 44
        raw = hashlib.sha256(''.join(fields).encode()).digest()
        assert Diger(raw=raw, code=code).qb64 == disclosed.said


@pytest.mark.parametrize('code', (DigDex.Blake3_256, DigDex.SHA2_256))
@pytest.mark.parametrize('bound', (False, True))
def test_opening_must_declare_the_anchored_commitment(code, bound):
    """Refuse mismatched d values, including another valid digest algorithm.

    Parameters select the anchored code and clan. Returns None; pytest raises
    an assertion failure if any altered opening avoids UnverifiedBlindError.
    """
    anchored = opening(code, bound)
    othercode = (DigDex.SHA2_256 if code == DigDex.Blake3_256
                 else DigDex.Blake3_256)
    other = opening(othercode, bound)
    wrong = Blinder(crew=anchored.crew._replace(d=other.said), verify=False)
    wrong_digest = Blinder(
        crew=anchored.crew._replace(d=Diger(ser=b'wrong', code=code).qb64),
        verify=False)
    empty = Blinder(crew=anchored.crew._replace(d=''), verify=False)
    for candidate in (other, wrong, wrong_digest, empty):
        for material in (candidate, candidate.qb64, candidate.qb64b):
            with pytest.raises(UnverifiedBlindError):
                vetBlind(material, blid=anchored.said)


@pytest.mark.parametrize('code', (DigDex.Blake3_256, DigDex.SHA2_256))
@pytest.mark.parametrize('bound', (False, True))
def test_every_disclosed_field_is_bound(code, bound):
    """Refuse each individually changed u/td/ts field and bound bn/bd field.

    Parameters select the anchored code and clan. Returns None; pytest raises
    an assertion failure if a tampered opening avoids UnverifiedBlindError.
    """
    anchored = opening(code, bound)
    replacements = dict(u=Noncer(raw=b'x' * 32,
                                code=NonceDex.Salt_256).qb64,
                        td=Diger(ser=b'other ACDC').qb64, ts='revoked')
    if bound:
        replacements.update(bn=2, bd=Diger(ser=b'other key event').qb64)
    for field, value in replacements.items():
        tampered = Blinder(crew=anchored.crew._replace(**{field: value}),
                           verify=False)
        for material in (tampered, tampered.qb64, tampered.qb64b):
            with pytest.raises(UnverifiedBlindError):
                vetBlind(material, blid=anchored.said)


@pytest.mark.parametrize('code', (DigDex.Blake3_512, DigDex.Blake2b_512,
                                 DigDex.SHA3_512, DigDex.SHA2_512))
@pytest.mark.parametrize('bound', (False, True))
def test_long_digest_codes_remain_outside_the_blid_profile(code, bound):
    """Refuse valid 512-bit digests whose encodings exceed the BLID profile.

    Parameters select the long digest code and clan. Returns None; pytest
    raises an assertion failure if the opening avoids UnverifiedBlindError.
    """
    disclosed = opening(code, bound)
    for material in (disclosed, disclosed.qb64, disclosed.qb64b):
        with pytest.raises(UnverifiedBlindError):
            vetBlind(material, blid=disclosed.said)


@pytest.mark.parametrize('blid', ('', '1AAP', UUID, 'Z' * 44, TARGET + '1AAP'))
def test_anchored_blid_must_be_one_supported_digest(blid):
    """Refuse malformed, non-digestive, empty, or trailing anchored material.

    blid is the invalid anchor parameter. Returns None; pytest raises an
    assertion failure if verification avoids UnverifiedBlindError.
    """
    with pytest.raises(UnverifiedBlindError):
        vetBlind(opening(DigDex.Blake3_256, False), blid=blid)


@pytest.mark.parametrize('bound', (False, True))
def test_declared_digest_does_not_allow_trailing_opening_fields(bound):
    """Preserve whole-opening consumption for SHA-256 in either clan.

    bound selects the clan. Returns None; pytest raises an assertion failure
    if a trailing primitive avoids UnverifiedBlindError.
    """
    disclosed = opening(DigDex.SHA2_256, bound)
    with pytest.raises(UnverifiedBlindError):
        vetBlind(disclosed.qb64 + '1AAP', blid=disclosed.said)


@pytest.mark.parametrize('code', (DigDex.Blake3_256, DigDex.SHA2_256))
@pytest.mark.parametrize('bound,field', ((False, 'ts'), (True, 'ts'), (True, 'bn')))
@pytest.mark.parametrize('valid', (False, True))
def test_blid_authenticates_exact_primitive_encodings(code, bound, field, valid):
    """Authenticate original primitive bytes rather than reconstructed values.

    Parameters select the digest, clan, alternate field encoding and whether
    its exact bytes have a matching digest. Returns None; pytest raises an
    assertion failure if valid bytes fail or an invalid opening is accepted.
    """
    canonical = opening(code, bound)
    alternative = (Labeler(qb64=Bexter(bext='issued').qb64) if field == 'ts'
                   else Number(num=1, code=NumDex.Long))
    fields = canonical.data._replace(**{field: alternative})
    assert alternative.qb64 != getattr(canonical.data, field).qb64
    # The text/value is unchanged; only its permitted CESR encoding differs.
    assert (alternative.text == canonical.state if field == 'ts'
            else alternative.num == canonical.bsn)
    raw = b'#' * 44 + b''.join(value.qb64b for value in fields[1:])
    exact = Diger(ser=raw, code=code)
    assert exact.qb64 != canonical.said
    if valid:
        fields = fields._replace(d=Noncer(qb64=exact.qb64))
    # verify=False exposes the object path to the same invalid exact bytes
    # rejected by wire decoding; vetBlind must not trust prior construction.
    disclosed = Blinder(data=fields, verify=False)
    for material in (disclosed, disclosed.qb64, disclosed.qb64b):
        if valid:
            assert vetBlind(material, blid=exact.qb64) == (TARGET, 'issued')
        else:
            with pytest.raises(UnverifiedBlindError):
                vetBlind(material, blid=canonical.said)


@pytest.mark.parametrize('code', (DigDex.Blake3_256, DigDex.SHA2_256))
@pytest.mark.parametrize('bound', (False, True))
def test_public_unblinded_opening_allows_empty_nonce(code, bound):
    """Preserve the specification's public-mode empty UUID in either clan.

    Parameters select the digest and clan. Returns None; assertion failures
    identify a rejected public opening or incorrect disclosed state.
    """
    fields = opening(code, bound).data._replace(u=Noncer(nonce=''))
    raw = b'#' * 44 + b''.join(value.qb64b for value in fields[1:])
    exact = Diger(ser=raw, code=code)
    disclosed = Blinder(data=fields._replace(d=Noncer(qb64=exact.qb64)))
    assert disclosed.uuid == '' and disclosed.data.u.qb64 == '1AAP'
    for material in (disclosed, disclosed.qb64, disclosed.qb64b):
        assert vetBlind(material, blid=exact.qb64) == (TARGET, 'issued')
