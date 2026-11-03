"""Verify exact CESR opening bytes against the anchored BLID digest profile."""

import hashlib

import pytest

from keri.acdc.regeventing import vetBlind
from keri.core import Blinder, BlindState, BoundState, Diger
from keri.core.coring import (Bexter, DigDex, Labeler, Noncer, NonceDex,
                              Number, NumDex)
from keri.kering import UnverifiedBlindError


UUID = Noncer(raw=b'0123456789abcdef0123456789abcdef', code=NonceDex.Salt_256).qb64
TARGET = Diger(ser=b'target ACDC').qb64
BOUND = Diger(ser=b'Issuee key event').qb64
CODES = (DigDex.Blake3_256, DigDex.Blake2b_256, DigDex.Blake2s_256,
         DigDex.SHA3_256, DigDex.SHA2_256)


def opening(code=DigDex.Blake3_256, bound=False, mode='issued'):
    """Build deterministic real primitive encodings without opening a database."""
    fields = dict(d='', u='' if mode == 'public' else UUID,
                  td='' if mode == 'placeholder' else TARGET,
                  ts='' if mode == 'placeholder' else 'issued')
    clan = BlindState
    if bound:
        clan = BoundState
        fields.update(bn=0 if mode == 'placeholder' else 1,
                      bd='' if mode == 'placeholder' else BOUND)
    return Blinder(crew=clan(**fields), makify=True, saids={'d': code})


def materials(disclosed):
    return disclosed, disclosed.qb64, disclosed.qb64b


@pytest.mark.parametrize('code', CODES)
@pytest.mark.parametrize('bound', [False, True])
@pytest.mark.parametrize('mode', ['issued', 'placeholder', 'public'])
def test_vet_blind_preserves_declared_digest_and_public_openings(code, bound, mode):
    disclosed = opening(code, bound, mode)
    expected = ('', '') if mode == 'placeholder' else (TARGET, 'issued')
    for material in materials(disclosed):
        assert vetBlind(material, blid=disclosed.said) == expected
    if mode == 'public':
        assert disclosed.data.u.qb64 == '1AAP'
    if code == DigDex.SHA2_256:
        raw = b'#' * 44 + b''.join(field.qb64b for field in disclosed.data[1:])
        assert Diger(raw=hashlib.sha256(raw).digest(), code=code).qb64 == disclosed.said


@pytest.mark.parametrize('bound', [False, True])
@pytest.mark.parametrize('replacement', ['wrong-digest', 'other-algorithm', 'empty'])
def test_vet_blind_requires_opening_to_declare_anchored_digest(bound, replacement):
    anchored = opening(bound=bound)
    wrong = {'wrong-digest': Diger(ser=b'wrong').qb64,
             'other-algorithm': opening(DigDex.SHA2_256, bound).said,
             'empty': ''}[replacement]
    disclosed = Blinder(crew=anchored.crew._replace(d=wrong), verify=False)
    for material in materials(disclosed):
        with pytest.raises(UnverifiedBlindError):
            vetBlind(material, blid=anchored.said)


@pytest.mark.parametrize('code', [DigDex.Blake3_256, DigDex.SHA2_256])
@pytest.mark.parametrize('bound,field', [(False, 'ts'), (True, 'ts'), (True, 'bn')])
@pytest.mark.parametrize('valid', [False, True])
def test_vet_blind_authenticates_supplied_primitive_encoding(code, bound, field, valid):
    canonical = opening(code, bound)
    alternate = (Labeler(qb64=Bexter(bext='issued').qb64) if field == 'ts'
                 else Number(num=1, code=NumDex.Long))
    fields = canonical.data._replace(**{field: alternate})
    assert alternate.qb64 != getattr(canonical.data, field).qb64
    assert (alternate.text == canonical.state if field == 'ts'
            else alternate.num == canonical.bsn)
    raw = b'#' * 44 + b''.join(value.qb64b for value in fields[1:])
    exact = Diger(ser=raw, code=code)
    assert exact.qb64 != canonical.said
    if valid:
        fields = fields._replace(d=Noncer(qb64=exact.qb64))
    disclosed = Blinder(data=fields, verify=False)
    for material in materials(disclosed):
        if valid:
            assert vetBlind(material, blid=exact.qb64) == (TARGET, 'issued')
        else:
            with pytest.raises(UnverifiedBlindError):
                vetBlind(material, blid=canonical.said)


@pytest.mark.parametrize('bound', [False, True])
@pytest.mark.parametrize('as_bytes', [False, True])
def test_vet_blind_rejects_trailing_opening_material(bound, as_bytes):
    disclosed = opening(bound=bound)
    material = disclosed.qb64 + '1AAP'
    with pytest.raises(UnverifiedBlindError):
        vetBlind(material.encode() if as_bytes else material, blid=disclosed.said)


@pytest.mark.parametrize('bound', [False, True])
@pytest.mark.parametrize('field', ['anchor', 'nonce'])
def test_vet_blind_refuses_noncanonical_primitive_midpad(bound, field):
    disclosed = opening(bound=bound)
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    material, blid = disclosed.qb64, disclosed.said
    value = blid if field == 'anchor' else disclosed.data.u.qb64
    # Change only bits discarded as the primitive's zero midpad byte.
    index = alphabet.index(value[1])
    assert index < 16
    noncanonical = value[:1] + alphabet[index + 16] + value[2:]
    if field == 'anchor':
        blid = noncanonical
    else:
        material = material[:44] + noncanonical + material[44 + len(value):]
    with pytest.raises(UnverifiedBlindError):
        vetBlind(material, blid=blid)


@pytest.mark.parametrize('bound,field', [(False, 'u'), (False, 'td'), (False, 'ts'),
                                      (True, 'u'), (True, 'td'), (True, 'ts'),
                                      (True, 'bn'), (True, 'bd')])
def test_vet_blind_binds_each_disclosed_field(bound, field):
    anchored = opening(bound=bound)
    replacements = dict(u=Noncer(raw=b'x' * 32, code=NonceDex.Salt_256).qb64,
                        td=Diger(ser=b'other ACDC').qb64, ts='revoked',
                        bn=2, bd=Diger(ser=b'other key event').qb64)
    tampered = Blinder(crew=anchored.crew._replace(**{field: replacements[field]}),
                       verify=False)
    for material in materials(tampered):
        with pytest.raises(UnverifiedBlindError):
            vetBlind(material, blid=anchored.said)


@pytest.mark.parametrize('blid', ['', '1AAP', UUID, TARGET + '1AAP', b'\xff',
                                  Diger(ser=b'long digest', code=DigDex.SHA2_512).qb64],
                         ids=['empty', 'empty-nonce', 'nonce', 'trailing', 'non-ascii', 'long'])
def test_vet_blind_requires_one_canonical_anchored_digest(blid):
    with pytest.raises(UnverifiedBlindError):
        vetBlind(opening(), blid=blid)


@pytest.mark.parametrize('material', ['', 'invalid', b'\xff', None],
                         ids=['empty', 'invalid', 'non-ascii', 'none'])
def test_vet_blind_reports_malformed_opening_without_disclosing_it(material):
    with pytest.raises(UnverifiedBlindError):
        vetBlind(material, blid=opening().said)
