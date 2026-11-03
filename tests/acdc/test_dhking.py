"""Public RFC 7748 secrets and independently checked R07a derivation vectors."""

import json
from pathlib import Path

import pytest

from keri.acdc.dhking import Domain, decodePublicKey, deriveRoot, generateKeyPair
from keri.core import Blinder, Matter, MtrDex


Vector = json.loads((Path(__file__).parent / "fixtures" / "dhke.json").read_text())


@pytest.mark.parametrize("role", ["issuer", "issuee"])
def test_derivation_matches_independent_vector(role):
    private = bytes.fromhex(Vector[f"{role}_private_hex"])
    root = deriveRoot(private, role=role, **Vector["context"])
    assert Domain.decode() == Vector["profile"]
    assert root.code == MtrDex.Salt_128
    assert root.raw.hex() == Vector["root_hex"]
    assert root.qb64 == Vector["root_qb64"]
    for sn, expected in Vector["uuids"].items():
        assert Blinder.makeUUID(raw=root.raw, sn=int(sn), tier="low") == expected


@pytest.mark.parametrize("case", Vector["rejected_public_keys"], ids=lambda case: case["name"])
@pytest.mark.parametrize("role", ["issuer", "issuee"])
def test_derivation_refuses_invalid_peer_keys(case, role):
    peer = "issuee_pk" if role == "issuer" else "issuer_pk"
    context = {**Vector["context"], peer: case["qb64"]}
    with pytest.raises(ValueError):
        deriveRoot(bytes.fromhex(Vector[f"{role}_private_hex"]), role=role, **context)


@pytest.mark.parametrize("field", list(Vector["context"]))
@pytest.mark.parametrize("role", ["issuer", "issuee"])
def test_every_context_field_is_bound(field, role):
    code = MtrDex.X25519 if field.endswith("_pk") else MtrDex.Blake3_256
    context = {**Vector["context"], field: Matter(raw=bytes(range(32)), code=code).qb64}
    private = bytes.fromhex(Vector[f"{role}_private_hex"])
    if field == f"{role}_pk":
        with pytest.raises(ValueError, match="do not match"):
            deriveRoot(private, role=role, **context)
    else:
        assert deriveRoot(private, role=role, **context).qb64 != Vector["root_qb64"]


@pytest.mark.parametrize("field", ["x", "grant", "registry", "issuer", "issuee"])
@pytest.mark.parametrize("suffix", ["AAAA", "=", "\N{SNOWMAN}"])
def test_context_identifiers_are_complete_cesr(field, suffix):
    context = {**Vector["context"], field: Vector["context"][field] + suffix}
    with pytest.raises(ValueError):
        deriveRoot(bytes.fromhex(Vector["issuer_private_hex"]), role="issuer", **context)


@pytest.mark.parametrize("private", [b"", bytes(31), bytes(33), "a" * 32, None])
def test_invalid_private_key(private):
    with pytest.raises(ValueError, match="32-byte"):
        deriveRoot(private, role="issuer", **Vector["context"])


def test_fresh_keys_derive_reciprocally_and_validate_role():
    issuerPrivate, issuerPublic = generateKeyPair()
    issueePrivate, issueePublic = generateKeyPair()
    assert issuerPrivate != issueePrivate and issuerPublic != issueePublic
    assert len(decodePublicKey(issuerPublic)) == len(decodePublicKey(issueePublic)) == 32
    context = {**Vector["context"], "issuer_pk": issuerPublic, "issuee_pk": issueePublic}
    issuerRoot = deriveRoot(issuerPrivate, role="issuer", **context)
    assert issuerRoot.qb64 == deriveRoot(issueePrivate, role="issuee", **context).qb64
    with pytest.raises(ValueError, match="role"):
        deriveRoot(issuerPrivate, role="presenter", **context)
    with pytest.raises(ValueError, match="do not match"):
        deriveRoot(issueePrivate, role="issuer", **context)
    with pytest.raises(ValueError):
        deriveRoot(issuerPrivate, role="issuer", **{**context, "x": issuerPublic})
