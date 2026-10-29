"""Public RFC vectors and a fixed vector for the local registry-salt profile."""

from hashlib import sha256
from hmac import digest

import pysodium
import pytest

from keri.app import registry_salts
from keri.core.coring import Matter, MtrDex
from keri.core.signing import Salter


# RFC 7748 section 6.1: https://www.rfc-editor.org/rfc/rfc7748#section-6.1
ALICE_PRIVATE = bytes.fromhex(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
ALICE_PUBLIC = bytes.fromhex(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
BOB_PRIVATE = bytes.fromhex(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
BOB_PUBLIC = bytes.fromhex(
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
SHARED = bytes.fromhex(
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

# Exact byte fixtures for the pure KDF boundary; these are not validated replies.
INIT = b'{"d":"init-said","r":"/rnd/registry-salt/init","a":{"nonce":"alice"}}'
BIND = b'{"d":"bind-said","r":"/rnd/registry-salt/bind","a":{"init":"init-said"}}'
ROOT = bytes.fromhex("c6ab3018975c57c71b4a7cc3dfdf8963")
COMMITMENT = bytes.fromhex(
    "b26b7caa16979162b61ff79a64be938bcc5c4a372d36283b614670acd7404c99")


def alice_private():
    """Qualify Alice's public RFC test private key as X25519_Private."""
    return Matter(raw=ALICE_PRIVATE, code=MtrDex.X25519_Private)


def bob_public():
    """Qualify Bob's RFC test public key as X25519."""
    return Matter(raw=BOB_PUBLIC, code=MtrDex.X25519)


def test_rfc7748_and_complete_profile_vector():
    """libsodium and independent RFC 5869 HMAC steps anchor the wrapper vector."""
    assert pysodium.crypto_scalarmult_base(ALICE_PRIVATE) == ALICE_PUBLIC
    assert pysodium.crypto_scalarmult_base(BOB_PRIVATE) == BOB_PUBLIC
    assert pysodium.crypto_scalarmult_curve25519(ALICE_PRIVATE, BOB_PUBLIC) == SHARED
    assert pysodium.crypto_scalarmult_curve25519(BOB_PRIVATE, ALICE_PUBLIC) == SHARED

    # Complete fixed framing, not an invocation of the implementation's helper.
    framed = b"\x00\x00\x00\x45" + INIT + b"\x00\x00\x00\x48" + BIND
    salt = sha256(b"keri-rnd/registry-salt/1/transcript\x00" + framed).digest()
    assert salt.hex() == "c4d54100e3361d0b180b2b639bc2953a6a8b40f10cc6e74e0e669a0f5537b7c9"
    prk = digest(salt, SHARED, "sha256")
    assert prk.hex() == "d62a292faeed20105de9f5db4a5ce7ec3a21dbcf80733417600e1a378f53abf6"
    assert digest(prk, b"keri-rnd/registry-salt/1/root\x01", "sha256")[:16] == ROOT

    root = registry_salts.deriveRoot(alice_private(), bob_public(), INIT, BIND)
    other = registry_salts.deriveRoot(
        Matter(raw=BOB_PRIVATE, code=MtrDex.X25519_Private),
        Matter(raw=ALICE_PUBLIC, code=MtrDex.X25519), INIT, BIND)
    assert isinstance(root, Salter) and root.code == MtrDex.Salt_128
    assert root.raw == other.raw == ROOT
    confirmed = registry_salts.commitment(root, INIT, BIND)
    assert confirmed.code == MtrDex.SHA2_256 and confirmed.raw == COMMITMENT
    assert sha256(b"keri-rnd/registry-salt/1/commitment\x00" + framed + ROOT).digest() == COMMITMENT


def test_generation_and_qualified_key_roundtrip():
    """Fresh keys match, preserve qualification and keep default repr opaque."""
    public, private = registry_salts.generateKeypair()
    assert public.code == MtrDex.X25519 and private.code == MtrDex.X25519_Private
    assert pysodium.crypto_scalarmult_base(private.raw) == public.raw
    assert private.qb64 not in repr(private) and private.raw.hex() not in repr(private)
    root = registry_salts.deriveRoot(private, bob_public(), INIT, BIND)
    assert registry_salts.deriveRoot(private.qb64, bob_public().qb64b, INIT, BIND).raw == root.raw
    second_public, second_private = registry_salts.generateKeypair()
    assert second_public.raw != public.raw and second_private.raw != private.raw


@pytest.mark.parametrize("init,bind", [
    (INIT + b" ", BIND),
    (INIT, BIND.replace(b"bind-said", b"other-said")),
    (INIT.replace(b"init-said", b"other-said"), BIND),
    (BIND, INIT),
    (INIT[:-1], INIT[-1:] + BIND),  # Same concatenation, different LP boundaries.
])
def test_exact_transcript_binding(init, bind):
    """Changing ordered body bytes or their boundaries changes the outputs."""
    root = registry_salts.deriveRoot(alice_private(), bob_public(), init, bind)
    assert root.raw != ROOT
    assert registry_salts.commitment(Salter(raw=ROOT), init, bind).raw != COMMITMENT


def test_changed_public_key_changes_root():
    """Another valid DH peer key produces another root and commitment."""
    other_public = Matter(raw=ALICE_PUBLIC, code=MtrDex.X25519)
    root = registry_salts.deriveRoot(alice_private(), other_public, INIT, BIND)
    assert root.raw != ROOT
    assert registry_salts.commitment(root, INIT, BIND).raw != COMMITMENT


@pytest.mark.parametrize("private,public", [
    (Matter(raw=ALICE_PRIVATE, code=MtrDex.Ed25519_Seed), bob_public()),
    (alice_private(), Matter(raw=BOB_PUBLIC, code=MtrDex.Ed25519)),
    (bob_public(), alice_private()),
    (alice_private().qb64[:-1], bob_public()),
    (alice_private(), bob_public().qb64[:-1]),
    (alice_private().qb64 + "AAAA", bob_public()),
    (alice_private(), bob_public().qb64 + "AAAA"),
    (alice_private().qb64[:-1] + "!", bob_public()),
    (alice_private(), b""),
])
def test_reject_wrong_or_incomplete_key_encoding(private, public):
    """Key boundaries reject wrong codes, truncation, suffixes and bad Base64."""
    with pytest.raises(ValueError):
        registry_salts.deriveRoot(private, public, INIT, BIND)


@pytest.mark.parametrize("raw", [bytes(32), b"\x01" + bytes(31)])
def test_reject_low_order_public_key(raw):
    """Low-order Curve25519 points cannot yield an accepted agreement."""
    public = Matter(raw=raw, code=MtrDex.X25519)
    with pytest.raises(ValueError, match="Invalid registry-salt X25519 agreement"):
        registry_salts.deriveRoot(alice_private(), public, INIT, BIND)


@pytest.mark.parametrize("body", ["{}", {}, bytearray(INIT), memoryview(INIT)])
def test_require_exact_body_bytes(body):
    """Neither KDF nor commitment silently serializes or converts bodies."""
    for init, bind in ((body, BIND), (INIT, body)):
        with pytest.raises(TypeError, match="exact bytes"):
            registry_salts.deriveRoot(alice_private(), bob_public(), init, bind)
        with pytest.raises(TypeError, match="exact bytes"):
            registry_salts.commitment(Salter(raw=ROOT), init, bind)


def test_reject_wrong_root_type_and_redact_invalid_private_errors():
    """Invalid roots fail and key parsing errors exclude the private input."""
    with pytest.raises(ValueError, match="Salt_128 Salter"):
        registry_salts.commitment(alice_private(), INIT, BIND)
    malformed = alice_private().qb64[:-1] + "!"
    with pytest.raises(ValueError) as caught:
        registry_salts.deriveRoot(malformed, bob_public(), INIT, BIND)
    assert malformed not in str(caught.value)
