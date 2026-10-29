"""Pure cryptographic helpers for the local ``keri-rnd/registry-salt/1`` profile.

X25519 is RFC 7748, section 6.1; HKDF is RFC 5869 with SHA-256. The transcript,
domains and 128-bit output below are a local experimental profile, not a
standardized KERI protocol. Cryptographic operations use ``cryptography``.

Callers must authenticate and authorize both replies and their DH public keys
before deriving a root. Pass the exact init and bind reply body bytes, including
their SAIDs, in that role order. Never parse and reserialize them for this API.
These helpers establish no protocol authority, replay protection, storage, or
replication policy. A commitment belongs in a subsequent confirmation reply,
not in either input body (which would create a circular dependency).
"""

from hashlib import sha256

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .. import kering
from ..core.coring import Diger, Matter, MtrDex
from ..core.signing import Salter


def _key(material, code):
    """Read exactly one qualified key without including material in errors."""
    if isinstance(material, Matter):
        key = material
    elif isinstance(material, (str, bytes)):
        try:
            key = Matter(qb64=material)
            encoded = material.encode("ascii") if isinstance(material, str) else material
            if key.qb64b != encoded:
                raise ValueError
        except (kering.KeriError, ValueError, TypeError):
            raise ValueError("Invalid qualified registry-salt key") from None
    else:
        raise TypeError("Registry-salt keys must be Matter or qualified str/bytes")
    if key.code != code or len(key.raw) != 32:
        raise ValueError("Incorrect registry-salt key code or length")
    return key


def _bodies(init_body, bind_body):
    """Frame exact ordered body bytes with unsigned 32-bit big endian lengths."""
    framed = []
    for body in (init_body, bind_body):
        if not isinstance(body, bytes):
            raise TypeError("Registry-salt reply bodies must be exact bytes")
        if len(body) > 0xffffffff:
            raise ValueError("Registry-salt reply body exceeds uint32 length")
        framed.append(len(body).to_bytes(4, "big") + body)
    return b"".join(framed)


def generateKeypair():
    """Return fresh ``(public, private)`` CESR Matter objects for one negotiation.

    Parameters: none.
    Returns: a pair of Matter objects with X25519 and X25519_Private codes.
    Errors: cryptographic backend failures propagate to the caller.

    The private Matter's default repr excludes key material. Its ``raw``,
    ``qb64`` and ``qb64b`` properties are secrets and must not be logged.
    This function does not persist, erase or manage the key's lifecycle.
    """
    private = X25519PrivateKey.generate()
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    private_raw = private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())
    return (Matter(raw=public_raw, code=MtrDex.X25519),
            Matter(raw=private_raw, code=MtrDex.X25519_Private))


def deriveRoot(private, remote_public, init_body, bind_body):
    """Return a Salt_128 Salter derived from authenticated ordered reply bytes.

    Parameters:
        private: X25519_Private Matter or complete CESR qb64 str/bytes.
        remote_public: X25519 Matter or complete CESR qb64 str/bytes.
        init_body: exact authenticated init reply body bytes, including SAID.
        bind_body: exact authenticated bind reply body bytes, including SAID.
    Returns: a Salter containing the derived 16-byte root with Salt_128 code.
    Errors: TypeError for unsupported input types; ValueError for malformed or
        wrong-code keys, oversized bodies, invalid/low-order peer keys or an
        all-zero agreement. Cryptographic backend failures propagate.

    Both parties use the same init/bind order, regardless of which party
    supplies its private key.
    """
    private = _key(private, MtrDex.X25519_Private)
    remote_public = _key(remote_public, MtrDex.X25519)
    transcript = b"keri-rnd/registry-salt/1/transcript\x00" + _bodies(init_body, bind_body)
    try:
        shared = X25519PrivateKey.from_private_bytes(private.raw).exchange(
            X25519PublicKey.from_public_bytes(remote_public.raw))
    except ValueError:
        raise ValueError("Invalid registry-salt X25519 agreement") from None
    if shared == bytes(32):
        raise ValueError("Invalid registry-salt X25519 agreement")
    raw = HKDF(algorithm=hashes.SHA256(), length=16,
               salt=sha256(transcript).digest(),
               info=b"keri-rnd/registry-salt/1/root").derive(shared)
    return Salter(raw=raw)


def commitment(root, init_body, bind_body):
    """Return the SHA2_256 Diger confirming a Salt_128 root after the bind.

    Parameters:
        root: the Salt_128 Salter returned by deriveRoot.
        init_body: the exact authenticated init reply body bytes used by deriveRoot.
        bind_body: the exact authenticated bind reply body bytes used by deriveRoot.
    Returns: a Diger with SHA2_256 code over the commitment domain and inputs.
    Errors: TypeError for non-byte bodies; ValueError for an invalid root or
        oversized body.

    Verification/authorization of the later confirmation reply remains the
    caller's responsibility. This digest alone does not authenticate its sender.
    """
    if not isinstance(root, Salter) or root.code != MtrDex.Salt_128 or len(root.raw) != 16:
        raise ValueError("Registry-salt commitment requires a Salt_128 Salter")
    message = (b"keri-rnd/registry-salt/1/commitment\x00"
               + _bodies(init_body, bind_body) + root.raw)
    return Diger(ser=message, code=MtrDex.SHA2_256)
