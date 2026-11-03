"""Derivation for the local IPEX DHKE profile.

This is not a standardized KERI key derivation. The caller must authenticate
the live Grant, participants and fresh registry scope before using these
primitives. Ephemeral private keys belong to that live operation, not Keeper.
"""

import hashlib
import struct

import pysodium
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..core import Matter, MtrDex, Prefixer, Saider, Salter


Domain = b"KERI/ipex/dhke/X25519-HKDF-SHA256-Salt128/v1"


def _canonical(qb64, klas):
    """Parse exactly one canonical qualified primitive, without trailing data."""
    if not isinstance(qb64, str) or not qb64:
        raise ValueError("expected a canonical CESR string")
    try:
        material = klas(qb64=qb64)
    except Exception:
        raise ValueError("invalid CESR material") from None
    if material.qb64 != qb64:
        raise ValueError("noncanonical or trailing CESR material")
    return material


def decodePublicKey(qb64):
    """Decode one CESR C X25519 public key; contributory checks occur in DH."""
    material = _canonical(qb64, Matter)
    if material.code != MtrDex.X25519 or len(material.raw) != 32:
        raise ValueError("expected a CESR X25519 public key")
    return material.raw


def generateKeyPair():
    """Return (private bytes, public qb64) for one fresh registry operation."""
    private = pysodium.randombytes(32)
    public = pysodium.crypto_scalarmult_curve25519_base(private)
    return private, Matter(raw=public, code=MtrDex.X25519).qb64


def deriveRoot(private, *, role, x, grant, registry, issuer, issuee,
               issuer_pk, issuee_pk):
    """Derive a Salt128 bound to the exact Grant, registry, parties and keys.

    ``role`` is the local party, either ``issuer`` or ``issuee``. The advertised
    key for that role must match the supplied 32-byte ephemeral private key.
    XIP identity ``x`` may differ from ``grant`` for Apply/Offer-first flows.
    Returns a Salter. Malformed input, mismatched local keys and noncontributory
    peer keys raise ValueError; no signing-key conversion or key storage occurs.
    """
    if role not in ("issuer", "issuee"):
        raise ValueError("role must be issuer or issuee")
    if not isinstance(private, (bytes, bytearray, memoryview)) or len(private) != 32:
        raise ValueError("expected a 32-byte ephemeral private key")
    private = bytes(private)
    for value in (x, grant, registry):
        _canonical(value, Saider)
    for value in (issuer, issuee):
        _canonical(value, Prefixer)
    issuerKey, issueeKey = decodePublicKey(issuer_pk), decodePublicKey(issuee_pk)
    own, peer = (issuerKey, issueeKey) if role == "issuer" else (issueeKey, issuerKey)
    if pysodium.crypto_scalarmult_curve25519_base(private) != own:
        raise ValueError("local ephemeral private and public keys do not match")
    try:
        shared = pysodium.crypto_scalarmult_curve25519(private, peer)
    except Exception:
        raise ValueError("noncontributory X25519 public key") from None
    if shared == bytes(32):
        raise ValueError("noncontributory X25519 public key")
    parts = [Domain, *(value.encode("ascii") for value in
                       (x, grant, registry, issuer, issuee, issuer_pk, issuee_pk))]
    info = b"".join(struct.pack(">I", len(part)) + part for part in parts)
    raw = HKDF(algorithm=hashes.SHA256(), length=16,
               salt=hashlib.sha256(Domain).digest(), info=info).derive(shared)
    return Salter(raw=raw, code=MtrDex.Salt_128)
