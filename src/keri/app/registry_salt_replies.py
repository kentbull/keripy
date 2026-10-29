"""Exact reply bodies for the local experimental registry-salt profile.

This is a keripy profile, not standardized KERI. Construction uses core.reply
with explicit KERI v2 JSON. Validation checks body integrity and relationships,
not signature authentication, representative approval, entitlement provenance,
or accepted registry/KEL history. Those remain caller responsibilities.

Either issuer or designated entitled discloser may initiate. The other party
binds the independently created registry inception; the issuer always confirms.
An ephemeral public key and signed reply timestamp identify the attempt. There
is no extra nonce. Never reuse negotiation private keys or put roots in bodies.
Only the exact returned init.raw and bind.raw belong in registry_salts' KDF.
Later entitlement assignments are outside this initial two-party profile.
"""

from .. import Vrsn_2_0
from ..core import Diger, Matter, MtrDex, Number, Prefixer, SerderACDC, SerderKERI, reply
from ..kering import Ilks, KeriError, Kinds, ValidationError
from . import registry_salts


SUITE = 'RKS1-X25519-HKDF-SHA256'
PROFILE = 'keripy-blinder-snh-low-v1'
PURPOSE = 'registry-state'
INIT_ROUTE = '/keri-rnd/registry-salt/1/init'
BIND_ROUTE = '/keri-rnd/registry-salt/1/bind'
CONFIRM_ROUTE = '/keri-rnd/registry-salt/1/confirm'


def _qualified(value, klas, code=None):
    """Require one canonical complete CESR string of the requested primitive."""
    try:
        if not isinstance(value, str):
            raise ValueError
        primitive = klas(qb64=value)
        if primitive.qb64 != value or (code is not None and primitive.code != code):
            raise ValueError
    except (KeriError, ValueError, TypeError):
        raise ValidationError('registry-salt reply contains invalid qualified material') from None


def _representative(data):
    """Check representative AID, establishment coordinate and DH key encoding."""
    _qualified(data['rep'], Prefixer)
    est = data['est']
    if not isinstance(est, dict) or set(est) != {'s', 'd'}:
        raise ValidationError('registry-salt representative requires exact s,d coordinates')
    try:
        if not isinstance(est['s'], str) or Number(numh=est['s']).numh != est['s']:
            raise ValueError
    except (KeriError, ValueError, TypeError, OverflowError):
        raise ValidationError('registry-salt representative sequence must be canonical hex') from None
    _qualified(est['d'], Diger)
    _qualified(data['key'], Matter, MtrDex.X25519)


def _body(serder, route, fields):
    """Check exact v2 JSON reply shape, SAID, fixed profile and logical sender."""
    if (not isinstance(serder, SerderKERI) or serder.pvrsn != Vrsn_2_0
            or serder.gvrsn != Vrsn_2_0 or serder.kind != Kinds.json
            or serder.ilk != Ilks.rpy or serder.route != route
            or set(serder.sad) != {'v', 't', 'd', 'i', 'dt', 'r', 'a'}
            or not serder.verify()):
        raise ValidationError('registry-salt requires an intact exact v2 JSON reply body')
    data = serder.sad['a']
    if not isinstance(data, dict) or set(data) != fields:
        raise ValidationError('registry-salt reply has unexpected or missing fields')
    if (data['suite'], data['profile'], data['purpose']) != (SUITE, PROFILE, PURPOSE):
        raise ValidationError('registry-salt reply profile is unsupported')
    _qualified(serder.pre, Prefixer)
    _qualified(serder.said, Diger)
    return data


def _registry(rip, issuer, registry):
    """Check the supplied exact rip body and controller; acceptance is external."""
    _qualified(registry, Diger)
    if (not isinstance(rip, SerderACDC) or rip.pvrsn != Vrsn_2_0
            or rip.ilk != Ilks.rip or rip.said != registry or rip.israid != issuer
            or rip.sad.get('n') != '0' or not rip.verify()):
        raise ValidationError('registry-salt bind does not match the supplied issuer registry inception')


def validateInit(init):
    """Validate an init body's semantics and return the same exact SerderKERI.

    Parameters: init is a parsed KERI reply SerderKERI retaining original bytes.
    Returns: init unchanged; authentication and representative approval are external.
    Raises: ValidationError for invalid shape, profile, roles or primitive encodings.
    """
    data = _body(init, INIT_ROUTE,
        {'issuer', 'discloser', 'rep', 'est', 'key', 'suite', 'profile', 'purpose'})
    _qualified(data['issuer'], Prefixer)
    _qualified(data['discloser'], Prefixer)
    if data['issuer'] == data['discloser'] or init.pre not in (data['issuer'], data['discloser']):
        raise ValidationError('registry-salt init requires distinct parties and one party as sender')
    _representative(data)
    return init


def validateBind(init, bind, rip):
    """Validate both bodies against one exact supplied registry inception.

    Parameters: init and bind are exact SerderKERI bodies; rip is SerderACDC.
    Returns: bind unchanged. Its other-party signature, rep approval and rip
        acceptance must be checked externally before the KDF uses these bytes.
    Raises: ValidationError for invalid bodies, source, cross-reference or rip.
    """
    validateInit(init)
    data = _body(bind, BIND_ROUTE,
        {'init', 'registry', 'rep', 'est', 'key', 'suite', 'profile', 'purpose'})
    _qualified(data['init'], Diger)
    if data['init'] != init.said:
        raise ValidationError('registry-salt bind references another init')
    parties = init.sad['a']
    other = parties['discloser'] if init.pre == parties['issuer'] else parties['issuer']
    if bind.pre != other:
        raise ValidationError('registry-salt bind must come from the other party')
    _representative(data)
    _registry(rip, parties['issuer'], data['registry'])
    return bind


def validateConfirm(init, bind, confirm, rip):
    """Validate issuer confirmation semantics and return its exact original body.

    Parameters: init, bind, confirm are SerderKERI; rip is the exact SerderACDC.
    Returns: confirm unchanged. Root agreement is a separate caller check:
        compare its commitment with registry_salts.commitment(root, init.raw,
        bind.raw).qb64. Signature, entitlement and history authority are external.
    Raises: ValidationError for invalid linkage, issuer, entitlement or commitment.
    """
    validateBind(init, bind, rip)
    data = _body(confirm, CONFIRM_ROUTE,
        {'init', 'bind', 'registry', 'commitment', 'entitled', 'suite', 'profile', 'purpose'})
    for name in ('init', 'bind', 'registry'):
        _qualified(data[name], Diger)
    parties = init.sad['a']
    if confirm.pre != parties['issuer']:
        raise ValidationError('registry-salt confirmation must come from issuer')
    if (data['init'], data['bind'], data['registry']) != (init.said, bind.said, rip.said):
        raise ValidationError('registry-salt confirmation references another negotiation')
    if data['entitled'] != [parties['issuer'], parties['discloser']]:
        raise ValidationError('registry-salt initial entitlement must be exactly issuer and discloser')
    _qualified(data['commitment'], Diger, MtrDex.SHA2_256)
    return confirm


def initReply(*, sender, issuer, discloser, rep, est, key, stamp=None):
    """Construct an unsigned exact init reply for either logical party.

    Parameters: sender, issuer, discloser and rep are qualified AIDs; est is
        the representative's {s: canonical hex, d: event digest}; key is its
        ephemeral public X25519 CESR string; stamp is an optional reply timestamp.
    Returns: validated v2 JSON SerderKERI; authorize and sign it externally.
    Raises: ValidationError for invalid body semantics or primitive encodings.
    """
    data = dict(issuer=issuer, discloser=discloser, rep=rep, est=est,
                key=key, suite=SUITE, profile=PROFILE, purpose=PURPOSE)
    return validateInit(reply(pre=sender, route=INIT_ROUTE, data=data, stamp=stamp,
                              version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json))


def bindReply(init, rip, *, sender, rep, est, key, stamp=None):
    """Construct the opposite party's unsigned bind to init and registry rip.

    Parameters: init is exact SerderKERI; rip is exact independently created
        SerderACDC; sender and rep are qualified AIDs; est is {s,d}; key is the
        ephemeral public X25519 CESR string; stamp is optional reply timestamp.
    Returns: validated v2 JSON SerderKERI; authorize and sign it externally.
    Raises: ValidationError for invalid source, primitive, profile or linkage.
    """
    validateInit(init)
    if not isinstance(rip, SerderACDC):
        raise ValidationError('registry-salt bind requires a registry inception body')
    data = dict(init=init.said, registry=rip.said, rep=rep, est=est,
                key=key, suite=SUITE, profile=PROFILE, purpose=PURPOSE)
    return validateBind(init, reply(pre=sender, route=BIND_ROUTE, data=data, stamp=stamp,
        version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json), rip)


def confirmReply(init, bind, rip, root, *, stamp=None):
    """Construct issuer confirmation without including the private root.

    Parameters: init/bind are exact SerderKERI; rip is exact SerderACDC; root
        is their derived Salt_128 Salter; stamp is optional reply timestamp.
    Returns: validated issuer v2 JSON SerderKERI with SHA2_256 root commitment.
    Raises: ValidationError for invalid linkage; ValueError for invalid root.
        Signature, accepted history and initial entitlement are external checks.
    """
    validateBind(init, bind, rip)
    parties = init.sad['a']
    data = dict(init=init.said, bind=bind.said, registry=rip.said,
        commitment=registry_salts.commitment(root, init.raw, bind.raw).qb64,
        entitled=[parties['issuer'], parties['discloser']],
        suite=SUITE, profile=PROFILE, purpose=PURPOSE)
    return validateConfirm(init, bind, reply(pre=parties['issuer'], route=CONFIRM_ROUTE,
        data=data, stamp=stamp, version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json), rip)
