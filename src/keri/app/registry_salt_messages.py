"""Assignment and encrypted replication for the provisional registry-salt/2 profile.

Kent Bull selected locally generated salts on 2026-10-29. This replaces the
fork's interactive DH protocol; the wire schema and commitment are local design
choices, not standardized ACDC routes. Existing CESR reply, salt, cipher and
signature primitives retain their original authority and encoding contracts.

These pure constructors/validators establish body integrity and exact evidence
relationships only. Callers authenticate signatures, accepted registry/controller
history, current members and recipient keys, and commit custody before receipts.
No plaintext salt enters a reply. No negotiation or ephemeral key is retained.
"""

from .. import Vrsn_2_0
from ..core import (Cipher, Diger, MtrDex, Number, Prefixer, Salter,
                    SerderACDC, SerderKERI, Texter, reply)
from ..kering import Ilks, KeriError, Kinds, ValidationError
from .replying import parseReply


DOMAIN = b'keri-rnd/registry-salt/2/commitment'
PROFILE = 'keripy-blinder-snh-low-v1'
PURPOSE = 'registry-state'
ASSIGN_ROUTE = '/keri-rnd/registry-salt/2/assign'
PROVISION_ROUTE = '/keri-rnd/registry-salt/2/provision'
RECEIPT_ROUTE = '/keri-rnd/registry-salt/2/receipt'
ROUTES = (ASSIGN_ROUTE, PROVISION_ROUTE, RECEIPT_ROUTE)
_ASSIGN = {'registry', 'commitment', 'party'}
_PROVISION = {'issuer', 'registry', 'commitment', 'assignment', 'source', 'party',
              'target', 'admission', 'recipientEst', 'cipher', 'proofs'}
_RECEIPT = {'provision', 'registry', 'commitment', 'assignment', 'party',
            'admission', 'retained'}


def _qualified(value, klas, code=None):
    """Validate one complete canonical CESR string; never echo secret inputs."""
    try:
        if not isinstance(value, str):
            raise ValueError
        primitive = klas(qb64=value)
        if primitive.qb64 != value or (code is not None and primitive.code != code):
            raise ValueError
    except (KeriError, ValueError, TypeError):
        raise ValidationError('registry-salt message contains invalid qualified material') from None


def _coordinate(value):
    """Require exactly one public establishment coordinate with canonical hex."""
    if not isinstance(value, dict) or set(value) != {'s', 'd'}:
        raise ValidationError('registry-salt message requires exact s,d coordinates')
    try:
        if not isinstance(value['s'], str) or Number(numh=value['s']).numh != value['s']:
            raise ValueError
    except (KeriError, ValueError, TypeError, OverflowError):
        raise ValidationError('registry-salt coordinate sequence must be canonical hex') from None
    _qualified(value['d'], Diger)


def commitment(root, issuer, registry):
    """Return a SHA2-256 CESR commitment to a Salt_128 and its registry context.

    Parameters: root is a Salter with 16 raw bytes; issuer and registry are
        complete qualified identifier/digest strings, respectively.
    Returns: Diger over DOMAIN, PROFILE, issuer, registry and root.raw, each
        prefixed by its unsigned four-byte big-endian byte length, in that order.
    Raises: ValidationError for invalid material. This binds no signature or
        timestamp and proves neither random generation nor registry acceptance.
    """
    if not isinstance(root, Salter) or root.code != MtrDex.Salt_128 or len(root.raw) != 16:
        raise ValidationError('registry-salt commitment requires Salt_128')
    _qualified(issuer, Prefixer)
    _qualified(registry, Diger)
    fields = (DOMAIN, PROFILE.encode('ascii'), issuer.encode('ascii'),
              registry.encode('ascii'), root.raw)
    framed = b''.join(len(value).to_bytes(4, 'big') + value for value in fields)
    return Diger(ser=framed, code=MtrDex.SHA2_256)


def _body(body, route, fields):
    """Validate intact v2 JSON, exact attributes and the fixed derivation profile."""
    if (not isinstance(body, SerderKERI) or body.ilk != Ilks.rpy
            or body.pvrsn != Vrsn_2_0 or body.gvrsn != Vrsn_2_0
            or body.kind != Kinds.json or body.route != route
            or set(body.sad) != {'v', 't', 'd', 'i', 'dt', 'r', 'a'}
            or not body.verify()):
        raise ValidationError('registry-salt requires an intact v2 JSON reply')
    data = body.sad['a']
    if not isinstance(data, dict) or set(data) != fields | {'profile', 'purpose'}:
        raise ValidationError('registry-salt message has unexpected or missing fields')
    if data['profile'] != PROFILE or data['purpose'] != PURPOSE:
        raise ValidationError('registry-salt message profile is unsupported')
    _qualified(body.pre, Prefixer)
    _qualified(data['registry'], Diger)
    _qualified(data['commitment'], Diger, MtrDex.SHA2_256)
    return data


def _new(sender, route, data, stamp):
    """Construct one unsigned reply; callers own endorsement and transport."""
    return reply(pre=sender, route=route, data=dict(data, profile=PROFILE, purpose=PURPOSE),
                 stamp=stamp, version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)


def validateAssign(assignment, rip):
    """Return assignment after exact controller/RIP checks, without authentication.

    Parameters: assignment is its original SerderKERI; rip is the exact
        independently accepted SerderACDC inception supplied by the caller.
    Raises: ValidationError for wrong controller, registry, profile or shape.
    Self-assignment and each additional logical party use this same operation.
    """
    data = _body(assignment, ASSIGN_ROUTE, _ASSIGN)
    _qualified(data['party'], Prefixer)
    if (not isinstance(rip, SerderACDC) or rip.ilk != Ilks.rip
            or rip.pvrsn != Vrsn_2_0 or rip.said != data['registry']
            or rip.israid != assignment.pre or rip.sad.get('n') != '0'
            or not rip.verify()):
        raise ValidationError('registry-salt assignment differs from controller registry inception')
    return assignment


def assignReply(rip, *, digest, party, stamp=None):
    """Construct an unsigned controller assignment for one entitled logical AID.

    Parameters: rip is SerderACDC; digest is the qualified root commitment;
        party is the entitled AID; stamp is an optional signed timestamp.
    Returns: validated SerderKERI. Raises: ValidationError for invalid context.
    The caller must obtain the issuer's actual threshold, not a lead-only signature.
    """
    if not isinstance(rip, SerderACDC):
        raise ValidationError('registry-salt assignment requires a registry inception')
    return validateAssign(_new(rip.israid, ASSIGN_ROUTE,
        dict(registry=rip.said, commitment=digest, party=party), stamp), rip)


def encodeProofs(streams):
    """Encode one or two exact signed assignment frames as qualified Texters.

    Parameters: streams is a list/tuple of nonempty bytes/bytearray values.
    Returns: ordered list of CESR strings. Raises: ValidationError on bad inputs.
    Encoding does not parse or authenticate the supplied frames.
    """
    if (not isinstance(streams, (list, tuple)) or not 1 <= len(streams) <= 2
            or any(not isinstance(s, (bytes, bytearray)) or not s for s in streams)):
        raise ValidationError('registry-salt requires one or two exact assignment frames')
    return [Texter(raw=bytes(stream)).qb64 for stream in streams]


def _provision(body):
    """Validate encrypted provision shape, recipient coordinates and proof framing."""
    data = _body(body, PROVISION_ROUTE, _PROVISION)
    for name in ('issuer', 'source', 'party', 'target'):
        _qualified(data[name], Prefixer)
    _qualified(data['assignment'], Diger)
    for name in ('admission', 'recipientEst'):
        _coordinate(data[name])
    _qualified(data['cipher'], Cipher, MtrDex.X25519_Cipher_Salt)
    proofs = data['proofs']
    if not isinstance(proofs, list) or not 1 <= len(proofs) <= 2:
        raise ValidationError('registry-salt requires one or two assignment proofs')
    for value in proofs:
        _qualified(value, Texter)
        if not Texter(qb64=value).raw:
            raise ValidationError('registry-salt proof must not be empty')
    return data


def decodeProofs(provision):
    """Return original assignment-frame bytes from a shape-checked provision."""
    return tuple(Texter(qb64=value).raw for value in _provision(provision)['proofs'])


def provisionReply(assignment, *, sender, source, target, admission, recipientEst,
                   cipher, proofs, stamp=None):
    """Construct an unsigned encrypted copy referencing its target's assignment.

    Parameters: assignment is the target grant; sender is the sending member;
        source is its entitled logical AID; target is the recipient member;
        admission/recipientEst are accepted {s,d} coordinates; cipher is Cipher_Salt;
        proofs is encodeProofs output; stamp is optional.
    Returns: shape-checked SerderKERI. Raises: ValidationError for malformed inputs.
    Current membership, exact proof bindings and authentication are caller checks.
    """
    data = _body(assignment, ASSIGN_ROUTE, _ASSIGN)
    body = _new(sender, PROVISION_ROUTE, dict(issuer=assignment.pre,
        registry=data['registry'], commitment=data['commitment'], assignment=assignment.said,
        source=source, party=data['party'], target=target, admission=admission,
        recipientEst=recipientEst, cipher=cipher, proofs=proofs), stamp)
    _provision(body)
    return body


def validateProvision(provision, rip, *, assignments, parser):
    """Validate exact source/target entitlement proofs, not their signatures.

    Parameters: provision/rip are original bodies; assignments is the ordered
        list/tuple of previously authenticated assignment bodies; parser is a
        borrowed parse-only owner. Returns: provision unchanged.
    Raises: ValidationError for wrong context, duplicates, extra/missing grants or
        substituted proof bytes. Current member/key checks remain external.
    """
    data = _provision(provision)
    streams = decodeProofs(provision)
    if not isinstance(assignments, (list, tuple)) or len(assignments) != len(streams):
        raise ValidationError('registry-salt assignment count differs from proof count')
    granted = {}
    for stream, assignment in zip(streams, assignments):
        validateAssign(assignment, rip)
        grant = assignment.sad['a']
        if (assignment.pre != data['issuer'] or grant['registry'] != data['registry']
                or grant['commitment'] != data['commitment'] or grant['party'] in granted):
            raise ValidationError('registry-salt provision contains conflicting assignments')
        if parseReply(parser, stream, {ASSIGN_ROUTE}).serder.raw != assignment.raw:
            raise ValidationError('registry-salt proof differs from exact assignment body')
        granted[grant['party']] = assignment.said
    if (set(granted) != {data['source'], data['party']}
            or granted.get(data['party']) != data['assignment']):
        raise ValidationError('registry-salt provision requires exact source and target assignments')
    return provision


def validateReceipt(provision, receipt):
    """Return an exact target retention acknowledgement; authentication is external."""
    original = _provision(provision)
    data = _body(receipt, RECEIPT_ROUTE, _RECEIPT)
    expected = {name: original[name] for name in
                ('registry', 'commitment', 'assignment', 'party', 'admission')}
    if (receipt.pre != original['target'] or data['provision'] != provision.said
            or data['retained'] is not True
            or any(data[name] != value for name, value in expected.items())):
        raise ValidationError('registry-salt receipt differs from exact target retention')
    return receipt


def receiptReply(provision, *, stamp=None):
    """Build an unsigned target receipt, to be called only after custody commits.

    Parameters: provision is validated SerderKERI; stamp is optional.
    Returns: exact SerderKERI. Raises: ValidationError for malformed context.
    This pure function performs no storage and proves no honest retention.
    """
    data = _provision(provision)
    fields = {name: data[name] for name in
              ('registry', 'commitment', 'assignment', 'party', 'admission')}
    return validateReceipt(provision, _new(data['target'], RECEIPT_ROUTE,
        dict(provision=provision.said, **fields, retained=True), stamp))
