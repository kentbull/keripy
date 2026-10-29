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
Issuer assignments may extend entitlement to another logical party without
another DH exchange. Provisions carry only Cipher_Salt encrypted roots and
public archived proofs; receipts describe retention after an external custody
transaction commits. These provisional routes are local, not standardized KERI.
Current accepted source/recipient membership, historical proof authentication,
root decryption/commitment checks and durable retention remain external.
"""

from .. import Vrsn_2_0
from ..core import Cipher, Diger, Matter, MtrDex, Number, Prefixer, SerderACDC, SerderKERI, Texter, reply
from ..kering import Ilks, KeriError, Kinds, ValidationError
from . import registry_salts
from .replying import parseReply


SUITE = 'RKS1-X25519-HKDF-SHA256'
PROFILE = 'keripy-blinder-snh-low-v1'
PURPOSE = 'registry-state'
INIT_ROUTE = '/keri-rnd/registry-salt/1/init'
BIND_ROUTE = '/keri-rnd/registry-salt/1/bind'
CONFIRM_ROUTE = '/keri-rnd/registry-salt/1/confirm'
ASSIGN_ROUTE = '/keri-rnd/registry-salt/1/assign'
PROVISION_ROUTE = '/keri-rnd/registry-salt/1/provision'
RECEIPT_ROUTE = '/keri-rnd/registry-salt/1/receipt'
_CONFIRM_FIELDS = {'init', 'bind', 'registry', 'commitment', 'entitled', 'suite', 'profile', 'purpose'}
_PROVISION_FIELDS = {'origin', 'registry', 'party', 'target', 'admission', 'source',
                     'recipientEst', 'cipher', 'proofs', 'suite', 'profile', 'purpose'}


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


def _establishment(est):
    """Require exactly one canonical public establishment coordinate {s,d}."""
    if not isinstance(est, dict) or set(est) != {'s', 'd'}:
        raise ValidationError('registry-salt representative requires exact s,d coordinates')
    try:
        if not isinstance(est['s'], str) or Number(numh=est['s']).numh != est['s']:
            raise ValueError
    except (KeriError, ValueError, TypeError, OverflowError):
        raise ValidationError('registry-salt representative sequence must be canonical hex') from None
    _qualified(est['d'], Diger)


def _representative(data):
    """Check representative AID, establishment coordinate and DH key encoding."""
    _qualified(data['rep'], Prefixer)
    _establishment(data['est'])
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
    data = _confirmed(confirm)
    parties = init.sad['a']
    if confirm.pre != parties['issuer']:
        raise ValidationError('registry-salt confirmation must come from issuer')
    if (data['init'], data['bind'], data['registry']) != (init.said, bind.said, rip.said):
        raise ValidationError('registry-salt confirmation references another negotiation')
    if data['entitled'] != [parties['issuer'], parties['discloser']]:
        raise ValidationError('registry-salt initial entitlement must be exactly issuer and discloser')
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


def _confirmed(confirm):
    """Check confirmation shape/local bindings; full transcript checks are external."""
    data = _body(confirm, CONFIRM_ROUTE, _CONFIRM_FIELDS)
    for name in ('init', 'bind', 'registry'):
        _qualified(data[name], Diger)
    _qualified(data['commitment'], Diger, MtrDex.SHA2_256)
    entitled = data['entitled']
    if not isinstance(entitled, list) or len(entitled) != 2:
        raise ValidationError('registry-salt confirmation requires two initial parties')
    for aid in entitled:
        _qualified(aid, Prefixer)
    if entitled[0] != confirm.pre or entitled[0] == entitled[1]:
        raise ValidationError('registry-salt confirmation requires its issuer as first initial party')
    return data


def _linked(confirm, data):
    """Require origin/registry to identify this exact confirmation and registry."""
    confirmed = _confirmed(confirm)
    if (data['origin'], data['registry']) != (confirm.said, confirmed['registry']):
        raise ValidationError('registry-salt reply references another origin or registry')
    return confirmed


def _newReply(sender, route, data, stamp):
    """Return an unsigned v2 JSON reply with this profile's fixed public labels."""
    data = dict(data, suite=SUITE, profile=PROFILE, purpose=PURPOSE)
    return reply(pre=sender, route=route, data=data, stamp=stamp,
                 version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)


def validateAssign(confirm, assign):
    """Return an issuer assignment extending this origin to one new logical party.

    Parameters: confirm is the previously validated original confirmation;
        assign is its unsigned or authenticated assignment SerderKERI.
    Returns: assign unchanged. Its issuer threshold/history authentication and
        the party's accepted signing roster remain external responsibilities.
    Raises: ValidationError for wrong author, origin, registry or initial party.
    """
    data = _body(assign, ASSIGN_ROUTE,
                 {'origin', 'registry', 'party', 'suite', 'profile', 'purpose'})
    confirmed = _linked(confirm, data)
    _qualified(data['party'], Prefixer)
    if assign.pre != confirm.pre or data['party'] in confirmed['entitled']:
        raise ValidationError('registry-salt assignment requires issuer and a new logical party')
    return assign


def assignReply(confirm, *, party, stamp=None):
    """Construct an unsigned issuer assignment for the same root/origin.

    Parameters: confirm is a validated original confirmation; party is the new
        logical AID; stamp is optional. Returns: locally validated SerderKERI.
    Raises: ValidationError for malformed confirmation, party or linkage.
    Full transcript, issuer authentication and accepted rosters are external.
    """
    confirmed = _confirmed(confirm)
    return validateAssign(confirm, _newReply(confirm.pre, ASSIGN_ROUTE,
        dict(origin=confirm.said, registry=confirmed['registry'], party=party), stamp))


def _proofStreams(proofs):
    """Decode exact canonical Texter strings without parsing or authenticating them."""
    if (not isinstance(proofs, dict) or set(proofs) != {'init', 'bind', 'confirm', 'assignments'}
            or not isinstance(proofs['assignments'], list) or len(proofs['assignments']) > 2):
        raise ValidationError('registry-salt provision requires exact archived proof fields')
    result = {}
    for name in ('init', 'bind', 'confirm', 'assignments'):
        values = proofs[name] if name == 'assignments' else [proofs[name]]
        streams = []
        for value in values:
            _qualified(value, Texter)
            stream = Texter(qb64=value).raw
            if not stream:
                raise ValidationError('registry-salt archived proofs must not be empty')
            streams.append(stream)
        result[name] = tuple(streams) if name == 'assignments' else streams[0]
    return result


def encodeProofs(initStream, bindStream, confirmStream, assignmentStreams=()):
    """Return qualified Texter proof fields preserving exact signed CESR bytes.

    Parameters: three nonempty bytes/bytearray streams and up to two assignment
        streams in a list/tuple. Returns: the fixed public proofs dictionary.
    Raises: ValidationError for empty/unsupported inputs. This only encodes;
        full framing and historical signature authentication remain external.
    """
    if not isinstance(assignmentStreams, (list, tuple)) or len(assignmentStreams) > 2:
        raise ValidationError('registry-salt provision accepts at most two assignment proofs')
    streams = [initStream, bindStream, confirmStream, *assignmentStreams]
    if any(not isinstance(stream, (bytes, bytearray)) or not stream for stream in streams):
        raise ValidationError('registry-salt archived proofs require nonempty exact bytes')
    encoded = [Texter(raw=bytes(stream)).qb64 for stream in streams]
    return dict(zip(('init', 'bind', 'confirm'), encoded[:3]), assignments=encoded[3:])


def decodeProofs(provision):
    """Return exact proof bytes from an intact provision without authenticating.

    Parameters: provision is a SerderKERI. Returns: init/bind/confirm bytes plus
        an assignments tuple in wire order. Raises: ValidationError for bad
        body shape, malformed/trailing Texters, missing or empty proof streams.
    """
    return _proofStreams(_body(provision, PROVISION_ROUTE, _PROVISION_FIELDS)['proofs'])


def _provision(provision):
    """Check provision shape/public coordinates and qualified encrypted Salt_128."""
    data = _body(provision, PROVISION_ROUTE, _PROVISION_FIELDS)
    for name in ('origin', 'registry'):
        _qualified(data[name], Diger)
    for name in ('source', 'party', 'target'):
        _qualified(data[name], Prefixer)
    _establishment(data['admission'])
    _establishment(data['recipientEst'])
    _qualified(data['cipher'], Cipher, MtrDex.X25519_Cipher_Salt)
    _proofStreams(data['proofs'])
    return data


def provisionReply(confirm, *, sender, source, party, target, admission,
                   recipientEst, cipher, proofs, stamp=None):
    """Construct an unsigned member provision containing only an encrypted root.

    Parameters: confirm is a validated confirmation; sender is the member AID;
        source/party are logical parties; target is the individual recipient;
        admission/recipientEst are {s,d}; cipher is qualified Cipher_Salt;
        proofs is encodeProofs output; stamp is optional.
    Returns: shape/local-binding validated SerderKERI. Full transcript/proof
        semantics require validateProvision; signatures, current rosters,
        ciphertext key selection and root commitment checks remain external.
    Raises: ValidationError for invalid shape, coordinates, cipher or linkage.
    """
    confirmed = _confirmed(confirm)
    provision = _newReply(sender, PROVISION_ROUTE,
        dict(origin=confirm.said, registry=confirmed['registry'], source=source,
             party=party, target=target, admission=admission, recipientEst=recipientEst,
             cipher=cipher, proofs=proofs), stamp)
    _linked(confirm, _provision(provision))
    return provision


def validateProvision(init, bind, confirm, provision, rip, *, assignments=(), parser):
    """Return an exact semantically linked member provision.

    Parameters: init/bind/confirm are original bodies; rip is the exact registry
        inception; provision is the member reply; assignments are original
        bodies in bundled order; parser is borrowed for strict parse-only checks.
    Returns: provision unchanged. Every embedded body must match supplied raw
        bytes exactly; both logical parties need initial or issuer-assigned
        entitlement. No signature, current-roster or root-cipher authority is
        established here. Authenticate these exact streams externally with
        verifyArchivedReply, and perform live member/current-key checks.
    Raises: ValidationError for any inconsistent context, proof or entitlement.
    """
    validateConfirm(init, bind, confirm, rip)
    data = _provision(provision)
    confirmed = _linked(confirm, data)
    if not isinstance(assignments, (list, tuple)) or len(assignments) > 2:
        raise ValidationError('registry-salt provision accepts at most two assignments')
    needed = {data['source'], data['party']} - set(confirmed['entitled'])
    granted = []
    for assignment in assignments:
        validateAssign(confirm, assignment)
        granted.append(assignment.sad['a']['party'])
    if len(granted) != len(set(granted)) or set(granted) != needed:
        raise ValidationError('registry-salt provision requires exactly its noninitial party assignments')
    streams = decodeProofs(provision)
    if len(streams['assignments']) != len(assignments):
        raise ValidationError('registry-salt provision assignment proof count differs')
    expected = [(streams['init'], init, INIT_ROUTE), (streams['bind'], bind, BIND_ROUTE),
                (streams['confirm'], confirm, CONFIRM_ROUTE)]
    expected.extend((stream, body, ASSIGN_ROUTE)
                    for stream, body in zip(streams['assignments'], assignments))
    for stream, body, route in expected:
        if parseReply(parser, stream, {route}).serder.raw != body.raw:
            raise ValidationError('registry-salt provision proof differs from its exact original body')
    return provision


def validateReceipt(provision, receipt, confirm):
    """Return a target member's literal retained acknowledgement for one provision.

    Parameters: provision is previously validated; receipt and confirm are
        SerderKERI bodies. Returns: receipt unchanged, without asserting that a
        transaction committed. Caller authenticates the member signature and
        emits receipts only after durable custody commit.
    Raises: ValidationError for another member, context, commitment or status.
    """
    provisionData = _provision(provision)
    confirmed = _linked(confirm, provisionData)
    data = _body(receipt, RECEIPT_ROUTE, {'provision', 'origin', 'registry', 'party',
                 'admission', 'commitment', 'retained', 'suite', 'profile', 'purpose'})
    expected = dict(provision=provision.said, origin=confirm.said,
        registry=provisionData['registry'], party=provisionData['party'],
        admission=provisionData['admission'], commitment=confirmed['commitment'])
    if (receipt.pre != provisionData['target'] or data['retained'] is not True or
            any(data[name] != value for name, value in expected.items())):
        raise ValidationError('registry-salt receipt does not acknowledge exact target retention')
    return receipt


def receiptReply(provision, confirm, *, stamp=None):
    """Construct an unsigned positive receipt after the caller commits custody.

    Parameters: provision is previously validated; confirm is its original
        confirmation; stamp is optional. Returns: locally validated receipt
        naming provision.target as sender and retained=True. Does not perform
        or prove a custody transaction. Raises: ValidationError on bad context.
    """
    data = _provision(provision)
    confirmed = _linked(confirm, data)
    receipt = _newReply(data['target'], RECEIPT_ROUTE,
        dict(provision=provision.said, origin=confirm.said, registry=data['registry'],
             party=data['party'], admission=data['admission'],
             commitment=confirmed['commitment'], retained=True), stamp)
    return validateReceipt(provision, receipt, confirm)
