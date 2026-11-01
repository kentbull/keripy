# -*- encoding: utf-8 -*-
"""
Minimal accepted-state transfer support for adding a member to a multisig AID.

This module is intentionally small and synchronous.  It provides the protocol
core used by adapters, but no transport, mailbox, persistence, retry, or
projection machinery.
"""

import base64
from dataclasses import dataclass
from functools import partial

from hio.base import doing
from hio.help import decking

from . import core, kering
from .app import habbing, signing
from .core import coring, eventing, parsing, routing, scheming, serdering
from .db import basing, dbing
from .vdr import eventing as teventing
from .vdr import verifying


Route = "/multisig/add"
Operations = frozenset(("propose", "approve", "deliver", "reject"))
FrameKinds = frozenset(("kel", "schema", "tel", "acdc", "rpy"))


class SyncError(kering.ValidationError):
    """Raised when a bounded multisig state transfer is invalid."""


def _encode(raw):
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("utf-8")


def _decode(text):
    if not isinstance(text, str):
        raise SyncError("encoded material must be a string")
    try:
        return base64.urlsafe_b64decode(text + ("=" * (-len(text) % 4)))
    except Exception as ex:
        raise SyncError("invalid base64url material") from ex


def _serder(raw):
    raw = raw.raw if hasattr(raw, "raw") else raw
    ims = bytearray(raw)
    serder = serdering.Serdery().reap(ims=ims, gvrsn=kering.Vrsn_1_0)
    return serder, bytes(ims)


@dataclass(frozen=True)
class Frame:
    """One exact canonical CESR frame committed by a catalog."""

    kind: str
    body: str
    attachments: str
    digest: str
    said: str
    pre: str = ""
    sn: int = None

    @property
    def raw(self):
        return _decode(self.body) + _decode(self.attachments)

    def asdict(self):
        return dict(kind=self.kind,
                    body=self.body,
                    attachments=self.attachments,
                    digest=self.digest,
                    said=self.said,
                    pre=self.pre,
                    sn=self.sn)

    @classmethod
    def from_raw(cls, kind, raw):
        """Create a frame while separating the exact body and attachment bytes."""
        if kind not in FrameKinds:
            raise SyncError(f"unsupported frame kind={kind}")

        raw = bytes(raw)
        if kind == "schema":
            schemer = scheming.Schemer(raw=raw)
            body = raw
            attachments = b""
            said = schemer.said
            pre = ""
            sn = None
        else:
            serder, attachments = _serder(raw)
            body = serder.raw
            said = serder.said
            pre = getattr(serder, "pre", "") or ""
            try:
                sn = serder.sn
            except (AttributeError, TypeError, ValueError):
                sn = None

        return cls(kind=kind,
                   body=_encode(body),
                   attachments=_encode(attachments),
                   digest=coring.Diger(ser=raw).qb64,
                   said=said,
                   pre=pre,
                   sn=sn)

    @classmethod
    def from_dict(cls, data):
        """Load a frame and require all committed coordinates to be exact."""
        fields = ("kind", "body", "attachments", "digest", "said", "pre", "sn")
        if not isinstance(data, dict) or set(data) != set(fields):
            raise SyncError("invalid frame fields")

        frame = cls(**{field: data[field] for field in fields})
        rebuilt = cls.from_raw(kind=frame.kind, raw=frame.raw)
        if rebuilt != frame:
            raise SyncError(f"frame commitment mismatch for said={frame.said}")
        return frame


@dataclass(frozen=True)
class Catalog:
    """Deterministic manifest and the exact frames it commits."""

    manifest: dict
    frames: tuple
    raw: bytes
    said: str

    @property
    def gid(self):
        return self.manifest["gid"]

    @property
    def target(self):
        return self.manifest["target"]

    @property
    def rotation(self):
        return self.manifest["rotation"]

    @property
    def smids(self):
        return self.manifest["smids"]

    @property
    def rmids(self):
        return self.manifest["rmids"]

    @classmethod
    def from_raw(cls, raw):
        """Load and independently verify a canonical catalog."""
        raw = bytes(raw)
        try:
            manifest = coring.loads(raw=raw, kind=coring.Kinds.json)
        except Exception as ex:
            raise SyncError("invalid catalog JSON") from ex

        expected = ("d", "type", "version", "gid", "target",
                    "smids", "rmids", "rotation", "frames")
        if not isinstance(manifest, dict) or tuple(manifest) != expected:
            raise SyncError("invalid catalog fields or field ordering")
        if manifest["type"] != "multisig.add" or manifest["version"] != 1:
            raise SyncError("unsupported catalog type or version")
        smids = manifest["smids"]
        rmids = manifest["rmids"]
        if (not isinstance(smids, list) or len(smids) != 3 or
                len(set(smids)) != 3 or smids[-1] != manifest["target"] or
                rmids != smids):
            raise SyncError("catalog is not the bounded one-member addition")

        rotation = manifest["rotation"]
        rfields = ("said", "digest", "body", "sn", "prior")
        if not isinstance(rotation, dict) or tuple(rotation) != rfields:
            raise SyncError("invalid rotation commitment")
        rserder, ratc = _serder(_decode(rotation["body"]))
        if (ratc or rserder.ilk != kering.Ilks.rot or
                rserder.pre != manifest["gid"] or
                rserder.said != rotation["said"] or
                coring.Diger(ser=rserder.raw).qb64 != rotation["digest"] or
                rserder.sn != rotation["sn"] or
                rserder.ked["p"] != rotation["prior"]):
            raise SyncError("rotation commitment mismatch")

        saider = coring.Saider(qb64=manifest["d"])
        if not saider.verify(sad=manifest, prefixed=True):
            raise SyncError("invalid catalog SAID")
        if coring.dumps(manifest, kind=coring.Kinds.json) != raw:
            raise SyncError("catalog is not canonically serialized")

        frames = tuple(Frame.from_dict(item) for item in manifest["frames"])
        if len({(frame.kind, frame.said) for frame in frames}) != len(frames):
            raise SyncError("duplicate catalog frame")
        catalog = cls(manifest=manifest, frames=frames,
                      raw=raw, said=saider.qb64)
        _validate_catalog_profile(catalog)
        return catalog


def build_catalog(*, gid, target, smids, rmids, rotation, frames):
    """Build a deterministic, SAIDified catalog from canonical frames."""
    if not gid or not target:
        raise SyncError("gid and target are required")
    if (not isinstance(smids, (list, tuple)) or
            not isinstance(rmids, (list, tuple)) or
            len(set(smids)) != len(smids) or
            len(set(rmids)) != len(rmids) or
            target not in smids or target not in rmids):
        raise SyncError("ordered final smids/rmids must uniquely include target")

    rserder, ratc = _serder(rotation)
    if ratc:
        raise SyncError("rotation commitment accepts the exact body only")
    if rserder.ilk != kering.Ilks.rot or rserder.pre != gid:
        raise SyncError("rotation must be a rot event for gid")

    normalized = tuple(frames)
    if not normalized:
        raise SyncError("catalog must contain at least one frame")
    if any(not isinstance(frame, Frame) for frame in normalized):
        raise SyncError("catalog frames must be Frame instances")

    rotation = dict(said=rserder.said,
                    digest=coring.Diger(ser=rserder.raw).qb64,
                    body=_encode(rserder.raw),
                    sn=rserder.sn,
                    prior=rserder.ked["p"])
    manifest = dict(d="",
                    type="multisig.add",
                    version=1,
                    gid=gid,
                    target=target,
                    smids=list(smids),
                    rmids=list(rmids),
                    rotation=rotation,
                    frames=[frame.asdict() for frame in normalized])
    saider, manifest = coring.Saider.saidify(sad=manifest)
    raw = coring.dumps(manifest, kind=coring.Kinds.json)
    return Catalog(manifest=manifest,
                   frames=normalized,
                   raw=raw,
                   said=saider.qb64)


def _grouped(body, groups):
    atc = bytearray()
    for code, values in groups:
        values = [bytes(value) for value in values]
        if not values:
            continue
        atc.extend(core.Counter(code=code,
                                count=len(values),
                                gvrsn=kering.Vrsn_1_0).qb64b)
        for value in values:
            atc.extend(value)

    msg = bytearray(body)
    if atc:
        if len(atc) % 4:
            raise SyncError("nonintegral canonical attachment group")
        msg.extend(core.Counter(code=core.Codens.AttachmentGroup,
                                count=len(atc) // 4,
                                gvrsn=kering.Vrsn_1_0).qb64b)
        msg.extend(atc)
    return bytes(msg)


def _canonical_kel(db, pre):
    kever = db.kevers.get(pre)
    if kever is None:
        raise SyncError(f"missing KEL for pre={pre}")
    if kever.delegated or kever.wits:
        raise SyncError(f"delegated or witnessed KEL is unsupported pre={pre}")

    preb = pre.encode("utf-8")
    frames = []
    for dig in db.getKelIter(pre=preb):
        dig = bytes(dig)
        dgkey = dbing.dgKey(preb, dig)
        raw = db.getEvt(key=dgkey)
        sigs = db.getSigs(key=dgkey)
        if not raw or not sigs:
            raise SyncError(f"incomplete KEL event pre={pre} dig={dig!r}")
        if db.getWigs(key=dgkey):
            raise SyncError(f"witnessed KEL is outside the minimal profile pre={pre}")
        if db.getAes(key=dgkey):
            raise SyncError(f"delegated KEL is outside the minimal profile pre={pre}")

        groups = [
            (core.Codens.ControllerIdxSigs, sigs),
            (core.Codens.TransReceiptQuadruples, db.getVrcs(key=dgkey)),
            (core.Codens.NonTransReceiptCouples, db.getRcts(key=dgkey)),
        ]
        frames.append(Frame.from_raw("kel", _grouped(raw, groups)))
    if not frames:
        raise SyncError(f"missing KEL for pre={pre}")
    return frames


def _canonical_tel(reger, pre):
    frames = []
    for msg in reger.clonePreIter(pre=pre):
        frame = Frame.from_raw("tel", msg)
        serder, _ = _serder(frame.raw)
        if serder.ilk in (kering.Ilks.vrt, kering.Ilks.rev, kering.Ilks.brv):
            raise SyncError(f"TEL event {serder.ilk} is outside the minimal profile")
        frames.append(frame)
    if not frames:
        raise SyncError(f"missing TEL for pre={pre}")
    return frames


def _reply_frame(ghab, *, endpoint=None, location=None):
    if endpoint is not None:
        if not isinstance(endpoint, tuple) or len(endpoint) != 3:
            raise SyncError("endpoint must be a (cid, role, eid) tuple")
        raw = ghab.loadEndRole(cid=endpoint[0], role=endpoint[1], eid=endpoint[2])
    else:
        if not isinstance(location, tuple) or len(location) != 2:
            raise SyncError("location must be an (eid, scheme) tuple")
        raw = ghab.loadLocScheme(eid=location[0], scheme=location[1])
    if not raw:
        raise SyncError("missing effective endpoint reply")
    frame = Frame.from_raw("rpy", raw)
    preflight_frame(frame)
    return frame


def _has_ref(value):
    if isinstance(value, dict):
        return "$ref" in value or any(_has_ref(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_ref(item) for item in value)
    return False


def _validate_catalog_profile(catalog):
    """Require the receiver-visible shape of the one supported spike profile."""
    grouped = {
        kind: [frame for frame in catalog.frames if frame.kind == kind]
        for kind in FrameKinds
    }
    if (len(grouped["schema"]) != 1 or
            len(grouped["acdc"]) != 1 or
            len(grouped["tel"]) != 2 or
            len(grouped["rpy"]) != 2 or
            not grouped["kel"]):
        raise SyncError("catalog does not contain the bounded state profile")

    creder = serdering.SerderACDC(
        raw=_decode(grouped["acdc"][0].body))
    if (creder.issuer != catalog.gid or
            not creder.attrib.get("i") or
            creder.edge or
            "u" in creder.sad or
            "u" in creder.attrib or
            any(not isinstance(value, str)
                for value in creder.attrib.values()) or
            grouped["schema"][0].said != creder.schema):
        raise SyncError("catalog credential is outside the bounded profile")
    schemer = scheming.Schemer(raw=grouped["schema"][0].raw)
    if _has_ref(schemer.sed):
        raise SyncError("catalog schema has an external reference")

    tel = [_serder(_decode(frame.body))[0] for frame in grouped["tel"]]
    registries = [serder for serder in tel
                  if serder.ilk == kering.Ilks.vcp]
    issuances = [serder for serder in tel
                 if serder.ilk == kering.Ilks.iss]
    if (len(registries) != 1 or len(issuances) != 1 or
            registries[0].pre != creder.regi or
            registries[0].ked.get("ii") != catalog.gid or
            registries[0].ked.get("b") or
            eventing.TraitDex.NoBackers not in
            registries[0].ked.get("c", []) or
            issuances[0].pre != creder.said or
            issuances[0].ked.get("ri") != creder.regi):
        raise SyncError("catalog TELs are outside the bounded profile")

    replies = [_serder(_decode(frame.body))[0]
               for frame in grouped["rpy"]]
    ends = [serder for serder in replies
            if serder.ked.get("r") == "/end/role/add"]
    locations = [serder for serder in replies
                 if serder.ked.get("r") == "/loc/scheme"]
    if len(ends) != 1 or len(locations) != 1:
        raise SyncError("catalog must contain one endpoint and location")
    end = ends[0].ked.get("a", {})
    location = locations[0].ked.get("a", {})
    if (end.get("cid") != catalog.gid or
            not end.get("role") or
            not end.get("eid") or
            location.get("eid") != end.get("eid") or
            not location.get("scheme") or
            not location.get("url")):
        raise SyncError("catalog endpoint state is outside the bounded profile")

    kel_roots = {frame.pre for frame in grouped["kel"]}
    expected_roots = (set(catalog.smids) |
                      {catalog.gid, creder.attrib["i"], end["eid"]})
    group_frames = [frame for frame in grouped["kel"]
                    if frame.pre == catalog.gid]
    if (kel_roots != expected_roots or not group_frames or
            max(group_frames, key=lambda frame: frame.sn).said !=
            catalog.rotation["prior"]):
        raise SyncError("catalog KEL closure is outside the bounded profile")


def _has_items(items):
    return next(iter(items), None) is not None


def _pending_state(db, reger, *, gid, kel_pres, tel_pres, credential,
                   endpoint, location):
    """Return pending stores that can change the selected source closure."""
    pending = []
    kel_pres = set(kel_pres)
    tel_pres = set(tel_pres)

    kel_iters = (
        ("ures", db.getUreItemIter),
        ("vres", db.getVreItemIter),
        ("pses", db.getPseItemIter),
        ("pwes", db.getPweItemIter),
        ("uwes", db.getUweItemIter),
        ("ooes", db.getOoeItemIter),
        ("ldes", db.getLdeItemIter),
    )
    for name, getter in kel_iters:
        if any(_has_items(getter(key=pre.encode("utf-8") + b"."))
               for pre in kel_pres):
            pending.append(name)

    if any(_has_items(db.getDelItemIter(pre.encode("utf-8") + b"."))
           for pre in kel_pres):
        pending.append("dels")

    for name in ("misfits", "delegables", "udes",
                 "dpub", "dpwe", "dune"):
        suber = getattr(db, name)
        if any(_has_items(suber.getItemIter(keys=(pre,), topive=True))
               for pre in kel_pres):
            pending.append(name)

    if any(_has_items(db.pdes.getOnItemIter(keys=pre))
           for pre in kel_pres):
        pending.append("pdes")

    for name in ("gpwe", "gdee", "gpse"):
        suber = getattr(db, name)
        if suber.get(keys=(gid,)):
            pending.append(name)

    for _, saider in db.rpes.getItemIter():
        serder = db.rpys.get(keys=(saider.qb64,))
        if serder is None:
            continue
        route = serder.ked.get("r")
        attrs = serder.ked.get("a", {})
        if not isinstance(attrs, dict):
            continue
        if (route in ("/end/role/add", "/end/role/cut") and
                (attrs.get("cid"), attrs.get("role"), attrs.get("eid")) ==
                endpoint):
            pending.append("rpes")
            break
        if (route == "/loc/scheme" and
                (attrs.get("eid"), attrs.get("scheme")) == location):
            pending.append("rpes")
            break

    for _, serder in db.epse.getItemIter():
        attrs = serder.ked.get("a", {})
        if not isinstance(attrs, dict):
            continue
        if (serder.ked.get("r", "").startswith("/multisig/") and
                attrs.get("gid") == gid):
            pending.append("epse")
            break

    tel_prefixes = tuple(pre.encode("utf-8") + b"." for pre in tel_pres)

    def has_tel_items(items):
        return any(any(bytes(key).startswith(prefix)
                       for prefix in tel_prefixes)
                   for key, _ in items)

    tel_iters = (
        ("oots", reger.getOotItemIter()),
        ("twes", reger.getTweItemIter()),
        ("taes", reger.getTaeItemIter()),
    )
    pending.extend(name for name, items in tel_iters if has_tel_items(items))

    for name in ("mre", "mce", "mse"):
        if getattr(reger, name).get(keys=(credential,)) is not None:
            pending.append(name)

    if _has_items(reger.cmse.getItemIter(keys=(credential,), topive=True)):
        pending.append("cmse")

    for name in ("tpwe", "tmse", "tede"):
        suber = getattr(reger, name)
        if any(_has_items(suber.getItemIter(keys=(pre,), topive=True))
               for pre in tel_pres):
            pending.append(name)

    return tuple(sorted(set(pending)))


def prepare(ghab, reger, *, target, rotation, registry, credential, schema,
            member_pres=None, smids=None, rmids=None,
            endpoint=None, location=None):
    """
    Extract the one deliberately bounded source-state profile from live stores.

    `endpoint` is `(cid, role, eid)` and `location` is `(eid, scheme)`.
    Registry, credential, and schema are their qb64 identifiers.
    """
    if not isinstance(ghab, (habbing.GroupHab, habbing.SignifyGroupHab)):
        raise SyncError("prepare requires a group habitat")
    if ghab.kever.delegated or ghab.kever.wits:
        raise SyncError("delegated or witnessed groups are unsupported")
    if len(ghab.kever.verfers) != 2 or ghab.kever.tholder.num != 2:
        raise SyncError("minimal profile requires a prior 2-of-2 group")
    if target not in ghab.rmids:
        raise SyncError("target must be a precommitted rotation member")
    if endpoint is None or location is None:
        raise SyncError("one endpoint and one location are required")
    if (not isinstance(endpoint, tuple) or len(endpoint) != 3 or
            not isinstance(location, tuple) or len(location) != 2 or
            endpoint[0] != ghab.pre or endpoint[2] != location[0]):
        raise SyncError("group endpoint and matching endpoint location are required")
    endpoints = {
        keys for keys, end in ghab.db.ends.getItemIter(keys=(ghab.pre,))
        if end.allowed or end.enabled
    }
    locations = {
        keys for keys, loc in ghab.db.locs.getItemIter(keys=(endpoint[2],))
        if loc.url
    }
    if endpoints != {endpoint} or locations != {location}:
        raise SyncError("minimal profile requires one effective endpoint and location")

    rserder, ratc = _serder(rotation)
    if ratc or rserder.ilk != kering.Ilks.rot or rserder.pre != ghab.pre:
        raise SyncError("invalid adding rotation body")
    if (rserder.sn != ghab.kever.sn + 1 or
            rserder.ked["p"] != ghab.kever.serder.said or
            rserder.ked.get("b")):
        raise SyncError("rotation does not extend the unwitnessed source state")

    smids = list(smids if smids is not None else ghab.rmids)
    rmids = list(rmids if rmids is not None else ghab.rmids)
    if (smids[:-1] != list(ghab.smids) or smids[-1:] != [target] or
            rmids != smids or len(smids) != len(rserder.verfers) or
            rserder.tholder.num != len(smids) or
            rserder.ntholder.num != len(rmids)):
        raise SyncError("manifest must commit the one exact target addition")
    try:
        expected_keys = [ghab.db.kevers[mid].verfers[0].qb64 for mid in smids]
        expected_digs = [ghab.db.kevers[mid].ndigers[0].qb64 for mid in rmids]
    except (KeyError, IndexError) as ex:
        raise SyncError("member KEL state cannot satisfy rotation membership") from ex
    if ([verfer.qb64 for verfer in rserder.verfers] != expected_keys or
            [diger.qb64 for diger in rserder.ndigers] != expected_digs):
        raise SyncError("rotation key ordering does not match committed members")

    pres = set(member_pres if member_pres is not None
               else [*ghab.smids, *ghab.rmids])
    if pres != set(smids):
        raise SyncError("selected member KELs must match final membership")

    creder, prefixer, seqner, saider = reger.cloneCred(said=credential)
    if creder.issuer != ghab.pre or creder.regi != registry:
        raise SyncError("credential is not issued by the selected group registry")
    if creder.schema != schema or creder.edge:
        raise SyncError("credential schema mismatch or chained credential")
    if (reger.saved.get(keys=(credential,)) is None or
            any(escrow.get(keys=(credential,)) is not None
                for escrow in (reger.mre, reger.mce, reger.mse))):
        raise SyncError("credential has pending verification state")
    if not isinstance(creder.attrib, dict) or not creder.attrib.get("i"):
        raise SyncError("credential must have an issuee")
    if "u" in creder.sad or "u" in creder.attrib:
        raise SyncError("private credential material is outside the minimal profile")
    if any(not isinstance(value, str) for value in creder.attrib.values()):
        raise SyncError("credential attributes must be string scalars")

    dependencies = pres | {creder.attrib["i"], endpoint[2]}
    pending_scope = dict(
        gid=ghab.pre,
        kel_pres=dependencies | {ghab.pre},
        tel_pres={registry, credential},
        credential=credential,
        endpoint=endpoint,
        location=location)
    pending = _pending_state(ghab.db, reger, **pending_scope)
    if pending:
        raise SyncError(f"pending source state prevents sync: {', '.join(pending)}")

    frames = []
    for pre in sorted(dependencies - {ghab.pre}):
        frames.extend(_canonical_kel(ghab.db, pre))
    frames.extend(_canonical_kel(ghab.db, ghab.pre))

    if registry not in reger.tevers:
        raise SyncError("registry is not accepted")
    registries = {regk for regk, candidate in reger.tevers.items()
                  if candidate.pre == ghab.pre}
    if registries != {registry}:
        raise SyncError("minimal profile requires exactly one group registry")
    credentials = set()
    for saider in reger.issus.get(keys=(ghab.pre,)):
        issued = reger.creds.get(keys=(saider.qb64,))
        if issued is not None and issued.regi == registry:
            credentials.add(saider.qb64)
    if credentials != {credential}:
        raise SyncError("minimal profile requires exactly one registry credential")
    tever = reger.tevers[registry]
    if tever.baks:
        raise SyncError("registry backers are outside the minimal profile")
    state = tever.vcState(credential)
    if state is None or state.et not in (kering.Ilks.iss, kering.Ilks.bis):
        raise SyncError("credential is not active")

    schemer = ghab.db.schema.get(keys=(schema,))
    if schemer is None or schemer.said != schema or _has_ref(schemer.sed):
        raise SyncError("missing schema or external schema reference")
    frames.append(Frame.from_raw("schema", schemer.raw))
    frames.extend(_canonical_tel(reger, registry))
    frames.extend(_canonical_tel(reger, credential))
    frames.append(Frame.from_raw(
        "acdc", signing.serialize(creder, prefixer, seqner, saider)))
    frames.append(_reply_frame(ghab, endpoint=endpoint))
    frames.append(_reply_frame(ghab, location=location))

    for frame in frames:
        preflight_frame(frame)
    pending = _pending_state(ghab.db, reger, **pending_scope)
    if pending:
        raise SyncError(f"source state became pending during sync: {', '.join(pending)}")
    return build_catalog(gid=ghab.pre,
                         target=target,
                         smids=smids,
                         rmids=rmids,
                         rotation=rserder.raw,
                         frames=frames)


class _Capture:
    def __init__(self):
        self.calls = []

    def add(self, name, **kwa):
        self.calls.append((name, kwa))

    @property
    def main(self):
        mains = [call for call in self.calls
                 if call[0] in ("kvy.event", "tvy.event", "rvy.reply", "vry.credential")]
        if len(mains) != 1:
            raise SyncError(f"expected one semantic callback, got {len(mains)}")
        return mains[0]


class _Kvy:
    def __init__(self, capture):
        self.capture = capture

    def processEvent(self, *, serder, sigers, wigers, delseqner, delsaider,
                     firner, dater, local):
        self.capture.add("kvy.event", serder=serder, sigers=sigers,
                         wigers=wigers, delseqner=delseqner,
                         delsaider=delsaider, firner=firner, dater=dater,
                         local=local)

    def processAttachedReceiptCouples(self, serder, cigars, firner=None, local=None):
        self.capture.add("kvy.cigars", serder=serder, cigars=cigars,
                         firner=firner, local=local)

    def processAttachedReceiptQuadruples(self, serder, trqs, firner=None, local=None):
        self.capture.add("kvy.trqs", serder=serder, trqs=trqs,
                         firner=firner, local=local)

    def processReceipt(self, *, serder, cigars, local):
        self.capture.add("kvy.receipt", serder=serder, cigars=cigars, local=local)

    def processReceiptWitness(self, *, serder, wigers, local):
        self.capture.add("kvy.witness", serder=serder, wigers=wigers, local=local)

    def processReceiptTrans(self, *, serder, tsgs, local):
        self.capture.add("kvy.trans", serder=serder, tsgs=tsgs, local=local)


class _Tvy:
    def __init__(self, capture):
        self.capture = capture

    def processEvent(self, *, serder, seqner, saider, wigers):
        self.capture.add("tvy.event", serder=serder, seqner=seqner,
                         saider=saider, wigers=wigers)


class _Rvy:
    def __init__(self, capture):
        self.capture = capture

    def processReply(self, serder, cigars=None, tsgs=None):
        if bool(cigars) == bool(tsgs):
            raise SyncError("reply must use exactly one signer mode")
        self.capture.add("rvy.reply", serder=serder,
                         cigars=cigars or [], tsgs=tsgs or [])


class _Vry:
    def __init__(self, capture):
        self.capture = capture

    def processCredential(self, *, creder, prefixer, seqner, saider):
        if prefixer is None or seqner is None or saider is None:
            raise SyncError("credential requires one source seal triple")
        self.capture.add("vry.credential", creder=creder, prefixer=prefixer,
                         seqner=seqner, saider=saider)


def _raw_from_capture(capture):
    name, kwa = capture.main
    if name == "kvy.event":
        if kwa["firner"] is not None or kwa["dater"] is not None:
            raise SyncError("source first-seen couples are forbidden")
        groups = [(core.Codens.ControllerIdxSigs,
                   [siger.qb64b for siger in kwa["sigers"]])]
        if kwa["wigers"]:
            groups.append((core.Codens.WitnessIdxSigs,
                           [siger.qb64b for siger in kwa["wigers"]]))
        if kwa["delseqner"] is not None or kwa["delsaider"] is not None:
            if kwa["delseqner"] is None or kwa["delsaider"] is None:
                raise SyncError("incomplete source seal couple")
            groups.append((core.Codens.SealSourceCouples,
                           [kwa["delseqner"].qb64b + kwa["delsaider"].qb64b]))
        for call, args in capture.calls:
            if call == "kvy.trqs":
                groups.append((core.Codens.TransReceiptQuadruples,
                               [prefixer.qb64b + seqner.qb64b + diger.qb64b + siger.qb64b
                                for prefixer, seqner, diger, siger in args["trqs"]]))
            elif call == "kvy.cigars":
                groups.append((core.Codens.NonTransReceiptCouples,
                               [cigar.verfer.qb64b + cigar.qb64b
                                for cigar in args["cigars"]]))
            elif call not in ("kvy.event",):
                raise SyncError(f"unsupported KEL callback={call}")
        return _grouped(kwa["serder"].raw, groups)

    if name == "tvy.event":
        groups = []
        if kwa["wigers"]:
            groups.append((core.Codens.WitnessIdxSigs,
                           [siger.qb64b for siger in kwa["wigers"]]))
        if kwa["seqner"] is not None or kwa["saider"] is not None:
            if kwa["seqner"] is None or kwa["saider"] is None:
                raise SyncError("incomplete TEL source seal couple")
            groups.append((core.Codens.SealSourceCouples,
                           [kwa["seqner"].qb64b + kwa["saider"].qb64b]))
        return _grouped(kwa["serder"].raw, groups)

    if name == "rvy.reply":
        if kwa["cigars"]:
            return bytes(eventing.messagize(serder=kwa["serder"],
                                            cigars=kwa["cigars"],
                                            pipelined=True))
        if len(kwa["tsgs"]) != 1:
            raise SyncError("minimal reply requires one transferable signer group")
        prefixer, seqner, diger, sigers = kwa["tsgs"][0]
        seal = eventing.SealEvent(i=prefixer.qb64,
                                  s=seqner.snh,
                                  d=diger.qb64)
        return bytes(eventing.messagize(serder=kwa["serder"],
                                        sigers=sigers,
                                        seal=seal,
                                        pipelined=True))

    if name == "vry.credential":
        return signing.serialize(kwa["creder"], kwa["prefixer"],
                                 kwa["seqner"], kwa["saider"])

    raise SyncError(f"unsupported callback={name}")


@dataclass(frozen=True)
class Preflight:
    kind: str
    said: str
    trace: tuple


def preflight_frame(frame):
    """Prove one canonical frame through the unchanged pinned Parser."""
    if not isinstance(frame, Frame):
        raise SyncError("preflight requires a Frame")
    if coring.Diger(ser=frame.raw).qb64 != frame.digest:
        raise SyncError(f"frame digest mismatch for said={frame.said}")

    if frame.kind == "schema":
        schemer = scheming.Schemer(raw=frame.raw)
        if schemer.said != frame.said or _decode(frame.attachments):
            raise SyncError("invalid schema frame")
        return Preflight(kind=frame.kind, said=frame.said, trace=("schema",))

    capture = _Capture()
    ims = bytearray(frame.raw)
    parser = parsing.Parser()
    imsgen = parser.msgParsator(ims=ims,
                                framed=True,
                                kvy=_Kvy(capture),
                                tvy=_Tvy(capture),
                                rvy=_Rvy(capture),
                                vry=_Vry(capture),
                                exc=None,
                                local=False)
    try:
        next(imsgen)
    except StopIteration:
        pass
    else:
        raise SyncError(f"short canonical frame for said={frame.said}")
    if ims:
        raise SyncError(f"trailing material for said={frame.said}")

    name, kwa = capture.main
    actual = {"kvy.event": "kel",
              "tvy.event": "tel",
              "rvy.reply": "rpy",
              "vry.credential": "acdc"}[name]
    if actual != frame.kind or kwa.get("serder", kwa.get("creder")).said != frame.said:
        raise SyncError(f"frame domain mismatch for said={frame.said}")
    if _raw_from_capture(capture) != frame.raw:
        raise SyncError(f"noncanonical attachment set for said={frame.said}")

    return Preflight(kind=frame.kind,
                     said=frame.said,
                     trace=tuple(call for call, _ in capture.calls))


def verify_approvals(catalog, sigers):
    """Verify indexed approvals using the KEL and prior threshold in catalog."""
    if not isinstance(catalog, Catalog):
        raise SyncError("approval verification requires a Catalog")
    loaded = Catalog.from_raw(catalog.raw)
    if loaded.said != catalog.said or loaded.frames != catalog.frames:
        raise SyncError("catalog object does not match its canonical bytes")
    catalog = loaded
    sigers = [siger if isinstance(siger, core.Siger) else core.Siger(qb64=siger)
              for siger in sigers]

    with basing.openDB(name="multisig-add-approval", temp=True) as db:
        cues = decking.Deck()
        rvy = routing.Revery(db=db, cues=cues, lax=True, local=False)
        kvy = eventing.Kevery(db=db, cues=cues, rvy=rvy, lax=True,
                              local=False, cloned=False, direct=False, check=False)
        kvy.registerReplyRoutes(router=rvy.rtr)
        for frame in catalog.frames:
            if frame.kind != "kel":
                continue
            preflight_frame(frame)
            _parse_real(frame, kvy=kvy, local=False)

        if catalog.gid not in db.kevers:
            raise SyncError("catalog does not establish the prior group KEL")
        kever = db.kevers[catalog.gid]
        if (kever.serder.said != catalog.rotation["prior"] or
                len(kever.verfers) != 2 or kever.tholder.num != 2):
            raise SyncError("catalog group state does not match rotation prior")
        rserder, _ = _serder(_decode(catalog.rotation["body"]))
        try:
            keys = [db.kevers[mid].verfers[0].qb64 for mid in catalog.smids]
            digs = [db.kevers[mid].ndigers[0].qb64 for mid in catalog.rmids]
        except (KeyError, IndexError) as ex:
            raise SyncError("catalog member KEL is incomplete") from ex
        if ([verfer.qb64 for verfer in rserder.verfers] != keys or
                [diger.qb64 for diger in rserder.ndigers] != digs or
                rserder.tholder.num != 3 or rserder.ntholder.num != 3):
            raise SyncError("catalog rotation does not match member KEL ordering")

        _, indices = eventing.verifySigs(catalog.raw, sigers, kever.verfers)
        if not kever.tholder.satisfy(indices):
            raise SyncError("insufficient prior-group manifest approval")
        return tuple(sorted(indices))


@dataclass
class ReplayProcessors:
    """One isolated real processor set over already-open target stores."""

    hby: object
    reger: object
    cues: decking.Deck
    rvy: routing.Revery
    kvy: eventing.Kevery
    tvy: teventing.Tevery
    vry: verifying.Verifier

    @classmethod
    def open(cls, hby, reger):
        cues = decking.Deck()
        rvy = routing.Revery(db=hby.db, cues=cues, lax=True, local=False)
        kvy = eventing.Kevery(db=hby.db, cues=cues, rvy=rvy, lax=True,
                              local=False, cloned=False, direct=False, check=False)
        kvy.registerReplyRoutes(router=rvy.rtr)
        tvy = teventing.Tevery(reger=reger, db=hby.db, cues=cues,
                               rvy=rvy, lax=True, local=False)
        tvy.registerReplyRoutes(router=rvy.rtr)
        vry = verifying.Verifier(hby=hby, reger=reger)
        return cls(hby=hby, reger=reger, cues=cues,
                   rvy=rvy, kvy=kvy, tvy=tvy, vry=vry)


def _parse_real(frame, *, kvy=None, tvy=None, rvy=None, vry=None, local=False):
    ims = bytearray(frame.raw)
    imsgen = parsing.Parser().msgParsator(ims=ims, framed=True,
                                          kvy=kvy, tvy=tvy,
                                          rvy=rvy, vry=vry,
                                          exc=None, local=local)
    try:
        next(imsgen)
    except StopIteration:
        pass
    else:
        raise SyncError(f"real replay shortage for said={frame.said}")
    if ims:
        raise SyncError(f"real replay left trailing bytes for said={frame.said}")


def _stored_reply(frame, db):
    serder, _ = _serder(_decode(frame.body))
    route = serder.ked["r"]
    attrs = serder.ked["a"]
    if route == "/end/role/add":
        said = db.eans.get(keys=(attrs["cid"], attrs["role"], attrs["eid"]))
    elif route == "/loc/scheme":
        said = db.lans.get(keys=(attrs["eid"], attrs["scheme"]))
    else:
        return None
    if said is None or said.qb64 != frame.said:
        return None

    stored = db.rpys.get(keys=(frame.said,))
    cigars = db.scgs.get(keys=(frame.said,))
    tsgs = eventing.fetchTsgs(db=db.ssgs, saider=said)
    if stored is None or bool(cigars) == bool(tsgs):
        return None
    if cigars:
        if len(cigars) != 1:
            return None
        verfer, cigar = cigars[0]
        cigar.verfer = verfer
        return bytes(eventing.messagize(serder=stored,
                                        cigars=[cigar],
                                        pipelined=True))
    if len(tsgs) != 1:
        return None
    prefixer, seqner, diger, sigers = tsgs[0]
    seal = eventing.SealEvent(i=prefixer.qb64,
                              s=seqner.snh,
                              d=diger.qb64)
    return bytes(eventing.messagize(serder=stored,
                                    sigers=sigers,
                                    seal=seal,
                                    pipelined=True))


def _stored_frame(frame, hby, reger):
    """Reconstruct the exact committed primitive evidence from target stores."""
    if frame.kind == "schema":
        schemer = hby.db.schema.get(keys=(frame.said,))
        return schemer.raw if schemer is not None else None
    if frame.kind == "kel":
        dgkey = dbing.dgKey(frame.pre, frame.said)
        raw = hby.db.getEvt(dgkey)
        sigs = hby.db.getSigs(dgkey)
        if raw is None or not sigs:
            return None
        return _grouped(
            raw,
            ((core.Codens.ControllerIdxSigs, sigs),
             (core.Codens.TransReceiptQuadruples, hby.db.getVrcs(dgkey)),
             (core.Codens.NonTransReceiptCouples, hby.db.getRcts(dgkey))))
    if frame.kind == "tel":
        try:
            return bytes(reger.cloneTvt(frame.pre, frame.said))
        except kering.MissingEntryError:
            return None
    if frame.kind == "acdc":
        try:
            creder, prefixer, seqner, saider = reger.cloneCred(frame.said)
        except kering.MissingEntryError:
            return None
        return signing.serialize(creder, prefixer, seqner, saider)
    if frame.kind == "rpy":
        return _stored_reply(frame, hby.db)
    return None


def _terminal(frame, hby, reger):
    if _stored_frame(frame, hby=hby, reger=reger) != frame.raw:
        return False
    if frame.kind == "schema":
        return True
    if frame.kind == "kel":
        dig = hby.db.getKeLast(dbing.snKey(frame.pre, frame.sn))
        return dig is not None and bytes(dig) == frame.said.encode("utf-8")
    if frame.kind == "tel":
        dig = reger.getTel(dbing.snKey(frame.pre, frame.sn))
        if dig is None or bytes(dig) != frame.said.encode("utf-8"):
            return False

        serder, _ = _serder(_decode(frame.body))
        if serder.ilk == kering.Ilks.vcp:
            tever = reger.tevers.get(frame.pre)
            return (tever is not None and tever.regk == frame.pre and
                    tever.sn == frame.sn and tever.serder.said == frame.said)
        if serder.ilk in (kering.Ilks.iss, kering.Ilks.bis):
            regk = (serder.ked.get("ri") or
                    serder.ked.get("ra", {}).get("i"))
            tever = reger.tevers.get(regk)
            state = tever.vcState(frame.pre) if tever is not None else None
            return (state is not None and state.i == frame.pre and
                    state.d == frame.said and int(state.s, 16) == frame.sn and
                    state.ri == regk and state.et == serder.ilk)
        return False
    if frame.kind == "acdc":
        creder = reger.creds.get(keys=(frame.said,))
        saved = reger.saved.get(keys=(frame.said,))
        indexed = (
            any(saider.qb64 == frame.said
                for saider in reger.issus.get(keys=(creder.issuer,))) and
            any(saider.qb64 == frame.said
                for saider in reger.schms.get(keys=(creder.schema,))) and
            any(saider.qb64 == frame.said
                for saider in reger.subjs.get(keys=(creder.attrib["i"],)))
        )
        tever = reger.tevers.get(creder.regi)
        state = tever.vcState(frame.said) if tever is not None else None
        pending = any(escrow.get(keys=(frame.said,)) is not None
                      for escrow in (reger.mre, reger.mce, reger.mse))
        return (saved is not None and saved.qb64 == frame.said and indexed and
                state is not None and
                state.et in (kering.Ilks.iss, kering.Ilks.bis) and
                not pending)
    if frame.kind == "rpy":
        serder = hby.db.rpys.get(keys=(frame.said,))
        route = serder.ked["r"]
        attrs = serder.ked["a"]
        if route == "/end/role/add":
            end = hby.db.ends.get(keys=(attrs["cid"], attrs["role"], attrs["eid"]))
            return end is not None and (end.allowed or end.enabled)
        if route == "/loc/scheme":
            loc = hby.db.locs.get(keys=(attrs["eid"], attrs["scheme"]))
            return loc is not None and loc.url == attrs["url"]
        return False
    return False


def replay_catalog(catalog, *, hby, reger):
    """Preflight and replay one catalog through isolated real processors."""
    for frame in catalog.frames:
        preflight_frame(frame)

    processors = ReplayProcessors.open(hby=hby, reger=reger)
    for frame in catalog.frames:
        if _terminal(frame, hby=hby, reger=reger):
            continue
        if frame.kind == "schema":
            schemer = scheming.Schemer(raw=frame.raw)
            hby.db.schema.pin(keys=(schemer.said,), val=schemer)
            continue
        _parse_real(frame,
                    kvy=processors.kvy,
                    tvy=processors.tvy,
                    rvy=processors.rvy,
                    vry=processors.vry,
                    local=False)
        if not _terminal(frame, hby=hby, reger=reger):
            raise SyncError(f"frame did not reach terminal state said={frame.said}")

    unexpected = [cue for cue in processors.cues
                  if cue.get("kin") not in ("saved", "receipt")]
    if unexpected:
        raise SyncError(f"replay emitted outward work cues={unexpected}")
    return catalog


def state_verified(catalog, *, hby, reger):
    return all(_terminal(frame, hby=hby, reger=reger)
               for frame in catalog.frames)


def core_converged(catalog, *, hby, reger):
    """The bounded state is accepted and the exact adding rotation is current."""
    if not state_verified(catalog, hby=hby, reger=reger):
        return False
    kever = hby.db.kevers.get(catalog.gid)
    return (kever is not None and
            kever.serder.said == catalog.rotation["said"] and
            kever.sn == catalog.rotation["sn"])


def process_delivery(work, *, hby, reger):
    """Validate approvals and apply the catalog carried by normalized work."""
    if work.get("op") != "deliver":
        raise SyncError("only deliver work replays accepted state")
    catalog = work.get("catalog")
    if not isinstance(catalog, Catalog):
        raise SyncError("deliver work is missing its catalog")
    verify_approvals(catalog, work.get("approvals", ()))
    return replay_catalog(catalog, hby=hby, reger=reger)


class MultisigAddHandler:
    """Protocol-neutral Exchanger handler for the unique `/multisig/add` route."""

    resource = Route

    def __init__(self, msgs=None):
        self.msgs = msgs if msgs is not None else decking.Deck()

    def _work(self, serder, attachments=None, essr=None):
        if attachments or essr:
            raise SyncError("minimal multisig add accepts inline public state only")
        attrs = serder.ked.get("a")
        if not isinstance(attrs, dict):
            raise SyncError("multisig add attributes must be an object")
        op = attrs.get("op")
        if op not in Operations:
            raise SyncError(f"unsupported multisig add operation={op}")

        work = dict(op=op,
                    said=serder.said,
                    sender=serder.ked["i"],
                    gid=attrs.get("gid"),
                    target=attrs.get("target"),
                    manifest=attrs.get("manifest"))
        if not all((work["gid"], work["target"], work["manifest"])):
            raise SyncError("gid, target, and manifest are required")
        if work["sender"] != work["target"]:
            raise SyncError("multisig add operations must be signed by the target member")
        if serder.ked.get("rp") != work["target"]:
            raise SyncError("multisig add recipient must be the target member")

        if op == "deliver":
            catalog = Catalog.from_raw(_decode(attrs.get("catalog")))
            if (catalog.said != work["manifest"] or
                    catalog.gid != work["gid"] or
                    catalog.target != work["target"]):
                raise SyncError("delivery does not match its catalog")
            approvals = attrs.get("approvals")
            if not isinstance(approvals, list):
                raise SyncError("delivery approvals must be a list")
            work.update(catalog=catalog, approvals=tuple(approvals))
        return work

    def verify(self, serder, attachments=None, essr=None):
        self._work(serder=serder, attachments=attachments, essr=essr)
        return True

    def handle(self, serder, attachments=None, essr=None):
        self.msgs.append(self._work(serder=serder,
                                    attachments=attachments,
                                    essr=essr))


class SyncDoer(doing.Doer):
    """Consume one ordinary Deck and keep only in-memory spike status."""

    def __init__(self, msgs, processor, converger=None, **kwa):
        self.msgs = msgs
        self.processor = processor
        self.converger = converger
        self.results = {}
        self.pending = {}
        self.controls = {}
        super(SyncDoer, self).__init__(**kwa)

    def status(self, manifest):
        return self.results.get(manifest)

    def recur(self, tyme):
        if self.msgs:
            work = self.msgs.popleft()
            manifest = work.get("manifest")
            if work["op"] == "deliver":
                current = self.results.get(manifest)
                if (current is None or
                        current["status"] not in
                        ("state-verified", "core-converged")):
                    self.results[manifest] = dict(status="pending",
                                                  said=work["said"])
                    try:
                        catalog = self.processor(work)
                    except Exception as ex:
                        self.results[manifest] = dict(status="failed",
                                                      error=str(ex),
                                                      said=work["said"])
                    else:
                        self.pending[manifest] = catalog
                        self.results[manifest] = dict(
                            status="state-verified",
                            said=work["said"])
            else:
                statuses = dict(propose="proposed",
                                approve="approved",
                                reject="rejected")
                result = dict(status=statuses[work["op"]],
                              said=work["said"])
                self.controls[(manifest, work["op"])] = result
                current = self.results.get(manifest)
                if current is None or current["status"] in statuses.values():
                    self.results[manifest] = result

        if self.converger is not None:
            for manifest, catalog in list(self.pending.items()):
                if self.converger(catalog):
                    self.results[manifest] = dict(status="core-converged",
                                                  said=self.results[manifest]["said"])
                    del self.pending[manifest]
        return False


def bind_delivery(hby, reger):
    """Return the two small callbacks an adapter supplies to `SyncDoer`."""
    return (partial(process_delivery, hby=hby, reger=reger),
            partial(core_converged, hby=hby, reger=reger))
