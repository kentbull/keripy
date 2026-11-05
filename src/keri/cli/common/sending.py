"""Finite public CESR delivery shared by live native command owners."""
from hio.base import doing

from ... import Kinds, Vrsn_2_0
from ...app import GroupHab, StreamPoster
from ...app.agenting import HTTPStreamMessenger
from ...core import Codens, Counter, Parser, Texter
from ...kering import ConfigurationError, ExtractionError


def messageParts(raw):
    """Yield v2 bodies and unchanged attachments from bare or counted messages.

    Parser owns complete message boundaries. A counted JSON body is carried by
    a Texter inside its message enclosure; only those wrappers are removed.
    Nested evidence and signature/opening groups remain their original bytes;
    an attachment counter replaces the outer enclosure when it owned their extent.
    """
    stream = bytearray(raw)
    parser = Parser(version=Vrsn_2_0)
    while stream:
        before = bytes(stream)
        parsed = parser.parseOneBare(ims=stream, processive=False)
        frame = bytearray(before[:len(before) - len(stream)])
        prefix = Counter.makeGVC(version=Vrsn_2_0)
        if frame.startswith(prefix):
            del frame[:len(prefix)]
        if frame.startswith(parsed.serder.raw):
            del frame[:parsed.serder.size]
        else:
            outer = Counter(qb64b=frame, strip=True, version=Vrsn_2_0)
            if (outer.name not in (Codens.BodyWithAttachmentGroup, Codens.BigBodyWithAttachmentGroup)
                    or outer.byteCount() != len(frame)):
                raise ExtractionError('expected one counted v2 message enclosure')
            body = Counter(qb64b=frame, strip=True, version=Vrsn_2_0)
            if body.name not in (Codens.NonNativeBodyGroup, Codens.BigNonNativeBodyGroup):
                raise ExtractionError('expected a counted non-native v2 body')
            texter = Texter(qb64b=frame, strip=True)
            if body.byteCount() != len(texter.qb64b) or texter.raw != parsed.serder.raw:
                raise ExtractionError('counted body differs from parsed message')
            attachments = Counter(qb64b=frame, version=Vrsn_2_0)
            if not (attachments.name in (Codens.AttachmentGroup, Codens.BigAttachmentGroup)
                    and attachments.fullSize + attachments.byteCount() == len(frame)):
                frame = Counter.enclose(qb64=frame, code=Codens.AttachmentGroup, version=Vrsn_2_0)
        yield parsed.serder, bytes(frame)


def send(owner, raw, dest, *, topic='credential'):
    """Send public CESR through the caller's selected hab/hby and finite check.

    The caller owns the DoDoer lifecycle; this function adds and removes its
    finite transport children on completion, failure and cancellation.
    """
    sender = owner.hab.mhab if isinstance(owner.hab, GroupHab) else owner.hab
    poster = StreamPoster(hby=owner.hby, hab=sender, recp=dest, topic=topic,
                          version=Vrsn_2_0, kind=Kinds.json)
    for serder, attachments in messageParts(raw):
        poster.send(serder, attachment=attachments, gvrsn=Vrsn_2_0)
    children = poster.deliver()
    if not children:
        raise ConfigurationError('no finite recipient transport was available')
    transport = doing.DoDoer(doers=children)
    owner.extend([transport])
    try:
        while not transport.done:
            owner.check()
            yield owner.tock
        owner.check()
        for child in children:
            if isinstance(child, HTTPStreamMessenger) and not 200 <= child.rep.status < 300:
                raise ConfigurationError(f'HTTP submission failed with status {child.rep.status}')
    finally:
        owner.remove([transport])
