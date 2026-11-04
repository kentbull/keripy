"""Finite public CESR delivery shared by live native command owners."""
from hio.base import doing

from ... import Kinds, Vrsn_2_0
from ...app import GroupHab, StreamPoster
from ...app.agenting import HTTPStreamMessenger
from ...core import Parser
from ...kering import ConfigurationError


def send(owner, raw, dest, *, topic='credential'):
    """Send public CESR through the caller's selected hab/hby and finite check.

    The caller owns the DoDoer lifecycle; this function adds and removes its
    finite transport children on completion, failure and cancellation.
    """
    sender = owner.hab.mhab if isinstance(owner.hab, GroupHab) else owner.hab
    poster = StreamPoster(hby=owner.hby, hab=sender, recp=dest, topic=topic,
                          version=Vrsn_2_0, kind=Kinds.json)
    stream = bytearray(raw)
    while stream:
        before = bytes(stream)
        parsed = Parser(version=Vrsn_2_0).parseOneBare(ims=stream, processive=False)
        consumed = len(before) - len(stream)
        poster.send(parsed.serder, attachment=before[parsed.serder.size:consumed], gvrsn=Vrsn_2_0)
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
