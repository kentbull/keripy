"""Approved group replies use the application's existing authenticated owners."""
import pytest

from keri import Vrsn_2_0
from keri.app import Notifier, openHby
from keri.app.grouping import Multiplexor, loadHandlers, multisigRpyExn
from keri.core import Kevery, Parser, Revery, messagize, reply
from keri.kering import Kinds, ValidationError
from keri.peer import Exchanger
from tests.app.test_acdc_v2_groups import groupMembers


class ApplicationReply:
    """Record only a fully authenticated exact application reply."""

    def __init__(self, rvy, author):
        """Borrow the caller's Revery and the expected logical group author."""
        self.rvy, self.author = rvy, author
        self.accepted = []

    def processReply(self, *, serder, diger, route, cigars=None, tsgs=None):
        """Use ordinary threshold authentication before recording application work."""
        assert self.rvy.acceptReply(serder=serder, saider=diger, route=route,
                                   aid=self.author, cigars=cigars, tsgs=tsgs)
        self.accepted.append(serder.said)


def test_approved_group_child_uses_borrowed_reply_route():
    """A real two-member signed child reaches the already registered app handler."""
    with groupMembers('borrowed-group-owners') as (hbys, groups, _, _):
        hby, group = hbys[0], groups[0]
        rvy = Revery(db=hby.db)
        kvy = Kevery(db=hby.db, rvy=rvy, lax=True, local=False)
        kvy.registerReplyRoutes(rvy.rtr)
        resource = ApplicationReply(rvy, group.pre)
        rvy.rtr.addRoute('/test/borrowed', resource)
        routes = tuple(rvy.rtr.routes)
        exc = Exchanger(hby, handlers=[])
        notifier = Notifier(hby)
        try:
            mux = Multiplexor(hby, notifier, exc=exc, kvy=kvy, rvy=rvy)
            loadHandlers(exc, mux)
            body = reply(pre=group.pre, route='/test/borrowed', data={'exact': True},
                         version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)
            parts = [Parser(version=Vrsn_2_0).parse(
                ims=bytearray(hab.endorse(body, gvrsn=Vrsn_2_0)), processive=False)[0]
                for hab in groups[:2]]
            aid, number, digest, sigers = parts[0].tsgs[0]
            stream = messagize(body, tsgs=[(aid, number, digest, sigers + parts[1].tsgs[0][3])],
                               gvrsn=Vrsn_2_0)
            wrapper, attachments = multisigRpyExn(group, stream)
            parser = Parser(kvy=kvy, rvy=rvy, exc=exc, version=Vrsn_2_0)
            parser.parse(
                ims=bytearray(wrapper.raw + attachments), local=True)
            assert resource.accepted == []  # own wrapper records approval
            wrapper, attachments = multisigRpyExn(groups[1], stream)
            parser.parse(ims=bytearray(wrapper.raw + attachments), local=False)
            assert resource.accepted == [body.said]
            assert tuple(rvy.rtr.routes) == routes
            assert mux.kvy is kvy and mux.rvy is rvy
        finally:
            notifier.noter.close()


def test_group_owner_injection_rejects_mixed_environments():
    """A caller cannot silently replay accepted children through another database."""
    with openHby(name='group-owner') as hby, openHby(name='other-owner') as other:
        rvy = Revery(db=hby.db)
        kvy = Kevery(db=hby.db, rvy=rvy)
        for pair in ({'kvy': kvy}, {'rvy': rvy},
                     {'kvy': kvy, 'rvy': Revery(db=hby.db)},
                     {'kvy': Kevery(db=other.db, rvy=rvy), 'rvy': rvy}):
            with pytest.raises(ValidationError, match='group replay'):
                Multiplexor(hby, None, **pair)
