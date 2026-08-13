# -*- encoding: utf-8 -*-
"""
tests.app.mailboxing module

"""
import importlib
import os

import falcon
from falcon import testing
import pytest

from hio.help import decking

from keri.app import openHab, openHby
from keri.app.forwarding import AuthorizedForwardHandler
from keri.app.mailboxing import MailboxAddRemoveEnd, _mailboxAdminPath, setupMailbox
from keri.app.configing import Configer
from keri.app.storing import Mailboxer
from keri.core import Kevery, Pather, Salter, exchange, parsing, routing, serdering
from keri.kering import Kinds, Roles
from keri.peer import specialExchange


mailbox_start = importlib.import_module("keri.cli.commands.mailbox.start")


def _collect_replay(hab):
    """Collect one habitat replay in the same delegation-first order used by mailbox admin."""
    body = bytearray()
    for msg in hab.db.clonePreIter(pre=hab.pre):
        body.extend(msg)
    for msg in hab.db.cloneDelegation(hab.kever):
        body.extend(msg)
    return body


def _mailbox_admin_client(hby, hab, route="/mailboxes"):
    """Build a focused Falcon client exposing only one mailbox admin route."""
    cues = decking.Deck()
    rvy = routing.Revery(db=hby.db, cues=cues)
    kvy = Kevery(db=hby.db, lax=True, local=False, rvy=rvy, cues=cues)
    kvy.registerReplyRoutes(router=rvy.rtr)

    app = falcon.App()
    app.add_route(route,
                  MailboxAddRemoveEnd(hby=hby, hab=hab, kvy=kvy, rvy=rvy, exc=None))
    return testing.TestClient(app)


def _multipart_body(**fields):
    """Create one minimal multipart body for mailbox admin endpoint tests."""
    boundary = "----keri-mailbox-admin-boundary"
    body = bytearray()

    for name, value in fields.items():
        if value is None:
            continue
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"))
        body.extend(value.encode("utf-8"))
        body.extend(b"\r\n")

    body.extend(f"--{boundary}--\r\n".encode("utf-8"))
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def _post_mailbox_admin(client, *, path="/mailboxes", fields=None, content_type="text/plain", body=b""):
    """Post either raw bytes or mailbox-admin multipart fields to one admin path."""
    if fields is not None:
        body, content_type = _multipart_body(**fields)

    return client.simulate_post(
        path,
        headers={"Content-Type": content_type},
        body=body,
    )


def test_mailbox_add_remove_end_accepts_multipart_add():
    """Mailbox admin accepts the legacy multipart add envelope for a direct controller."""
    with openHby(name="mailbox-provider", salt=Salter(raw=b"mailbox-provider0").qb64) as providerHby, \
            openHby(name="mailbox-controller", salt=Salter(raw=b"mailbox-controller").qb64) as controllerHby:
        mailboxHab = providerHby.makeHab(name="mbx", transferable=False)
        controller = controllerHby.makeHab(name="alice", transferable=True)
        client = _mailbox_admin_client(providerHby, mailboxHab)

        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": controller.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=True).decode("utf-8"),
        })

        assert rep.status_code == 200
        assert rep.json == {
            "cid": controller.pre,
            "role": Roles.mailbox,
            "eid": mailboxHab.pre,
            "allowed": True,
        }
        assert providerHby.db.ends.get(keys=(controller.pre, Roles.mailbox, mailboxHab.pre)).allowed


def test_mailbox_add_remove_end_accepts_multipart_delegated_add():
    """Mailbox admin accepts delegated controller add when `delkel` carries delegator evidence."""
    with openHby(name="mailbox-provider-delegated",
                 salt=Salter(raw=b"mailbox-provider1").qb64) as providerHby, \
            openHby(name="mailbox-controller-delegated",
                    salt=Salter(raw=b"mailbox-controller1").qb64) as controllerHby:
        mailboxHab = providerHby.makeHab(name="mbx", transferable=False)
        delegator = controllerHby.makeHab(name="delegator", transferable=True)
        controller = controllerHby.makeHab(name="alice", transferable=True, delpre=delegator.pre)

        delegator.interact(data=[dict(i=controller.pre, s="0", d=controller.pre)])
        for msg in delegator.db.clonePreIter(pre=delegator.pre):
            controller.psr.parse(ims=msg)

        client = _mailbox_admin_client(providerHby, mailboxHab)
        rep = _post_mailbox_admin(client, fields={
            "kel": bytearray(controller.replay()).decode("utf-8"),
            "delkel": b"".join(controller.db.cloneDelegation(controller.kever)).decode("utf-8"),
            "rpy": controller.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=True).decode("utf-8"),
        })

        assert rep.status_code == 200
        assert rep.json["cid"] == controller.pre
        assert providerHby.db.ends.get(keys=(controller.pre, Roles.mailbox, mailboxHab.pre)).allowed


def test_mailbox_add_remove_end_accepts_multipart_cut_after_add():
    """Mailbox admin accepts a cut after a previously accepted mailbox add."""
    with openHby(name="mailbox-provider-cut", salt=Salter(raw=b"mailbox-provider2").qb64) as providerHby, \
            openHby(name="mailbox-controller-cut", salt=Salter(raw=b"mailbox-controller-cut").qb64) as controllerHby:
        mailboxHab = providerHby.makeHab(name="mbx", transferable=False)
        controller = controllerHby.makeHab(name="alice", transferable=True)
        client = _mailbox_admin_client(providerHby, mailboxHab)

        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": controller.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=True).decode("utf-8"),
        })
        assert rep.status_code == 200

        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": controller.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=False).decode("utf-8"),
        })

        assert rep.status_code == 200
        assert rep.json == {
            "cid": controller.pre,
            "role": Roles.mailbox,
            "eid": mailboxHab.pre,
            "allowed": False,
        }
        assert not providerHby.db.ends.get(keys=(controller.pre, Roles.mailbox, mailboxHab.pre)).allowed


def test_mailbox_admin_path_uses_stored_mailbox_url_path_without_root_alias():
    """Mailbox admin is served relative to the stored mailbox URL path only."""
    with openHby(name="mailbox-provider-path",
                 salt=Salter(raw=b"mailbox-provider-path").qb64) as providerHby, \
            openHby(name="mailbox-controller-path",
                    salt=Salter(raw=b"mailbox-controller-path").qb64) as controllerHby:
        mailboxHab = providerHby.makeHab(name="mbx", transferable=False)
        controller = controllerHby.makeHab(name="alice", transferable=True)
        mailboxUrl = f"http://127.0.0.1:5632/{mailboxHab.pre}"
        mailboxHab.psr.parse(ims=bytearray(mailboxHab.makeLocScheme(
            url=mailboxUrl,
            eid=mailboxHab.pre,
            scheme="http",
        )))

        adminPath = _mailboxAdminPath(mailboxHab)
        assert adminPath == f"/{mailboxHab.pre}/mailboxes"

        client = _mailbox_admin_client(providerHby, mailboxHab, route=adminPath)
        fields = {
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": controller.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=True).decode("utf-8"),
        }

        rep = _post_mailbox_admin(client, fields=fields)
        assert rep.status_code == 404

        rep = _post_mailbox_admin(client, path=adminPath, fields=fields)
        assert rep.status_code == 200
        assert rep.json["allowed"] is True


def test_mailbox_admin_path_requires_loaded_self_location():
    """Mailbox admin path is derived only from loaded self location state."""
    with openHby(name="mailbox-provider-missing-loc",
                 salt=Salter(raw=b"mailbox-provider-missing").qb64) as providerHby:
        mailboxHab = providerHby.makeHab(name="mbx", transferable=False)

        with pytest.raises(ValueError, match="loaded self HTTP"):
            _mailboxAdminPath(mailboxHab)


def test_setup_mailbox_requires_self_identity_state_before_boot():
    """Mailbox host boot fails until self location and self role state are accepted."""
    with openHby(name="mailbox-provider-boot",
                 salt=Salter(raw=b"mailbox-provider-boot").qb64) as providerHby:
        mailboxHab = providerHby.makeHab(name="mbx", transferable=False)

        with pytest.raises(ValueError, match="loaded self HTTP"):
            setupMailbox(providerHby, alias="mbx")

        mailboxHab.psr.parse(ims=bytearray(mailboxHab.makeLocScheme(
            url=f"http://127.0.0.1:5632/{mailboxHab.pre}",
            eid=mailboxHab.pre,
            scheme="http",
        )))
        with pytest.raises(ValueError, match="self controller authorization"):
            setupMailbox(providerHby, alias="mbx")

        mailboxHab.psr.parse(ims=bytearray(mailboxHab.makeEndRole(
            mailboxHab.pre,
            Roles.controller,
            allow=True,
        )))
        with pytest.raises(ValueError, match="self mailbox authorization"):
            setupMailbox(providerHby, alias="mbx")

        mailboxHab.psr.parse(ims=bytearray(mailboxHab.makeEndRole(
            mailboxHab.pre,
            Roles.mailbox,
            allow=True,
        )))
        doers = setupMailbox(providerHby, alias="mbx", httpPort=9000)
        try:
            assert len(doers) > 0
        finally:
            for doer in doers:
                if hasattr(doer, "server"):
                    doer.server.close()


def test_mailbox_start_creates_missing_alias_from_config_startup_material():
    """Mailbox start bootstrap reuses Hab config application for alias startup material."""
    cf = Configer(name=f"mailbox-start-cf-{os.urandom(4).hex()}",
                  temp=True,
                  reopen=True,
                  clear=False)
    hby = None
    try:
        cf.put({
            "relay": {
                "dt": "2026-04-07T12:00:00.000000+00:00",
                "curls": ["http://127.0.0.1:5632/relay"],
            }
        })

        hby = mailbox_start._openMailboxHabery(
            name=f"mailbox-start-config-{os.urandom(4).hex()}",
            cf=cf,
            temp=True,
        )
        hab, startup = mailbox_start._prepareMailboxHabitat(hby=hby, alias="relay")

        assert startup["source"] == "stored"
        assert not hab.kever.prefixer.transferable
        assert hab.fetchUrls(eid=hab.pre, scheme="http")["http"] == "http://127.0.0.1:5632/relay"
        assert hby.db.ends.get(keys=(hab.pre, Roles.controller, hab.pre)).allowed
        assert hby.db.ends.get(keys=(hab.pre, Roles.mailbox, hab.pre)).allowed
    finally:
        if hby is not None:
            hby.close(clear=hby.temp)
        cf.close(clear=cf.temp)


def test_mailbox_start_requires_config_when_alias_is_missing():
    """Mailbox start does not offer a CLI bootstrap path in KERIpy."""
    hby = mailbox_start._openMailboxHabery(
        name=f"mailbox-start-no-config-{os.urandom(4).hex()}",
        temp=True,
    )
    try:
        with pytest.raises(ValueError, match="matching config alias section"):
            mailbox_start._prepareMailboxHabitat(hby=hby, alias="relay")
    finally:
        hby.close(clear=hby.temp)


def test_mailbox_start_rejects_incomplete_config_startup_material():
    """Mailbox start fails when Hab config application does not yield usable self state."""
    cf = Configer(name=f"mailbox-start-bad-cf-{os.urandom(4).hex()}",
                  temp=True,
                  reopen=True,
                  clear=False)
    hby = None
    try:
        cf.put({
            "relay": {
                "dt": "2026-04-07T12:00:00.000000+00:00",
            }
        })
        hby = mailbox_start._openMailboxHabery(
            name=f"mailbox-start-bad-{os.urandom(4).hex()}",
            cf=cf,
            temp=True,
        )

        with pytest.raises(ValueError, match="complete mailbox startup state"):
            mailbox_start._prepareMailboxHabitat(hby=hby, alias="relay", requireConfig=True)
    finally:
        if hby is not None:
            hby.close(clear=hby.temp)
        cf.close(clear=cf.temp)


def test_mailbox_add_remove_end_rejects_invalid_requests():
    """Mailbox admin rejects malformed envelopes, invalid replies, and unaccepted auth state.

    This test is intentionally broad because the endpoint has two layers of
    failure:
        1. request-shape validation before ingest
        2. post-ingest acceptance checks against resulting `ends.` state

    Each block below labels one distinct seam to show which regression surface changed on failures.
    """
    with openHby(name="mailbox-provider-invalid",
                 salt=Salter(raw=b"mailbox-provider3").qb64) as providerHby, \
            openHby(name="mailbox-controller-invalid",
                    salt=Salter(raw=b"mailbox-controller3").qb64) as controllerHby:
        mailboxHab = providerHby.makeHab(name="mbx", transferable=False)
        otherMailbox = providerHby.makeHab(name="other", transferable=False)
        controller = controllerHby.makeHab(name="alice", transferable=True)
        unauthorized = controllerHby.makeHab(name="bob", transferable=True)
        client = _mailbox_admin_client(providerHby, mailboxHab)

        # Reject non-multipart content types. KERIpy keeps this endpoint on the
        # legacy multipart envelope instead of reparsing raw CESR bodies.
        rep = _post_mailbox_admin(client, body=b"not multipart", content_type="text/plain")
        assert rep.status_code == 406

        # Reject envelopes missing the controller KEL replay.
        rep = _post_mailbox_admin(client, fields={
            "rpy": controller.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=True).decode("utf-8"),
        })
        assert rep.status_code == 400
        assert "missing kel" in rep.text

        # Reject envelopes missing the terminal signed authorization reply.
        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
        })
        assert rep.status_code == 400
        assert "missing rpy" in rep.text

        # Reject replies on the wrong route before checking mailbox-specific
        # payload fields. This keeps route errors clearer than generic
        # cid/role/eid payload failures.
        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": controller.makeLocScheme(url="http://127.0.0.1:5632", eid=mailboxHab.pre).decode("utf-8"),
        })
        assert rep.status_code == 400
        assert "Unsupported mailbox authorization route" in rep.text

        # Reject `/end/role/*` replies that do not target the mailbox role.
        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": controller.makeEndRole(mailboxHab.pre, Roles.watcher, allow=True).decode("utf-8"),
        })
        assert rep.status_code == 400
        assert "role=mailbox" in rep.text

        # Reject replies whose `eid` points at a different hosted mailbox AID.
        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": controller.makeEndRole(otherMailbox.pre, Roles.mailbox, allow=True).decode("utf-8"),
        })
        assert rep.status_code == 403
        assert "does not match hosted mailbox" in rep.text

        # Reject empty multipart `kel` field values even when the field exists.
        rep = _post_mailbox_admin(client, fields={
            "kel": "",
            "rpy": controller.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=True).decode("utf-8"),
        })
        assert rep.status_code == 400
        assert "missing kel" in rep.text

        # Reject non-CESR `rpy` field values before runtime ingest.
        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": "not cesr",
        })
        assert rep.status_code == 400
        assert "invalid mailbox authorization reply" in rep.text

        # Reject replies that parse correctly but do not survive acceptance into
        # `ends.` state. Here the KEL belongs to `alice` while the signed reply
        # was produced by `bob`, so normal KERI processing must refuse it.
        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": unauthorized.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=True).decode("utf-8"),
        })
        assert rep.status_code == 403
        assert "was not accepted" in rep.text


# ---------------------------------------------------------------------------
# Review tests for PR #1395.
#
# Each test below states an invariant the mailbox host implementation should
# hold but currently does not.  They are written to fail against this branch;
# the assertion messages name the seam that needs fixing.
# ---------------------------------------------------------------------------


def _multipart_body_with_part_content_type(partContentType, **fields):
    """Build a multipart body whose parts carry an explicit Content-Type header.

    RFC 7578 makes the per-part ``Content-Type`` optional and defaults it to
    ``text/plain``.  A client is free to label the CESR fields with their real
    media type, so the endpoint must not depend on the default.
    """
    boundary = "----keri-mailbox-admin-boundary"
    body = bytearray()

    for name, value in fields.items():
        if value is None:
            continue
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{name}"\r\n'.encode("utf-8"))
        body.extend(f"Content-Type: {partContentType}\r\n\r\n".encode("utf-8"))
        body.extend(value.encode("utf-8"))
        body.extend(b"\r\n")

    body.extend(f"--{boundary}--\r\n".encode("utf-8"))
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def test_mailbox_admin_rejects_a_reply_that_was_not_accepted():
    """Acceptance must be tied to the submitted reply, not to pre-existing `ends.` state.

    `_confirmRoleAuth` only re-reads `(cid, mailbox, eid)` after ingest.  When a
    prior genuine add already left `allowed=True`, any later request whose `rpy`
    is dropped by normal KERI processing still finds that record and reports
    success.  The reply below carries no signature at all, so nothing about it
    was verified, yet the endpoint answers 200.

    `.eans` already records the SAID of the reply that was actually accepted,
    so the acceptance check can be made specific to this request.
    """
    with openHby(name="mailbox-provider-mask",
                 salt=Salter(raw=b"mailbox-provider-mask").qb64) as providerHby, \
            openHby(name="mailbox-controller-mask",
                    salt=Salter(raw=b"mailbox-controller-mask").qb64) as controllerHby:
        mailboxHab = providerHby.makeHab(name="mbx", transferable=False)
        controller = controllerHby.makeHab(name="alice", transferable=True)
        client = _mailbox_admin_client(providerHby, mailboxHab)

        signed = controller.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=True)
        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": signed.decode("utf-8"),
        })
        assert rep.status_code == 200

        # Strip the signature attachment.  Everything a forger needs to build
        # this body -- the controller's public KEL and the hosted mailbox AID --
        # is public.
        unsigned = serdering.SerderKERI(raw=bytes(signed)).raw.decode("utf-8")
        rep = _post_mailbox_admin(client, fields={
            "kel": _collect_replay(controller).decode("utf-8"),
            "rpy": unsigned,
        })

        assert rep.status_code == 403, (
            "unsigned mailbox authorization reply was reported as accepted; "
            "the post-ingest check reads pre-existing ends. state instead of "
            "confirming that this reply was the one accepted"
        )


def test_mailbox_admin_reads_parts_labeled_with_a_cesr_media_type():
    """Mailbox admin must read multipart fields that declare their real media type.

    `_readMultipart` uses falcon's `BodyPart.text`, which returns ``None`` for
    any part whose Content-Type is not ``text/plain``.  A client that labels the
    CESR fields honestly gets "missing kel" rather than a parse of its body, and
    an honestly-labeled optional `delkel` is dropped silently, which turns a
    delegated add into an opaque 403.
    """
    with openHby(name="mailbox-provider-ct",
                 salt=Salter(raw=b"mailbox-provider-ct").qb64) as providerHby, \
            openHby(name="mailbox-controller-ct",
                    salt=Salter(raw=b"mailbox-controller-ct").qb64) as controllerHby:
        mailboxHab = providerHby.makeHab(name="mbx", transferable=False)
        controller = controllerHby.makeHab(name="alice", transferable=True)
        client = _mailbox_admin_client(providerHby, mailboxHab)

        body, contentType = _multipart_body_with_part_content_type(
            "application/cesr",
            kel=_collect_replay(controller).decode("utf-8"),
            rpy=controller.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=True).decode("utf-8"),
        )
        rep = client.simulate_post("/mailboxes",
                                   headers={"Content-Type": contentType},
                                   body=body)

        assert rep.status_code == 200, (
            "multipart parts labeled application/cesr were not read; "
            f"got {rep.status_code} {rep.text}"
        )


def test_mailbox_admin_accepts_a_kel_replay_larger_than_falcons_default_part_buffer():
    """A long-lived controller KEL must not hit falcon's 1 MiB per-part default.

    The endpoint's whole job is to ingest a controller KEL replay, but the app
    never configures `MultipartFormHandler` parse options, so
    `max_body_part_buffer_size` stays at its 1 MiB default.  Past that the
    request fails with a generic "body part is too large" 400 that says nothing
    about mailbox authorization.
    """
    with openHby(name="mailbox-provider-big",
                 salt=Salter(raw=b"mailbox-provider-big").qb64) as providerHby, \
            openHby(name="mailbox-controller-big",
                    salt=Salter(raw=b"mailbox-controller-big").qb64) as controllerHby:
        mailboxHab = providerHby.makeHab(name="mbx", transferable=False)
        controller = controllerHby.makeHab(name="alice", transferable=True)
        client = _mailbox_admin_client(providerHby, mailboxHab)

        kel = _collect_replay(controller)
        while len(kel) < 1024 * 1024:  # KEL replay is idempotent, so repeat it
            kel.extend(_collect_replay(controller))
        assert len(kel) > 1024 * 1024

        rep = _post_mailbox_admin(client, fields={
            "kel": kel.decode("utf-8"),
            "rpy": controller.makeEndRole(mailboxHab.pre, Roles.mailbox, allow=True).decode("utf-8"),
        })

        assert rep.status_code == 200, (
            "controller KEL replay over 1 MiB was rejected by the multipart "
            f"reader; got {rep.status_code} {rep.text}"
        )


def test_setup_mailbox_scopes_forwarded_message_storage_to_the_habery_base():
    """Mailbox storage must be scoped by `hby.base`, the way witness hosting is.

    `setupWitness` builds `Mailboxer(name=alias, base=hby.base, temp=hby.temp)`;
    `setupMailbox` omits `base`.  Two haberies run under different `--base`
    values with the same alias therefore share one mailbox database.
    """
    with openHby(name="mailbox-provider-base",
                 base="tenantA",
                 salt=Salter(raw=b"mailbox-provider-base").qb64) as providerHby:
        mailboxHab = providerHby.makeHab(name="mbx", transferable=False)
        mailboxHab.psr.parse(ims=bytearray(mailboxHab.makeLocScheme(
            url="http://127.0.0.1:5632",
            eid=mailboxHab.pre,
            scheme="http",
        )))
        mailboxHab.psr.parse(ims=bytearray(mailboxHab.makeEndRole(
            mailboxHab.pre, Roles.controller, allow=True)))
        mailboxHab.psr.parse(ims=bytearray(mailboxHab.makeEndRole(
            mailboxHab.pre, Roles.mailbox, allow=True)))

        doers = setupMailbox(providerHby, alias="mbx", httpPort=0)
        try:
            mbxs = [doer.mbx for doer in doers if hasattr(doer, "mbx")]
            assert mbxs
            for mbx in mbxs:
                assert f"/{providerHby.base}/" in mbx.path, (
                    f"mailbox storage at {mbx.path} ignores hby.base "
                    f"{providerHby.base!r}; setupMailbox does not pass base= to Mailboxer"
                )
        finally:
            for doer in doers:
                if hasattr(doer, "server"):
                    doer.server.close()


def test_authorized_forward_handler_survives_a_fwd_exn_without_a_recipient():
    """A malformed `/fwd` must not raise out of the handler.

    `AuthorizedForwardHandler.handle` indexes `modifiers["pre"]` unguarded.
    `Exchanger.processEvent` only catches `AttributeError` around
    `behavior.handle`, so a `KeyError` propagates through the parser and stops
    the host's ingress loop.  On a standalone mailbox host that loop is reachable
    by any remote peer over the unauthenticated `/` CESR endpoint, so this is a
    remote halt rather than the latent flaw it is on a witness.
    """
    with openHab(name="mbx-fwd-malformed-sender", transferable=True, temp=True,
                 kind=Kinds.json) as (hby, hab):
        mbx = Mailboxer(temp=True)
        forwarder = AuthorizedForwardHandler(hby=hby, mbx=mbx, mailboxAid=hab.pre)

        fwd, _ = specialExchange(sender=hab.pre,
                                 route="/fwd",
                                 modifiers=dict(topic="echo"),  # no `pre`
                                 attributes={},
                                 embeds=dict())

        try:
            forwarder.handle(serder=fwd, attachments=[])
        except KeyError as ex:
            pytest.fail(f"malformed /fwd raised {ex!r} out of the handler")
        finally:
            mbx.close(clear=True)


def test_authorized_forward_handler_gates_storage_on_recipient_authorization():
    """Characterization coverage for the gate this PR adds.

    The `/fwd` authorization gate is the security boundary that separates a
    standalone mailbox host from an open storage relay, and it currently has no
    test.  This pins both directions plus the transition after a role cut.
    """
    with openHab(name="mbx-fwd-sender", transferable=True, temp=True,
                 kind=Kinds.json) as (senderHby, sender), \
            openHab(name="mbx-fwd-host", transferable=False, temp=True,
                    kind=Kinds.json) as (hostHby, host), \
            openHab(name="mbx-fwd-recp", transferable=True, temp=True,
                    kind=Kinds.json) as (recpHby, recp):

        mbx = Mailboxer(temp=True)
        forwarder = AuthorizedForwardHandler(hby=hostHby, mbx=mbx, mailboxAid=host.pre)

        hostCues = decking.Deck()
        hostRvy = routing.Revery(db=hostHby.db, cues=hostCues)
        hostKvy = Kevery(db=hostHby.db, lax=True, local=False, rvy=hostRvy, cues=hostCues)
        hostKvy.registerReplyRoutes(router=hostRvy.rtr)

        def ingest(raw):
            """Ingest CESR into the host the way the mailbox host runtime does."""
            parser = parsing.Parser(framed=True, kvy=hostKvy, rvy=hostRvy,
                                    version=hostHby.version)
            parser.parse(ims=bytearray(raw), local=False)
            hostKvy.processEscrows()
            hostRvy.processEscrowReply()

        inner = exchange(route="/echo", attributes=dict(msg="hello"), sender=sender.pre,
                         kind=Kinds.json)
        atc = sender.endorse(inner, last=False, framed=False)
        del atc[:inner.size]
        evt = bytearray(inner.raw)
        evt.extend(atc)

        def forward():
            fwd, _ = specialExchange(sender=sender.pre,
                                     route="/fwd",
                                     modifiers=dict(pre=recp.pre, topic="echo"),
                                     attributes={},
                                     embeds=dict(evt=evt))
            forwarder.handle(serder=fwd, attachments=[(Pather(path=["evt"]), atc)])

        try:
            # Unauthorized recipient: nothing is stored.
            forward()
            assert not list(mbx.cloneTopicIter(topic=f"{recp.pre}/echo"))

            # The recipient authorizes the host as its mailbox.
            ingest(recp.replay())
            ingest(recp.makeEndRole(host.pre, Roles.mailbox, allow=True))
            assert hostHby.db.ends.get(keys=(recp.pre, Roles.mailbox, host.pre)).allowed

            forward()
            assert len(list(mbx.cloneTopicIter(topic=f"{recp.pre}/echo"))) == 1

            # After a cut the host must stop accepting storage again.
            ingest(recp.makeEndRole(host.pre, Roles.mailbox, allow=False))
            assert not hostHby.db.ends.get(keys=(recp.pre, Roles.mailbox, host.pre)).allowed

            forward()
            assert len(list(mbx.cloneTopicIter(topic=f"{recp.pre}/echo"))) == 1, (
                "forwarded storage continued after the recipient cut the mailbox role"
            )
        finally:
            mbx.close(clear=True)
